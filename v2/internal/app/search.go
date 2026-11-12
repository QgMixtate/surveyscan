package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
	"github.com/jackc/pgx/v5"
)

// C29 — поисковая проекция (ADR C28: Tantivy отдельным процессом surveyscan-search). Центр — единственный писатель:
// потребитель outbox "search-index" строит документ актива из PostgreSQL и отправляет его в сервис с версией агрегата
// (сервис не применяет версию не новее сохранённой — повтор после сбоя безопасен). Ответы поиска — кандидаты: центр
// перепроверяет тенант и состояние актива по PostgreSQL; фасеты и фрагменты строятся только по перепроверенным.
// Если сервис недоступен — запасной точный поиск по PostgreSQL, явно помеченный как не полнотекстовый.

const SearchConsumer = "search-index"

// SearchClient — клиент сервиса surveyscan-search (loopback, токен).
type SearchClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

type SearchDoc struct {
	Asset   string   `json:"asset_uid"`
	Tenant  string   `json:"tenant"`
	Version uint64   `json:"version"`
	OS      string   `json:"os"`
	Class   string   `json:"class"`
	Hosts   []string `json:"hosts"`
	Serials []string `json:"serials"`
	IPs     []string `json:"ips"`
	FQDNs   []string `json:"fqdns"`
	Text    string   `json:"text"`
}

type searchDelete struct {
	Asset   string `json:"asset_uid"`
	Version uint64 `json:"version"`
}

type searchApply struct {
	Docs    []SearchDoc    `json:"docs"`
	Deletes []searchDelete `json:"deletes"`
}

type SearchHit struct {
	Asset      string   `json:"asset_uid"`
	Score      float32  `json:"score"`
	OS         string   `json:"os"`
	Class      string   `json:"class"`
	Fragment   string   `json:"fragment"`
	Highlights [][2]int `json:"highlights"`
}

var ErrSearchUnavailable = errors.New("search service unavailable")

func (c *SearchClient) call(ctx context.Context, path string, in, out any) error {
	if c == nil || c.BaseURL == "" {
		return ErrSearchUnavailable
	}
	var body io.Reader
	method := http.MethodGet
	if in != nil {
		raw, e := json.Marshal(in)
		if e != nil {
			return e
		}
		body, method = bytes.NewReader(raw), http.MethodPost
	}
	req, e := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if e != nil {
		return e
	}
	req.Header.Set("X-Search-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, e := client.Do(req)
	if e != nil {
		return fmt.Errorf("%w: %v", ErrSearchUnavailable, e)
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if e != nil {
		return fmt.Errorf("%w: %v", ErrSearchUnavailable, e)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrSearchUnavailable, resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

type SearchServiceStatus struct {
	Format     string `json:"format"`
	Generation uint64 `json:"generation"`
	Docs       uint64 `json:"docs"`
	Rebuilding bool   `json:"rebuilding"`
}

func (c *SearchClient) Status(ctx context.Context) (SearchServiceStatus, error) {
	var out SearchServiceStatus
	return out, c.call(ctx, "/v1/status", nil, &out)
}

// searchDocument строит документ актива из PostgreSQL; ok=false — актива нет или он слит (документ удаляется).
func (r *Registry) searchDocument(ctx context.Context, tx pgx.Tx, tenant, uid string) (SearchDoc, bool, error) {
	d := SearchDoc{Asset: uid, Tenant: tenant, Hosts: []string{}, Serials: []string{}, IPs: []string{}, FQDNs: []string{}}
	var merged *string
	var version string
	e := tx.QueryRow(ctx, "SELECT aggregate_version::text,merged_into::text FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2", tenant, uid).Scan(&version, &merged)
	if errors.Is(e, pgx.ErrNoRows) {
		return d, false, nil
	}
	if e != nil {
		return d, false, e
	}
	if d.Version, e = strconv.ParseUint(version, 10, 64); e != nil {
		return d, false, e
	}
	if merged != nil {
		return d, false, nil
	}
	a, e := r.readAsset(ctx, tx, tenant, uid)
	if e != nil {
		return d, false, e
	}
	var text []string
	add := func(values ...*string) {
		for _, v := range values {
			if v != nil && *v != "" {
				text = append(text, *v)
			}
		}
	}
	add(a.Business.DisplayName, a.Business.Purpose, a.Hostname, a.OS)
	if a.Hostname != nil {
		d.Hosts = append(d.Hosts, *a.Hostname)
	}
	if a.OS != nil {
		switch o := strings.ToLower(*a.OS); {
		case strings.Contains(o, "windows"):
			d.OS = "windows"
		case o != "":
			d.OS = "linux"
		}
	}
	if d.OS == "" {
		d.OS = "unknown"
	}
	manual, _, e := r.Assets.ManualClass(ctx, tx, tenant, uid)
	if e != nil {
		return d, false, e
	}
	if manual != nil {
		d.Class = *manual
	} else if d.Class, _, e = r.Inventory.ObservedClass(ctx, tx, tenant, uid); e != nil {
		return d, false, e
	}
	rows, e := tx.Query(ctx, `SELECT kind,normalized_value FROM assets.asset_identifiers WHERE tenant_id=$1 AND asset_uid=$2 AND valid_to IS NULL AND kind IN ('serial','hostname','fqdn') GROUP BY 1,2 LIMIT 64`, tenant, uid)
	if e != nil {
		return d, false, e
	}
	for rows.Next() {
		var kind, value string
		if e = rows.Scan(&kind, &value); e != nil {
			rows.Close()
			return d, false, e
		}
		switch kind {
		case "serial":
			d.Serials = append(d.Serials, value)
		case "hostname":
			d.Hosts = append(d.Hosts, value)
		case "fqdn":
			d.FQDNs = append(d.FQDNs, value)
		}
	}
	rows.Close()
	// адреса: проекции 1.0 (JSON-массив адресов интерфейса) и 1.2 (поле addresses записей раздела network)
	if e = tx.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT ip),'{}') FROM (
SELECT jsonb_array_elements(value::jsonb)->>'ip' AS ip FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='network' AND fact_key LIKE '%.addresses'
UNION ALL SELECT jsonb_array_elements(value)->>'ip' FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='network' AND field_name='addresses' AND jsonb_typeof(value)='array') x WHERE ip IS NOT NULL`, tenant, uid).Scan(&d.IPs); e != nil {
		return d, false, e
	}
	var domain *string
	if e = tx.QueryRow(ctx, "SELECT max(value #>> '{}') FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='identity' AND field_name='domain'", tenant, uid).Scan(&domain); e != nil {
		return d, false, e
	}
	if domain != nil && *domain != "" && a.Hostname != nil {
		d.FQDNs = append(d.FQDNs, *a.Hostname+"."+*domain)
	}
	var software, people, services []string
	if e = tx.QueryRow(ctx, `SELECT COALESCE((SELECT array_agg(DISTINCT name) FROM (SELECT name FROM inventory.software_installations12 WHERE tenant_id=$1 AND asset_uid=$2 AND name IS NOT NULL LIMIT 3000) s),'{}'),
COALESCE((SELECT array_agg(s.name) FROM responsibility.responsibility_assignments a JOIN responsibility.subjects s ON s.tenant_id=a.tenant_id AND s.subject_id=a.subject_id WHERE a.tenant_id=$1 AND a.asset_uid=$2 AND a.valid_to IS NULL),'{}'),
COALESCE((SELECT array_agg(DISTINCT v.name) FROM cmdb.relations rel JOIN cmdb.services v ON v.tenant_id=rel.tenant_id AND v.service_uid=rel.from_service_uid WHERE rel.tenant_id=$1 AND rel.to_asset_uid=$2 AND rel.valid_to IS NULL AND v.retired_at IS NULL),'{}')`, tenant, uid).Scan(&software, &people, &services); e != nil {
		return d, false, e
	}
	text = append(text, people...)
	text = append(text, services...)
	text = append(text, software...)
	d.Text = strings.Join(text, " · ")
	return d, true, nil
}

// IndexSearchOne — один шаг потребителя outbox поиска для тенанта (false — событий нет). Сервис недоступен —
// событие не потребляется (попытки не тратятся, в dead letter не уходит).
func (r *Registry) IndexSearchOne(ctx context.Context, tenant string) (bool, error) {
	n, e := r.IndexSearchBatch(ctx, tenant, 1)
	return n > 0, e
}

// IndexSearchBatch — пачка событий outbox тенанта одним обращением к сервису (C30.03: по одному событию с фиксацией
// индекса на каждое потребитель не успевал за фоновым импортом). Активы в пачке не повторяются.
func (r *Registry) IndexSearchBatch(ctx context.Context, tenant string, max int) (int, error) {
	if r.Search == nil {
		return 0, ErrSearchUnavailable
	}
	if _, e := r.Search.Status(ctx); e != nil {
		return 0, e
	}
	return messaging.ConsumeBatch(ctx, r.Pool, tenant, SearchConsumer, max, func(ctx context.Context, tx pgx.Tx, events []messaging.Event) error {
		seen := map[string]bool{}
		var uids []string
		for _, ev := range events {
			if ev.Aggregate == "asset" && !seen[ev.AssetID] {
				seen[ev.AssetID] = true
				uids = append(uids, ev.AssetID)
			}
		}
		if len(uids) == 0 {
			return nil
		}
		return r.pushSearch(ctx, tx, tenant, uids, "/v1/apply")
	})
}

func (r *Registry) pushSearch(ctx context.Context, tx pgx.Tx, tenant string, uids []string, path string) error {
	req := searchApply{Docs: []SearchDoc{}, Deletes: []searchDelete{}}
	for _, uid := range uids {
		d, ok, e := r.searchDocument(ctx, tx, tenant, uid)
		if e != nil {
			return e
		}
		if ok {
			for _, list := range []*[]string{&d.Hosts, &d.Serials, &d.IPs, &d.FQDNs} {
				if *list == nil {
					*list = []string{}
				}
			}
			req.Docs = append(req.Docs, d)
		} else {
			req.Deletes = append(req.Deletes, searchDelete{Asset: uid, Version: d.Version})
		}
	}
	return r.Search.call(ctx, path, req, nil)
}

// RebuildSearch — полная пересборка индекса из PostgreSQL в новое поколение (изменения во время пересборки сервис
// пишет в оба поколения), затем атомарное переключение. Возвращает число документов.
func (r *Registry) RebuildSearch(ctx context.Context) (n int, err error) {
	if r.Search == nil {
		return 0, ErrSearchUnavailable
	}
	// C35.02: пересборку ведёт один процесс контура (индекс — один писатель)
	e := r.exclusive(ctx, "search-rebuild", func(ctx context.Context) error {
		n, err = r.rebuildSearchLocked(ctx)
		return nil
	})
	if e != nil {
		return 0, e
	}
	return n, err
}

func (r *Registry) rebuildSearchLocked(ctx context.Context) (int, error) {
	if e := r.Search.call(ctx, "/v1/rebuild/begin", struct{}{}, nil); e != nil {
		return 0, e
	}
	abort := func(e error) (int, error) {
		_ = r.Search.call(context.WithoutCancel(ctx), "/v1/rebuild/abort", struct{}{}, nil)
		return 0, e
	}
	total, tenant, after := 0, "", ""
	for {
		tx, e := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if e != nil {
			return abort(e)
		}
		rows, e := tx.Query(ctx, "SELECT tenant_id::text,asset_uid::text FROM assets.assets WHERE merged_into IS NULL AND (tenant_id,asset_uid)>($1::uuid,$2::uuid) ORDER BY tenant_id,asset_uid LIMIT 200", nonEmptyUUID(tenant), nonEmptyUUID(after))
		if e != nil {
			tx.Rollback(ctx)
			return abort(e)
		}
		batch := map[string][]string{}
		n := 0
		for rows.Next() {
			if e = rows.Scan(&tenant, &after); e != nil {
				rows.Close()
				tx.Rollback(ctx)
				return abort(e)
			}
			batch[tenant] = append(batch[tenant], after)
			n++
		}
		rows.Close()
		for t, uids := range batch {
			if e = r.pushSearch(ctx, tx, t, uids, "/v1/rebuild/load"); e != nil {
				tx.Rollback(ctx)
				return abort(e)
			}
		}
		tx.Rollback(ctx)
		total += n
		if n < 200 {
			break
		}
	}
	if e := r.Search.call(ctx, "/v1/rebuild/commit", struct{}{}, nil); e != nil {
		return abort(e)
	}
	return total, nil
}

func nonEmptyUUID(v string) string {
	if v == "" {
		return "00000000-0000-0000-0000-000000000000"
	}
	return v
}

// --- API ---

type SearchResultItem struct {
	Asset       string   `json:"asset_uid"`
	DisplayName *string  `json:"display_name"`
	Hostname    *string  `json:"observed_hostname"`
	OS          *string  `json:"observed_os"`
	Score       *float32 `json:"score"`
	Fragment    string   `json:"fragment"`
	Highlights  [][2]int `json:"highlights"`
}

type SearchPage struct {
	Tenant     string                    `json:"tenant_id"`
	Query      string                    `json:"query"`
	Mode       string                    `json:"mode"` // fulltext | fallback_exact
	Notice     string                    `json:"notice,omitempty"`
	Lag        int                       `json:"pending_index_events"`
	Items      []SearchResultItem        `json:"items"`
	Facets     map[string]map[string]int `json:"facets"`
	NextCursor *string                   `json:"next_cursor"`
}

const searchWindow = 1000

func (r *Registry) SearchAssets(ctx context.Context, id accessport.Identity, query string, filters map[string]string, offset, limit int) (SearchPage, error) {
	out := SearchPage{Tenant: id.TenantID, Query: query, Items: []SearchResultItem{}, Facets: map[string]map[string]int{"os": {}, "class": {}}}
	if l := len([]rune(strings.TrimSpace(query))); l < 2 || l > 256 || offset < 0 || offset >= searchWindow || limit < 1 || limit > 100 {
		return out, domain.Invalid
	}
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM messaging.outbox_events e WHERE e.tenant_id=$1 AND NOT EXISTS(SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name=$2 AND c.state='applied')`, id.TenantID, SearchConsumer).Scan(&out.Lag); e != nil {
		return out, e
	}
	var hits []SearchHit
	var resp struct {
		Total int         `json:"total"`
		Hits  []SearchHit `json:"hits"`
	}
	if filters == nil {
		filters = map[string]string{}
	}
	e = r.Search.call(ctx, "/v1/search", map[string]any{"tenant": id.TenantID, "query": query, "filters": filters, "limit": searchWindow, "snippets": min(offset+limit+20, searchWindow)}, &resp)
	if e == nil {
		out.Mode, hits = "fulltext", resp.Hits
	} else if errors.Is(e, ErrSearchUnavailable) {
		out.Mode = "fallback_exact"
		out.Notice = "Полнотекстовый поиск недоступен: показаны только точные совпадения имени, серийного номера, IP и названия ПО. Морфология, части FQDN и опечатки не учитываются."
		if hits, e = r.exactSearch(ctx, tx, id.TenantID, query, filters); e != nil {
			return out, e
		}
	} else {
		return out, e
	}
	// перепроверка по источнику истины: тенант, существование, не слит (индекс мог устареть)
	candidates := make([]string, 0, len(hits))
	for _, h := range hits {
		candidates = append(candidates, h.Asset)
	}
	live := map[string]bool{}
	rows, e := tx.Query(ctx, "SELECT asset_uid::text FROM assets.assets WHERE tenant_id=$1 AND asset_uid=ANY($2::uuid[]) AND merged_into IS NULL", id.TenantID, candidates)
	if e != nil {
		return out, e
	}
	for rows.Next() {
		var uid string
		if e = rows.Scan(&uid); e != nil {
			rows.Close()
			return out, e
		}
		live[uid] = true
	}
	rows.Close()
	visible := hits[:0]
	for _, h := range hits {
		if live[h.Asset] {
			visible = append(visible, h)
		}
	}
	// фасеты — только по перепроверенным кандидатам (счётчики не раскрывают чужие или устаревшие документы)
	for _, h := range visible {
		out.Facets["os"][h.OS]++
		out.Facets["class"][h.Class]++
	}
	if offset < len(visible) {
		page := visible[offset:min(offset+limit, len(visible))]
		for _, h := range page {
			a, e := r.readAsset(ctx, tx, id.TenantID, h.Asset)
			if e != nil {
				return out, e
			}
			item := SearchResultItem{Asset: h.Asset, DisplayName: a.Business.DisplayName, Hostname: a.Hostname, OS: a.OS, Fragment: h.Fragment, Highlights: h.Highlights}
			if out.Mode == "fulltext" {
				score := h.Score
				item.Score = &score
			}
			if item.Highlights == nil {
				item.Highlights = [][2]int{}
			}
			out.Items = append(out.Items, item)
		}
		if next := offset + limit; next < len(visible) && next < searchWindow {
			c := strconv.Itoa(next)
			out.NextCursor = &c
		}
	}
	return out, tx.Commit(ctx)
}

// exactSearch — запасной режим без сервиса: точные совпадения по PostgreSQL (не эквивалент полнотекстового поиска).
func (r *Registry) exactSearch(ctx context.Context, tx pgx.Tx, tenant, query string, filters map[string]string) ([]SearchHit, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	rows, e := tx.Query(ctx, `SELECT DISTINCT a.asset_uid::text FROM assets.assets a WHERE a.tenant_id=$1 AND a.merged_into IS NULL AND (
EXISTS(SELECT 1 FROM assets.asset_identifiers i WHERE i.tenant_id=a.tenant_id AND i.asset_uid=a.asset_uid AND i.valid_to IS NULL AND lower(i.normalized_value)=$2)
OR EXISTS(SELECT 1 FROM assets.asset_business_fields b WHERE b.tenant_id=a.tenant_id AND b.asset_uid=a.asset_uid AND lower(b.display_name)=$2)
OR EXISTS(SELECT 1 FROM inventory.record_facts12 f WHERE f.tenant_id=a.tenant_id AND f.asset_uid=a.asset_uid AND f.section_name='identity' AND f.field_name='hostname' AND lower(f.value #>> '{}')=$2)
OR EXISTS(SELECT 1 FROM inventory.current_facts f WHERE f.tenant_id=a.tenant_id AND f.asset_uid=a.asset_uid AND f.section_name='identity' AND f.fact_key='hostname' AND lower(f.value)=$2)
OR EXISTS(SELECT 1 FROM inventory.record_facts12 f WHERE f.tenant_id=a.tenant_id AND f.asset_uid=a.asset_uid AND f.section_name='network' AND f.field_name='addresses' AND jsonb_typeof(f.value)='array' AND f.value @> jsonb_build_array(jsonb_build_object('ip',$2::text)))
OR EXISTS(SELECT 1 FROM inventory.software_installations12 s WHERE s.tenant_id=a.tenant_id AND s.asset_uid=a.asset_uid AND lower(s.name)=$2)
) ORDER BY 1 LIMIT $3`, tenant, q, searchWindow)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	hits := []SearchHit{}
	for rows.Next() {
		var h SearchHit
		if e = rows.Scan(&h.Asset); e != nil {
			return nil, e
		}
		hits = append(hits, h)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	filtered := hits[:0]
	for _, h := range hits {
		d, ok, e := r.searchDocument(ctx, tx, tenant, h.Asset)
		if e != nil {
			return nil, e
		}
		if ok && (filters["os"] == "" || filters["os"] == d.OS) && (filters["class"] == "" || filters["class"] == d.Class) {
			h.OS, h.Class = d.OS, d.Class
			filtered = append(filtered, h)
		}
	}
	return filtered, nil
}

func (r *Registry) searchHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, ok := queryOnly(w, req, "q", "os", "class", "cursor", "limit")
		if !ok {
			return
		}
		limit, ok := pageLimit(w, q, 20, 100)
		if !ok {
			return
		}
		offset := 0
		if c := q.Get("cursor"); c != "" {
			n, err := strconv.Atoi(c)
			if err != nil || n < 1 || n >= searchWindow {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
			offset = n
		}
		filters := map[string]string{}
		for _, k := range []string{"os", "class"} {
			if v := q.Get(k); v != "" {
				filters[k] = v
			}
		}
		ctx, cancel, id := cmdbContext(req)
		defer cancel()
		out, e := r.SearchAssets(ctx, id, q.Get("q"), filters, offset, limit)
		if e != nil {
			if errors.Is(e, domain.Invalid) {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
			cmdbError(w, req, e)
			return
		}
		registryJSON(w, out)
	})
}

func (r *Registry) searchRebuildHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, ok := queryOnly(w, req); !ok {
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 30*time.Minute)
		defer cancel()
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(31 * time.Minute))
		id, _ := access.Identity(req.Context())
		tx, e := r.Pool.Begin(ctx)
		if e != nil {
			registryError(w, e)
			return
		}
		if _, e = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "sources:admin"); e != nil {
			tx.Rollback(ctx)
			registryError(w, e)
			return
		}
		if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "search.rebuild_requested", "search", id.TenantID); e != nil || tx.Commit(ctx) != nil {
			tx.Rollback(ctx)
			registryError(w, e)
			return
		}
		n, e := r.RebuildSearch(ctx)
		if e != nil {
			if errors.Is(e, ErrSearchUnavailable) {
				access.APIError(w, 503, "SEARCH_UNAVAILABLE")
				return
			}
			if errors.Is(e, ErrBusy) {
				access.APIError(w, 409, "CONFLICT") // пересборка уже идёт в другом процессе центра
				return
			}
			registryError(w, e)
			return
		}
		registryJSON(w, map[string]any{"indexed_assets": n})
	})
}

// SearchFormat — формат индекса, который ожидает центр; при несовпадении (обновление сервиса) индекс пересобирается.
const SearchFormat = "surveyscan-search-2/tantivy-0.27"

// SearchMaintain — фоновая роль центра: пересборка при смене формата или пустом индексе, иначе применение событий outbox.
func (r *Registry) SearchMaintain(ctx context.Context, log func(string)) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		task, done := context.WithTimeout(ctx, 30*time.Minute)
		status, e := r.Search.Status(task)
		if e == nil {
			var assets int
			if e = r.Pool.QueryRow(task, "SELECT count(*) FROM assets.assets WHERE merged_into IS NULL").Scan(&assets); e == nil && (status.Format != SearchFormat || status.Docs == 0 && assets > 0) && !status.Rebuilding {
				n, e := r.RebuildSearch(task)
				if !errors.Is(e, ErrBusy) {
					log(fmt.Sprintf("search index rebuilt: %d assets (format %q → %q), err=%v", n, status.Format, SearchFormat, e))
				}
			}
			tenants, e := messaging.PendingTenantsFor(task, r.Pool, SearchConsumer)
			if e == nil {
				for _, tenant := range tenants {
					for range 20 {
						n, e := r.IndexSearchBatch(task, tenant, 200)
						if e != nil || n == 0 {
							break
						}
					}
				}
			}
		}
		done()
	}
}

// SearchCall — низкоуровневый вызов сервиса поиска (проверки и сопровождение: пересборка, состояние).
func SearchCall(c *SearchClient, ctx context.Context, path string, in, out any) error {
	return c.call(ctx, path, in, out)
}
