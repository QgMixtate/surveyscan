package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/assets"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

// C31.02 (ADR decisions/C31-integrations.md): обмен ручными бизнес-полями активов через CSV (Excel, 1С).
// Мастер — SurveyScan: импорт — операция оператора с проверкой ревизии каждой строки, а не второй источник истины.

const CSVFormat = "#surveyscan-assets-csv;v1"

var csvColumns = []string{"asset_uid", "business_revision", "display_name", "purpose", "criticality", "tags", "asset_class",
	"observed_hostname", "observed_os", "accountable_subject_id", "accountable_name", "last_inventory_at"}

// csvCell защищает от формул в табличных редакторах: значение, начинающееся с = + - @ (или табуляции/CR), получает
// префикс «'»; импорт этот префикс снимает.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func csvValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 1 && s[0] == '\'' && strings.ContainsRune("=+-@\t\r", rune(s[1])) {
		return s[1:]
	}
	return s
}

func (r *Registry) ExportAssetsCSV(ctx context.Context, id accessport.Identity, w io.Writer) error {
	tx, e := r.readTx(ctx, id)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	out := bufio.NewWriter(w)
	out.WriteString("\uFEFF" + CSVFormat + "\r\n")
	c := csv.NewWriter(out)
	c.Comma, c.UseCRLF = ';', true
	if e = c.Write(csvColumns); e != nil {
		return e
	}
	names := map[string]string{}
	after := ""
	for {
		ids, e := r.Assets.IDs(ctx, tx, id.TenantID, after, 500)
		if e != nil {
			return e
		}
		for _, uid := range ids {
			a, e := r.readAsset(ctx, tx, id.TenantID, uid)
			if e != nil {
				return e
			}
			class, _, e := r.Assets.ManualClass(ctx, tx, id.TenantID, uid)
			if e != nil {
				return e
			}
			name, ok := names[a.Accountable]
			if !ok && a.Accountable != "" {
				if s, e := r.Owners.SubjectByID(ctx, tx, id.TenantID, a.Accountable); e == nil {
					name = s.Name
				}
				names[a.Accountable] = name
			}
			opt := func(p *string) string {
				if p == nil {
					return ""
				}
				return *p
			}
			last := ""
			if a.LastInventory != nil {
				last = a.LastInventory.UTC().Format(time.RFC3339)
			}
			row := []string{a.UID, a.Revision, opt(a.Business.DisplayName), opt(a.Business.Purpose), a.Business.Criticality,
				strings.Join(a.Business.Tags, ","), opt(class), opt(a.Hostname), opt(a.OS), a.Accountable, name, last}
			for i := range row {
				row[i] = csvCell(row[i])
			}
			if e = c.Write(row); e != nil {
				return e
			}
		}
		if len(ids) < 500 {
			break
		}
		after = ids[len(ids)-1]
	}
	c.Flush()
	if e = c.Error(); e != nil {
		return e
	}
	if e = out.Flush(); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

type CSVRowResult struct {
	Line     int     `json:"line"`
	Asset    string  `json:"asset_uid"`
	Status   string  `json:"status"` // applied | unchanged | stale_revision | not_found | invalid
	Field    *string `json:"field"`
	Revision *string `json:"business_revision"`
}

type CSVImportResult struct {
	Tenant  string         `json:"tenant_id"`
	DryRun  bool           `json:"dry_run"`
	Format  string         `json:"format"`
	Counts  map[string]int `json:"counts"`
	Results []CSVRowResult `json:"results"`
}

var errCSVFormat = errors.New("csv format")

const csvMaxRows = 10000

type csvRow struct {
	line                                         int
	uid, revision, name, purpose, crit, tags, cl string
}

func parseAssetsCSV(raw []byte) ([]csvRow, error) {
	raw = bytes.TrimPrefix(raw, []byte("\uFEFF"))
	if !utf8.Valid(raw) {
		return nil, errCSVFormat
	}
	head, rest, ok := bytes.Cut(raw, []byte("\n"))
	if !ok || strings.TrimRight(string(head), "\r;") != CSVFormat {
		return nil, errCSVFormat // неизвестная или отсутствующая версия формата — отказ целиком
	}
	c := csv.NewReader(bytes.NewReader(rest))
	c.Comma, c.FieldsPerRecord, c.ReuseRecord = ';', -1, false
	header, e := c.Read()
	if e != nil {
		return nil, errCSVFormat
	}
	at := map[string]int{}
	for i, h := range header {
		at[strings.TrimSpace(h)] = i
	}
	if _, ok := at["asset_uid"]; !ok {
		return nil, errCSVFormat
	}
	if _, ok := at["business_revision"]; !ok {
		return nil, errCSVFormat
	}
	get := func(rec []string, col string) string {
		if i, ok := at[col]; ok && i < len(rec) {
			return csvValue(rec[i])
		}
		return ""
	}
	rows := []csvRow{}
	for {
		rec, e := c.Read()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return nil, errCSVFormat
		}
		if len(rows) == csvMaxRows {
			return nil, errCSVFormat
		}
		line, _ := c.FieldPos(0)
		rows = append(rows, csvRow{line: line + 1, uid: strings.ToLower(get(rec, "asset_uid")), revision: get(rec, "business_revision"),
			name: get(rec, "display_name"), purpose: get(rec, "purpose"), crit: get(rec, "criticality"), tags: get(rec, "tags"), cl: get(rec, "asset_class")})
	}
	return rows, nil
}

func (r *Registry) ImportAssetsCSV(ctx context.Context, id accessport.Identity, raw []byte, dryRun bool) (CSVImportResult, error) {
	out := CSVImportResult{Tenant: id.TenantID, DryRun: dryRun, Format: CSVFormat, Counts: map[string]int{"applied": 0, "unchanged": 0, "stale_revision": 0, "not_found": 0, "invalid": 0}, Results: []CSVRowResult{}}
	rows, e := parseAssetsCSV(raw)
	if e != nil {
		return out, domain.Invalid
	}
	tx, e := r.assetOperationTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	seen := map[string]bool{}
	for _, row := range rows {
		res, e := r.importRow(ctx, tx, id, row, dryRun, seen)
		if e != nil {
			return out, e
		}
		out.Counts[res.Status]++
		out.Results = append(out.Results, res)
	}
	if out.Counts["applied"] > 0 && !dryRun {
		if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "assets.csv_imported", "csv_import", identifier.New()); e != nil {
			return out, e
		}
	}
	if dryRun {
		return out, nil // откат: проверка без изменений
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) importRow(ctx context.Context, tx pgx.Tx, id accessport.Identity, row csvRow, dryRun bool, seen map[string]bool) (CSVRowResult, error) {
	res := CSVRowResult{Line: row.line, Asset: cut64(row.uid), Status: "invalid"}
	field := func(f string) (CSVRowResult, error) { res.Field = &f; return res, nil }
	if !identifier.Valid(row.uid) {
		return field("asset_uid")
	}
	if seen[row.uid] {
		return field("asset_uid") // строка актива повторяется — неоднозначно
	}
	seen[row.uid] = true
	if _, e := strconv.ParseUint(row.revision, 10, 64); e != nil {
		return field("business_revision")
	}
	a, e := r.Assets.Get(ctx, tx, id.TenantID, row.uid)
	if errors.Is(e, domain.NotFound) || e == nil && a.TenantID != id.TenantID {
		res.Status = "not_found" // включая слитые (их строки — по каноническому активу) и чужие
		return res, nil
	}
	if e != nil {
		var merged assets.ErrMerged
		if errors.As(e, &merged) {
			res.Status = "not_found"
			return res, nil
		}
		return res, e
	}
	class, revision, e := r.Assets.ManualClass(ctx, tx, id.TenantID, row.uid)
	if e != nil {
		return res, e
	}
	if revision != row.revision {
		res.Status, res.Revision = "stale_revision", &revision
		return res, nil
	}
	var p contracts.BusinessPatch
	if row.name != "" && (a.Business.DisplayName == nil || *a.Business.DisplayName != row.name) {
		p.DisplayName = &row.name
	}
	if row.purpose != "" && (a.Business.Purpose == nil || *a.Business.Purpose != row.purpose) {
		p.Purpose = &row.purpose
	}
	if row.crit != "" && row.crit != a.Business.Criticality {
		p.Criticality = &row.crit
	}
	if row.tags != "" {
		tags := []string{}
		for _, t := range strings.Split(row.tags, ",") {
			if t = strings.TrimSpace(t); t != "" && !slices.Contains(tags, t) {
				tags = append(tags, t)
			}
		}
		if !slices.Equal(tags, a.Business.Tags) {
			p.Tags = &tags
		}
	}
	var newClass *string
	setClass := false
	switch {
	case row.cl == "-":
		setClass = class != nil
	case row.cl != "":
		if !assetClasses[row.cl] {
			return field("asset_class")
		}
		newClass, setClass = &row.cl, class == nil || *class != row.cl
	}
	patch := p.DisplayName != nil || p.Purpose != nil || p.Criticality != nil || p.Tags != nil
	if patch {
		raw, _ := json.Marshal(p)
		if e = r.Wire.Validate("BusinessPatch", raw); e != nil {
			for _, f := range []string{"display_name", "purpose", "criticality", "tags"} {
				if one, _ := json.Marshal(map[string]any{f: json.RawMessage(fieldOf(raw, f))}); fieldOf(raw, f) != nil && r.Wire.Validate("BusinessPatch", one) != nil {
					return field(f)
				}
			}
			return field("business")
		}
	}
	if !patch && !setClass {
		res.Status, res.Revision = "unchanged", &revision
		return res, nil
	}
	res.Status = "applied"
	if dryRun {
		res.Revision = &revision
		return res, nil
	}
	next := revision
	if patch {
		if e = r.Assets.Patch(ctx, tx, id.TenantID, row.uid, next, p); e != nil {
			return res, e
		}
		n, _ := strconv.ParseUint(next, 10, 64)
		next = strconv.FormatUint(n+1, 10)
	}
	if setClass {
		if e = r.Assets.SetClass(ctx, tx, id.TenantID, row.uid, next, newClass); e != nil {
			return res, e
		}
		n, _ := strconv.ParseUint(next, 10, 64)
		next = strconv.FormatUint(n+1, 10)
	}
	version, e := r.Assets.Bump(ctx, tx, id.TenantID, row.uid)
	if e != nil {
		return res, e
	}
	if e = r.assetEvent(ctx, tx, id.TenantID, row.uid, version, "asset.facts_changed.v1", "Assets", "CSV_IMPORT", id.UserID, identifier.New()); e != nil {
		return res, e
	}
	res.Revision = &next
	return res, nil
}

func fieldOf(raw []byte, f string) []byte {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m[f]
}

func (r *Registry) csvHandlers() map[string]http.Handler {
	return map[string]http.Handler{
		"GET /api/v1/assets/export.csv": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := queryOnly(w, req); !ok {
				return
			}
			ctx, cancel := assetOperationContext(w, req)
			defer cancel()
			id, _ := access.Identity(req.Context())
			var buf bytes.Buffer // целиком: ошибка в середине не должна отдать обрезанный файл с кодом 200
			if e := r.ExportAssetsCSV(ctx, id, &buf); e != nil {
				cmdbError(w, req, e)
				return
			}
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="surveyscan-assets.csv"`)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Write(buf.Bytes())
		}),
		"POST /api/v1/assets/import.csv": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			q, ok := queryOnly(w, req, "dry_run")
			if !ok {
				return
			}
			dry := q.Get("dry_run")
			if dry != "true" && dry != "false" {
				access.APIError(w, 400, "INVALID_QUERY") // явный выбор: проверка или применение
				return
			}
			if ct := req.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
				access.APIError(w, 415, "UNSUPPORTED_MEDIA_TYPE")
				return
			}
			raw, e := io.ReadAll(http.MaxBytesReader(w, req.Body, 8<<20))
			if e != nil {
				access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
				return
			}
			ctx, cancel := assetOperationContext(w, req)
			defer cancel()
			id, _ := access.Identity(req.Context())
			out, e := r.ImportAssetsCSV(ctx, id, raw, dry == "true")
			if e != nil {
				cmdbError(w, req, e)
				return
			}
			registryJSON(w, out)
		}),
	}
}

func cut64(s string) string {
	if len(s) > 64 {
		s = strings.ToValidUTF8(s[:64], "")
	}
	return s
}
