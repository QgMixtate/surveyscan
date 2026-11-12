//go:build integration

package app_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// searchService — настоящий surveyscan-search (Rust) на loopback; путь к бинарнику — SURVEYSCAN_SEARCH_BIN или
// v2/search/target/release/surveyscan-search (cargo build --release в v2/search).
type searchService struct {
	t           *testing.T
	bin, data   string
	token, addr string
	cmd         *osexec.Cmd
}

func startSearch(t *testing.T) *searchService {
	t.Helper()
	bin := os.Getenv("SURVEYSCAN_SEARCH_BIN")
	if bin == "" {
		bin, _ = filepath.Abs("../../search/target/release/surveyscan-search")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("surveyscan-search binary not built: cd v2/search && cargo build --release (or set SURVEYSCAN_SEARCH_BIN)")
	}
	dir := t.TempDir()
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	s := &searchService{t: t, bin: bin, data: filepath.Join(dir, "index"), token: hex.EncodeToString(raw)}
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(s.token), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = l.Addr().String()
	l.Close()
	s.start(tokenFile)
	t.Cleanup(s.stop)
	return s
}

func (s *searchService) start(tokenFile string) {
	s.t.Helper()
	s.cmd = osexec.Command(s.bin, s.addr, s.data, tokenFile)
	s.cmd.Stderr = os.Stderr
	if err := s.cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	client := s.client()
	for range 100 {
		if _, err := client.Status(context.Background()); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.t.Fatal("search service did not start")
}

func (s *searchService) stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill() // «падение» без корректного завершения
		_, _ = s.cmd.Process.Wait()
		s.cmd = nil
	}
}

func (s *searchService) client() *app.SearchClient {
	return &app.SearchClient{BaseURL: "http://" + s.addr, Token: s.token}
}

func TestC29SearchProjection(t *testing.T) {
	f := registrySetup(t)
	svc := startSearch(t)
	tokenFile := filepath.Join(filepath.Dir(svc.data), "token")
	f.registry.Search = svc.client()
	n := 0
	newAsset := func(host, purpose string) string {
		n++
		o := f.observation("1")
		mu := fmt.Sprintf("00000000-0000-4000-8000-%012d", 900+n)
		o.Record.LocalID = "search-" + host
		o.Candidates = []contracts.Candidate{{Kind: "machine_uuid", Namespace: "host", Value: mu}, {Kind: "hostname", Namespace: "dns", Value: host}}
		o.Sections[0].Records = []map[string]any{{"hostname": host, "machine_uuid": mu}}
		r := f.ingest(t, o)
		if r.AssetID == nil {
			t.Fatal("asset not created")
		}
		if purpose != "" {
			card, err := f.registry.Get(f.ctx, f.identity, *r.AssetID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.registry.Patch(f.ctx, f.identity, *r.AssetID, card.Revision, contracts.BusinessPatch{Purpose: &purpose}); err != nil {
				t.Fatal(err)
			}
		}
		return *r.AssetID
	}
	drain := func() {
		t.Helper()
		for range 100000 {
			worked, err := f.registry.IndexSearchOne(f.ctx, tenant)
			if err != nil {
				t.Fatal(err)
			}
			if !worked {
				return
			}
		}
		t.Fatal("index consumer did not drain")
	}
	search := func(q string) app.SearchPage {
		t.Helper()
		page, err := f.registry.SearchAssets(f.ctx, f.identity, q, nil, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}
	has := func(p app.SearchPage, uid string) bool {
		for _, it := range p.Items {
			if it.Asset == uid {
				return true
			}
		}
		return false
	}
	liveAssets := func() int {
		var c int
		if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM assets.assets WHERE merged_into IS NULL").Scan(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}

	// 1. индексация из outbox: имя хоста, назначение (морфология), фрагмент с подсветкой
	acct := newAsset("buh-srv-01", "Сервер бухгалтерии филиала")
	db := newAsset("db-main-02", "")
	drain()
	if st, _ := svc.client().Status(f.ctx); st.Docs != uint64(liveAssets()) {
		t.Fatal("index must hold every live asset", st.Docs, liveAssets())
	}
	p := search("бухгалтерия")
	if p.Mode != "fulltext" || !has(p, acct) || has(p, db) || p.Lag != 0 {
		t.Fatalf("morphological search: %+v", p)
	}
	if len(p.Items[0].Highlights) == 0 || !strings.Contains(p.Items[0].Fragment, "бухгалтерии") {
		t.Fatal("fragment must highlight the match", p.Items[0])
	}
	if !has(search("db-main"), db) {
		t.Fatal("host prefix search")
	}

	// 2. сбой сервиса: события не потребляются и не сгорают; после перезапуска — догоняет
	svc.stop()
	ws := newAsset("ws-crash-03", "Рабочее место кассира")
	if _, err := f.registry.IndexSearchOne(f.ctx, tenant); !errors.Is(err, app.ErrSearchUnavailable) {
		t.Fatal("consumer must stop while the service is down", err)
	}
	var claimed int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM messaging.consumer_checkpoints WHERE consumer_name=$1 AND state<>'applied'", app.SearchConsumer).Scan(&claimed)
	if claimed != 0 {
		t.Fatal("unavailable service must not burn attempts", claimed)
	}
	// запасной режим: только точные совпадения, явно помеченный; морфологии нет
	fb := search("ws-crash-03")
	if fb.Mode != "fallback_exact" || fb.Notice == "" || !has(fb, ws) || fb.Lag == 0 {
		t.Fatalf("fallback must find the exact host and say so: %+v", fb)
	}
	if fb = search("кассир"); fb.Mode != "fallback_exact" || len(fb.Items) != 0 {
		t.Fatal("fallback is not full-text and must not pretend to be", fb.Items)
	}
	svc.start(tokenFile)
	drain()
	if !has(search("кассира"), ws) {
		t.Fatal("after restart the index must catch up")
	}

	// 3. повтор всей истории (сброс контрольной точки): дублей нет, документы те же
	before, _ := svc.client().Status(f.ctx)
	if _, err := f.pool.Exec(f.ctx, "DELETE FROM messaging.consumer_checkpoints WHERE consumer_name=$1", app.SearchConsumer); err != nil {
		t.Fatal(err)
	}
	drain()
	if after, _ := svc.client().Status(f.ctx); after.Docs != before.Docs || len(search("бухгалтерии").Items) != 1 {
		t.Fatal("full replay must be idempotent", before.Docs, after.Docs)
	}

	// 4. слияние: поглощённый документ удаляется, канонический находится по имени поглощённого
	if _, err := f.registry.MergeAssets(f.ctx, f.identity, app.MergeRequest{Target: db, Absorbed: ws}); err != nil {
		t.Fatal(err)
	}
	drain()
	p = search("ws-crash-03")
	if has(p, ws) || !has(p, db) {
		t.Fatalf("merged asset must resolve to the canonical one: %+v", p.Items)
	}

	// 5. устаревший/чужой документ в индексе не раскрывается ни в выдаче, ни в фасетах
	forged := identifier.New()
	raw := `{"docs":[{"asset_uid":"` + forged + `","tenant":"` + tenant + `","version":1,"os":"linux","class":"printer","hosts":["leak-host"],"text":"бухгалтерия утечка"}]}`
	if err := postRaw(svc, "/v1/apply", raw); err != nil {
		t.Fatal(err)
	}
	p = search("бухгалтерия")
	if has(p, forged) || p.Facets["class"]["printer"] != 0 {
		t.Fatalf("index entry without a live asset must not leak: %+v", p)
	}
	if len(search("leak-host").Items) != 0 {
		t.Fatal("stale entry must be filtered by PostgreSQL recheck")
	}

	// 6. всплеск импорта одновременно с потреблением
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 60 {
			newAsset(fmt.Sprintf("burst-%02d", i), "")
		}
	}()
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = f.registry.IndexSearchOne(f.ctx, tenant)
				time.Sleep(10 * time.Millisecond) // фоновая роль центра работает тиками, не в плотном цикле
			}
		}
	}()
	wg.Wait()
	close(stop)
	drain()
	if len(search("burst").Items) != 60 {
		t.Fatal("burst must be fully indexed", len(search("burst").Items))
	}

	// 7. пересборка из PostgreSQL сходится с источником истины (и убирает поддельную запись)
	indexed, err := f.registry.RebuildSearch(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := svc.client().Status(f.ctx)
	if indexed != liveAssets() || st.Docs != uint64(liveAssets()) || st.Generation < 2 {
		t.Fatal("rebuild must converge with PostgreSQL", indexed, st, liveAssets())
	}
	var probe struct {
		Total int `json:"total"`
	}
	if err = postRawInto(svc, "/v1/search", `{"tenant":"`+tenant+`","query":"leak-host","filters":{},"limit":10}`, &probe); err != nil || probe.Total != 0 {
		t.Fatal("rebuild must drop entries absent from PostgreSQL", probe, err)
	}

	// 8. HTTP: контракт ответа, фасеты, курсор, валидация запроса, токен сервиса обязателен
	auth, err := access.NewHTTP(f.users, "https://ui.example", false)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewHTTP(auth, health.Handler(func(context.Context) error { return nil }), f.registry)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	b := newBrowser(t, server)
	b.login(t, "admin")
	code, body, _ := b.request(t, "GET", "/api/v1/search?q=burst&limit=25", "", "", "", nil)
	expect(t, 200, code)
	schemaRaw, _ := os.ReadFile("../../contracts/c29-search.schema.json")
	doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	_ = compiler.AddResource("urn:surveyscan:c29:search:1:0", doc)
	schema, err := compiler.Compile("urn:surveyscan:c29:search:1:0#/$defs/SearchPage")
	if err != nil {
		t.Fatal(err)
	}
	instance, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(body)))
	if err = schema.Validate(instance); err != nil {
		t.Fatal("search page violates contract", err, string(body))
	}
	var page app.SearchPage
	_ = json.Unmarshal(body, &page)
	if len(page.Items) != 25 || page.NextCursor == nil || page.Facets["os"]["linux"] != 60 {
		t.Fatalf("paging and facets: %d %v %v", len(page.Items), page.NextCursor, page.Facets)
	}
	code, _, _ = b.request(t, "GET", "/api/v1/search?q=burst&cursor="+url.QueryEscape(*page.NextCursor), "", "", "", nil)
	expect(t, 200, code)
	code, _, _ = b.request(t, "GET", "/api/v1/search?q=x", "", "", "", nil)
	expect(t, 400, code)
	if _, err = (&app.SearchClient{BaseURL: "http://" + svc.addr, Token: strings.Repeat("0", 48)}).Status(f.ctx); err == nil {
		t.Fatal("service must reject a wrong token")
	}
}

func postRaw(s *searchService, path, body string) error { return postRawInto(s, path, body, nil) }

func postRawInto(s *searchService, path, body string, out any) error {
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return err
	}
	return app.SearchCall(s.client(), context.Background(), path, v, out)
}
