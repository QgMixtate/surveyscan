//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/inventory"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// R-027, решения пользователя 1А/2А/3А на сценарии стенда: агент на хосте и SSH-цель одной машины (оба — источники
// вида agent, отличаются способом сбора acquisition), доверенные часы.
//
//	3А — данные агента не перезаписываются более поздним сбором SSH (приоритет +2 против +1);
//	1А — статус раздела в карточке — лучший среди источников, попытки каждого источника отдаются списком;
//	2А — профиль 1.2 засчитывается успешной инвентаризацией, если нет «недоступных» разделов.
func TestR027SourcePrecedenceSectionStatusAndSuccess12(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	collectorSource, collectorID := identifier.New(), identifier.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.pool.Exec(f.ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO sources.sources(tenant_id,source_id,source_kind,site_id,state,generation_id) VALUES($1,$2,'collector',$3,'active',$4)", tenant, collectorSource, siteID, identifier.New())
	exec("INSERT INTO sources.collectors(tenant_id,collector_id,source_id) VALUES($1,$2,$3)", tenant, collectorID, collectorSource)
	type src struct {
		id, gen, keyID string
		key            ed25519.PrivateKey
	}
	agentSource := func(acquisition string) src {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		s := src{identifier.New(), identifier.New(), identifier.New(), key}
		exec("INSERT INTO sources.sources(tenant_id,source_id,source_kind,site_id,state,generation_id) VALUES($1,$2,'agent',$3,'active',$4)", tenant, s.id, siteID, s.gen)
		exec("INSERT INTO sources.agents(tenant_id,agent_id,source_id,collector_id,acquisition) VALUES($1,$2,$3,$4,$5)", tenant, identifier.New(), s.id, collectorID, acquisition)
		exec("INSERT INTO sources.ingest_bindings(tenant_id,source_id,generation_id,key_id,namespace,scope_id,public_key) VALUES($1,$2,$3,$4,'host',$5,$6)", tenant, s.id, s.gen, s.keyID, scopeID, []byte(pub))
		return s
	}
	machine := contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: "4c4c4544-0000-1000-8000-" + identifier.New()[24:]}
	base := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	send := func(s src, seq string, at time.Time, osVersion string, unavailable ...string) inventory.Result {
		t.Helper()
		o := testObservation12(t, f, seq)
		o.Origin = contracts.Origin{SourceID: s.id, SourceKind: "agent", GenerationID: s.gen}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: "host:" + s.id[:8]}
		o.Clock, o.CollectedAt, o.Candidates = "trusted", at, []contracts.Candidate{machine}
		for i := range o.Sections {
			sec := &o.Sections[i]
			sec.CollectedAt = at
			if sec.Name == "os" {
				sec.Records = []map[string]any{{"name": "Ubuntu", "version": osVersion, "architecture": "amd64"}}
				sec.Count = 1
			}
			for _, name := range unavailable {
				if sec.Name == name {
					sec.Status, sec.Reason, sec.Count, sec.Records = "unavailable", "SOURCE_UNAVAILABLE", 0, []map[string]any{}
				}
			}
		}
		payload, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := wire.Canonical(payload)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(canonical)
		sig := ed25519.Sign(s.key, append([]byte("SURVEYSCAN-OBSERVATION-V1\n"), canonical...))
		raw, _ := json.Marshal(contracts.SignedObservation{Payload: payload, Digest: hex.EncodeToString(digest[:]), KeyID: s.keyID, Signature: base64.RawURLEncoding.EncodeToString(sig)})
		r, err := f.registry.Ingest(f.ctx, tenant, s.id, raw)
		if err != nil {
			t.Fatal("ingest", s.id[:8], seq, err)
		}
		return r
	}
	agent, ssh := agentSource("agent"), agentSource("ssh")
	ra := send(agent, "1", base, "24.04-agent")
	if ra.Disposition != "applied" || ra.AssetID == nil {
		t.Fatal("agent must create the asset", ra)
	}
	asset := *ra.AssetID
	// SSH собирает позже, тот же machine_uuid → тот же актив (C25.01)
	rs := send(ssh, "1", base.Add(10*time.Second), "24.04-ssh")
	if rs.Disposition != "applied" || rs.AssetID == nil || *rs.AssetID != asset {
		t.Fatal("ssh view must attach to the agent asset", rs)
	}
	var pa, ps int
	if err := f.pool.QueryRow(f.ctx, "SELECT max(source_priority) FILTER (WHERE source_id=$2),max(source_priority) FILTER (WHERE source_id=$3) FROM inventory.observations WHERE tenant_id=$1", tenant, agent.id, ssh.id).Scan(&pa, &ps); err != nil || pa != 3 || ps != 2 {
		t.Fatal("priority must be agent 3 > ssh 2 (binding 1 + acquisition bonus)", pa, ps, err)
	}
	// 3А: более поздний сбор SSH не перезаписывает значение агента
	var version, origin string
	if err := f.pool.QueryRow(f.ctx, "SELECT f.value#>>'{}',o.source_id::text FROM inventory.record_facts12 f JOIN inventory.observations o USING(tenant_id,observation_id) WHERE f.tenant_id=$1 AND f.asset_uid=$2 AND f.section_name='os' AND f.field_name='version'", tenant, asset).Scan(&version, &origin); err != nil || version != "24.04-agent" || origin != agent.id {
		t.Fatal("agent value must win over a later ssh value", version, origin, err)
	}
	// агент собирает снова, но раздел services у него стал «недоступен»: последняя попытка любого источника —
	// агент/unavailable, а лучший статус раздела — partial (данные SSH), обе попытки перечислены
	send(agent, "2", base.Add(20*time.Second), "24.04-agent", "services")
	state := func(section string) *contracts.RecordState12 {
		t.Helper()
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(f.ctx)
		_, st, err := inventory.Store{}.RecordState12(f.ctx, tx, tenant, asset, section)
		if err != nil || st == nil {
			t.Fatal(section, err)
		}
		return st
	}
	var latest string
	if err := f.pool.QueryRow(f.ctx, "SELECT last_status FROM inventory.record_section_state12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='services'", tenant, asset).Scan(&latest); err != nil || latest != "unavailable" {
		t.Fatal("last attempt of any source is the agent's unavailable", latest, err)
	}
	st := state("services")
	if st.Status != "partial" || st.Attempt.Origin.SourceID != ssh.id || len(st.Sources) != 2 {
		t.Fatalf("section status must be the best among sources (ssh partial): %+v", st)
	}
	for _, x := range st.Sources {
		if want := map[string]string{agent.id: "unavailable", ssh.id: "partial"}[x.SourceID]; x.Status != want {
			t.Fatalf("per-source status %s: %s, want %s", x.SourceID[:8], x.Status, want)
		}
	}
	if st := state("os"); st.Status != "partial" || len(st.Sources) != 2 {
		t.Fatalf("os: %+v", st)
	}
	// ответ API проходит контракт C15 (с новым полем sources)
	page, err := f.registry.InventoryRecordFacts(f.ctx, f.identity, asset, "services", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(page)
	if err = wire.ValidateRecordPage12(b); err != nil {
		t.Fatal("record page with per-source statuses must match the C15 contract", err)
	}
	// 2А: успешная инвентаризация 1.2 — наблюдение без «недоступных» разделов; seq 2 агента (services недоступен) — нет
	success := func(s src) *time.Time {
		t.Helper()
		var at *time.Time
		if err := f.pool.QueryRow(f.ctx, "SELECT max(last_successful_inventory_at) FROM sources.inventory_progress WHERE tenant_id=$1 AND source_id=$2", tenant, s.id).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	if at := success(agent); at == nil || !at.Equal(base) {
		t.Fatal("agent success must be its first (all collected) observation, not the one with an unavailable section", at)
	}
	if at := success(ssh); at == nil || !at.Equal(base.Add(10*time.Second)) {
		t.Fatal("ssh success", at)
	}
}
