//go:build integration

package app_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Схема сети L3 строится из фактов 1.2 нескольких источников: подсеть, шлюз-актив, внешний шлюз.
func TestTopologyFromInventory12(t *testing.T) {
	f := registrySetup(t)
	if _, err := f.registry.ConfigureInventoryProtocol12(true); err != nil {
		t.Fatal(err)
	}
	machine := &sources.MachineService{Pool: f.pool, Audit: audit.Store{}}
	host := func(name string, network []map[string]any, routes []map[string]any) string {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		source, generation := identifier.New(), identifier.New()
		if _, err := machine.RegisterPortable(f.ctx, "console", sources.PortableRegistration{Tenant: tenant, Site: siteID, Scope: scopeID, Source: source, Generation: generation, PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
		o := testObservation12(t, f, "1")
		o.Origin = contracts.Origin{SourceID: source, SourceKind: "portable", GenerationID: generation}
		o.Record = contracts.SourceRecord{Namespace: "host", LocalID: "host:" + name}
		o.Clock = "estimated"
		o.Candidates = []contracts.Candidate{{Kind: "hostname", Namespace: "hostname.raw", Value: name + "-" + identifier.New()[:6]}}
		for i := range o.Sections {
			switch o.Sections[i].Name {
			case "identity":
				o.Sections[i].Records = []map[string]any{{"hostname": name}}
			case "network":
				o.Sections[i].Records = network
			case "routes_ports":
				o.Sections[i].Records = routes
			}
			o.Sections[i].Count = len(o.Sections[i].Records)
		}
		raw, _ := json.Marshal(o)
		report, err := f.registry.ImportPortable(f.ctx, machine, tenant, source, portablePackage(t, key, source, raw))
		if err != nil || len(report.Records) != 1 || report.Records[0].Disposition != "applied" {
			t.Fatal("import", name, err, report)
		}
		return report.Records[0].AssetID
	}
	router := host("router", []map[string]any{{"name": "lan", "mac": "02:00:00:00:00:01", "addresses": []map[string]any{{"ip": "10.20.0.1", "prefix": 24}}}, {"name": "wan", "addresses": []map[string]any{{"ip": "198.51.100.2", "prefix": 30}}}},
		[]map[string]any{{"kind": "route", "family": "ipv4", "destination": "0.0.0.0/0", "gateway": "198.51.100.1", "interface": "wan"}})
	app := host("app", []map[string]any{{"name": "eth0", "addresses": []map[string]any{{"ip": "10.20.0.15", "prefix": 24}, {"ip": "127.0.0.1", "prefix": 8}}}},
		[]map[string]any{{"kind": "route", "family": "ipv4", "destination": "0.0.0.0/0", "gateway": "10.20.0.1", "interface": "eth0"}})

	topo, err := f.registry.Topology(f.ctx, f.identity)
	if err != nil {
		t.Fatal(err)
	}
	// ответ соответствует контракту contracts/c22-topology.schema.json (его же проверяет браузер)
	raw, _ := json.Marshal(topo)
	schemaRaw, err := os.ReadFile("../../contracts/c22-topology.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err = compiler.AddResource("urn:surveyscan:c22:topology:1:0", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:surveyscan:c22:topology:1:0")
	if err != nil {
		t.Fatal(err)
	}
	instance, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err = schema.Validate(instance); err != nil {
		t.Fatal("topology response violates its contract:", err)
	}
	nodes := map[string]bool{}
	routerFlag := false
	for _, n := range topo.Nodes {
		nodes[n.ID] = true
		if n.ID == "host:"+router && n.Router && n.Label == "router" && n.Asset == router && n.Device == "server" {
			routerFlag = true
		}
	}
	for _, id := range []string{"host:" + router, "host:" + app, "subnet:10.20.0.0/24", "subnet:198.51.100.0/30", "gw:198.51.100.1"} {
		if !nodes[id] {
			t.Fatalf("missing %s in %+v", id, topo.Nodes)
		}
	}
	if nodes["subnet:127.0.0.0/8"] || !routerFlag || topo.Hosts != 2 || topo.Truncated {
		t.Fatalf("unexpected topology %+v", topo)
	}
	gateway := false
	for _, l := range topo.Links {
		if l.A == "subnet:10.20.0.0/24" && l.B == "host:"+router && l.Role == "gateway" && l.Level == "probable" {
			gateway = true
		}
		if len(l.Evidence) == 0 {
			t.Fatal("every link must carry evidence", l)
		}
	}
	if !gateway {
		t.Fatalf("app default route must make router the gateway of 10.20.0.0/24: %+v", topo.Links)
	}
}

// C22.04: ручной слой схемы — общий документ с ревизией, строгой проверкой и аудитом; ответ по контракту.
func TestNetworkMapEditing(t *testing.T) {
	f := registrySetup(t)
	empty, err := f.registry.NetworkMap(f.ctx, f.identity)
	if err != nil || empty.Revision != "0" || empty.UpdatedAt != nil || len(empty.Document.Devices) != 0 {
		t.Fatal("empty map", empty, err)
	}
	doc := `{"positions":{"host:` + identifier.New() + `":{"x":10,"y":-20},"subnet:10.0.0.0/24":{"x":0,"y":0}},
"devices":[{"id":"m:sw1","type":"switch","label":"Коммутатор ядра","address":"10.0.0.2","at":{"x":100,"y":50}},{"id":"m:hv1","type":"hypervisor","label":"hv-01","at":{"x":300,"y":50}}],
"links":[{"id":"m:l1","a":"m:sw1","b":"subnet:10.0.0.0/24","kind":"copper","port_a":"Gi0/1"},{"id":"m:l2","a":"m:sw1","b":"m:hv1","kind":"fiber","label":"10G"}],
"groups":[{"id":"m:g1","label":"Серверная","color":"blue","at":{"x":-50,"y":-50},"width":600,"height":400}],
"notes":[{"id":"m:n1","text":"Стойка 1","at":{"x":0,"y":420}}],
"overrides":{"gw:10.0.0.1":{"type":"firewall","label":"FW"}}}`
	saved, err := f.registry.SaveNetworkMap(f.ctx, f.identity, app.NetworkMapPut{Revision: "0", Document: json.RawMessage(doc)})
	if err != nil || saved.Revision != "1" || saved.UpdatedBy == nil || len(saved.Document.Devices) != 2 || saved.Document.Overrides["gw:10.0.0.1"].Type != "firewall" {
		t.Fatal("save", saved, err)
	}
	schemaRaw, err := os.ReadFile("../../contracts/c22-network-map.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	sdoc, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaRaw)))
	if err = compiler.AddResource("urn:surveyscan:c22:network-map:1:0", sdoc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("urn:surveyscan:c22:network-map:1:0")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(saved)
	instance, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err = schema.Validate(instance); err != nil {
		t.Fatal("network map violates its contract:", err)
	}
	// устаревшая ревизия — 412, ничего не меняется
	if _, err = f.registry.SaveNetworkMap(f.ctx, f.identity, app.NetworkMapPut{Revision: "0", Document: json.RawMessage(doc)}); !errors.Is(err, domain.Revision) {
		t.Fatal("stale revision must be refused", err)
	}
	for _, bad := range []string{
		strings.Replace(doc, `"b":"m:hv1"`, `"b":"m:missing"`, 1), // связь на несуществующее ручное устройство
		strings.Replace(doc, `"type":"switch"`, `"type":"toaster"`, 1),
		strings.Replace(doc, `"width":600`, `"width":5`, 1),
		strings.Replace(doc, `"positions":{`, `"positions":{"evil":{"x":1,"y":1},`, 1),
		strings.Replace(doc, `"notes":`, `"extra":1,"notes":`, 1),
		strings.Replace(doc, `"id":"m:n1"`, `"id":"m:sw1"`, 1), // повтор идентификатора
	} {
		if _, err = f.registry.SaveNetworkMap(f.ctx, f.identity, app.NetworkMapPut{Revision: "1", Document: json.RawMessage(bad)}); !errors.Is(err, domain.Invalid) {
			t.Fatal("invalid document accepted", err, bad[:80])
		}
	}
	next, err := f.registry.SaveNetworkMap(f.ctx, f.identity, app.NetworkMapPut{Revision: "1", Document: json.RawMessage(`{"positions":{},"devices":[],"links":[],"groups":[],"notes":[],"overrides":{}}`)})
	if err != nil || next.Revision != "2" || len(next.Document.Devices) != 0 {
		t.Fatal("second save", next, err)
	}
	var audits int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit.audit_events WHERE tenant_id=$1 AND action='topology.map_saved'", tenant).Scan(&audits); err != nil || audits != 2 {
		t.Fatal("audit", audits, err)
	}
}
