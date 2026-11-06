package wire

import (
	"bytes"
	"encoding/json"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
)

func recordPageFixture12() contracts.RecordFactPage12 {
	uuid := "00000000-0000-4000-8000-000000000001"
	evidence := contracts.FactEvidence{Observation: uuid, Origin: contracts.Origin{SourceID: uuid, SourceKind: "agent", GenerationID: uuid}, Sequence: "1", Collected: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), Clock: "trusted"}
	return contracts.RecordFactPage12{Version: contracts.Version{Major: 1, Minor: 2}, Tenant: uuid, Asset: uuid, Section: "services", Revision: "1", State: &contracts.RecordState12{Status: "partial", Attempt: evidence}, Items: []contracts.RecordFact12{{Record: strings.Repeat("a", 64), Field: "state", Value: json.RawMessage(`"running"`), Evidence: evidence}}}
}

func TestRecordPage12SchemaAndCounterexamples(t *testing.T) {
	page := recordPageFixture12()
	b, err := RecordJSON(page)
	if err != nil || ValidateRecordPage12(b) != nil {
		t.Fatal("valid page rejected", err, ValidateRecordPage12(b))
	}
	for name, mutate := range map[string]func(*contracts.RecordFactPage12){
		"unknown-field":            func(p *contracts.RecordFactPage12) { p.Items[0].Field = "credential" },
		"wrong-type":               func(p *contracts.RecordFactPage12) { p.Items[0].Value = json.RawMessage(`false`) },
		"duplicate":                func(p *contracts.RecordFactPage12) { p.Items = append(p.Items, p.Items[0]) },
		"revision-overflow":        func(p *contracts.RecordFactPage12) { p.Revision = "18446744073709551616" },
		"state-with-zero-revision": func(p *contracts.RecordFactPage12) { p.Revision = "0" },
		"empty-page-cursor": func(p *contracts.RecordFactPage12) {
			p.Items = []contracts.RecordFact12{}
			s := "abc"
			p.NextCursor = &s
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := recordPageFixture12()
			mutate(&p)
			b, err := RecordJSON(p)
			if err == nil && ValidateRecordPage12(b) == nil {
				t.Fatal("invalid page accepted")
			}
		})
	}
	page = recordPageFixture12()
	page.State = nil
	page.Revision = "0"
	page.Items = []contracts.RecordFact12{}
	b, _ = RecordJSON(page)
	if err = ValidateRecordPage12(b); err != nil {
		t.Fatal("uncollected section rejected", err)
	}
	deployed, err := contracts.C15API12Files.ReadFile("c15-records.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	draft, err := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C15/records.schema.json")
	if err != nil || string(deployed) != string(draft) {
		t.Fatal("draft/embed diverged", err)
	}
}

func TestRecordPage12CountByteBoundsAndJSONEncoding(t *testing.T) {
	page := recordPageFixture12()
	page.Section = "network"
	page.Items[0].Field = "addresses"
	// One network address list cannot fill a page. Use valid repeated typed NIC
	// fields to exercise byte overflow separately from count overflow.
	page.Items = []contracts.RecordFact12{}
	for i := 0; i < RecordPage12MaxItems+1; i++ {
		p := recordPageFixture12().Items[0]
		p.Record = strings.Repeat("a", 62) + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16])
		p.Field = "name"
		p.Value = json.RawMessage(`"<adapter>&"`)
		page.Items = append(page.Items, p)
	}
	b, _ := RecordJSON(page)
	if strings.Contains(string(b), `\u003c`) {
		t.Fatal("JSON field expanded as HTML")
	}
	if ValidateRecordPage12(b) == nil {
		t.Fatal("over-count page accepted")
	}
	page.Items = page.Items[:RecordPage12MaxItems]
	b, _ = RecordJSON(page)
	if err := ValidateRecordPage12(b); err != nil {
		t.Fatal(err)
	}
	if ValidateRecordPage12([]byte(strings.Repeat(" ", RecordPage12MaxBytes+1))) == nil {
		t.Fatal("over-byte page accepted")
	}
}

func TestRecordPage12OpenAPIComponentMatchesRuntime(t *testing.T) {
	embedded, err := contracts.C15API12Files.ReadFile("c15.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	draft, err := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C15/records.openapi.json")
	if err != nil || string(embedded) != string(draft) {
		t.Fatal("OpenAPI copies diverged", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(embedded))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	id := "urn:surveyscan:c15:openapi"
	if err = c.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	v, err := c.Compile(id + "#/components/schemas/RecordFactPage12")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := RecordJSON(recordPageFixture12())
	page, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil || v.Validate(page) != nil {
		t.Fatal("published component rejects runtime page", err, v.Validate(page))
	}
}
