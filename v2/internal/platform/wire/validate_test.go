package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func TestC03SignatureInteroperability(t *testing.T) {
	v, e := New()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C03/fixtures/C03-F01.json")
	if e != nil {
		t.Fatal(e)
	}
	signed, _, canonical, e := v.Observation(raw)
	if e != nil {
		t.Fatal(e)
	}
	key, e := base64.RawURLEncoding.DecodeString("9fg5C6onZ-7KZ7GjSYqQEk1acloPpdl47utgpDOr5GQ")
	if e != nil {
		t.Fatal(e)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	if !ed25519.Verify(key, append([]byte("SURVEYSCAN-OBSERVATION-V1\n"), canonical...), sig) {
		t.Fatal("Go JCS/signature differs from C03 reference")
	}
}
func TestStrictSchemaAndDuplicateJSON(t *testing.T) {
	v, e := New()
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{`{"display_name":"a","display_name":"b"}`, `{}`, `{"tenant_id":"00000000-0000-4000-8000-000000000001"}`, `{"purpose":null}`, `{"purpose":"\u0000"}`} {
		if e = v.Validate("BusinessPatch", []byte(raw)); e == nil {
			t.Error("accepted", raw)
		}
	}
	b, _ := json.Marshal(map[string]any{"purpose": ""})
	if e = v.Validate("BusinessPatch", b); e != nil {
		t.Fatal(e)
	}
}

func TestObservationSemanticBounds(t *testing.T) {
	v, e := New()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C03/fixtures/C03-F01.json")
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(map[string]any){
		func(p map[string]any) { p["source_sequence"] = "18446744073709551616" },
		func(p map[string]any) { p["sections"].([]any)[0].(map[string]any)["status"] = "unknown" },
		func(p map[string]any) {
			p["sections"].([]any)[0].(map[string]any)["collected_at"] = "2099-01-01T00:00:00Z"
		},
	} {
		var envelope map[string]any
		_ = json.Unmarshal(raw, &envelope)
		mutate(envelope["payload"].(map[string]any))
		changed, _ := json.Marshal(envelope)
		if _, _, _, e = v.Observation(changed); e == nil {
			t.Fatal("accepted semantic violation")
		}
	}
}
