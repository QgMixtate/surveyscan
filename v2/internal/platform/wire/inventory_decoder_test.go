package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestInventoryDecoderOptInAndUnchangedReceiptContract(t *testing.T) {
	legacy, err := New()
	if err != nil {
		t.Fatal(err)
	}
	off, err := NewInventoryDecoder(legacy, false)
	if err != nil {
		t.Fatal(err)
	}
	on, err := NewInventoryDecoder(legacy, true)
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C03/fixtures/C03-F01.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []*InventoryDecoder{off, on} {
		if _, _, _, err = d.Observation(old); err != nil {
			t.Fatal("legacy compatibility lost", err)
		}
	}
	o, key, trust := signedFixture12(t)
	full, _ := signFixture12(t, o, key, trust.KeyID)
	if _, _, _, err = on.Observation(full); err == nil {
		t.Fatal("runtime accepted unimplemented complete12")
	}
	for i := range o.Sections {
		o.Sections[i].Status = "partial"
		o.Sections[i].Complete = false
	}
	signed, _ := signFixture12(t, o, key, trust.KeyID)
	if _, _, _, err = off.Observation(signed); err == nil {
		t.Fatal("default enabled12")
	}
	if _, _, _, err = on.Observation(signed); err != nil {
		t.Fatal(err)
	}
	batch := contracts.Batch{Version: contracts.Version{Major: 1, Minor: 2}, TenantID: o.TenantID, DeliveryID: "00000000-0000-4000-8000-000000000066", Records: []json.RawMessage{signed}}
	batchRaw, _ := RecordJSON(batch)
	canonical, _ := Canonical(batchRaw)
	batchHash := sha256.Sum256(canonical)
	var envelope contracts.SignedObservation
	if err = json.Unmarshal(signed, &envelope); err != nil {
		t.Fatal(err)
	}
	asset := "00000000-0000-4000-8000-000000000077"
	payload := contracts.CenterResult{Version: contracts.Version{Major: 1}, ReceiptID: asset, TenantID: o.TenantID, DeliveryID: batch.DeliveryID, BatchDigest: hex.EncodeToString(batchHash[:]), CommittedAt: time.Now().UTC(), Revision: "1", Status: "completed", Results: []contracts.RecordResult{{SourceID: o.Origin.SourceID, ObservationID: o.ID, Digest: envelope.Digest, Disposition: "applied", AssetID: &asset, Reason: "SOURCE_MAPPING", SpoolAction: "remove"}}}
	public, center, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := RecordJSON(payload)
	canonical, _ = Canonical(body)
	hash := sha256.Sum256(canonical)
	receipt := contracts.SignedCenterResult{Payload: payload, Digest: hex.EncodeToString(hash[:]), KeyID: trust.KeyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(center, append([]byte("SURVEYSCAN-CENTER-RESULT-V1\n"), canonical...)))}
	raw, _ := RecordJSON(receipt)
	if _, remove, err := on.VerifyCenterResult(raw, batchRaw, trust.KeyID, public); err != nil || !remove {
		t.Fatal("receipt1.0 did not bind to batch1.2", err)
	}
	if _, _, err := legacy.VerifyCenterResult(raw, batchRaw, trust.KeyID, public); err == nil {
		t.Fatal("legacy receipt verifier silently accepted a new batch")
	}
	batch.DeliveryID = asset
	other, _ := RecordJSON(batch)
	if _, _, err := on.VerifyCenterResult(raw, other, trust.KeyID, public); err == nil {
		t.Fatal("receipt crossed delivery binding")
	}
}

func TestInventory12OpenAPIPartialBatchMatchesRuntime(t *testing.T) {
	raw, err := contracts.C15API12Files.ReadFile("c15.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	id := "urn:surveyscan:c15:openapi-upload"
	if err = c.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile(id + "#/components/schemas/InventoryBatch12")
	if err != nil {
		t.Fatal(err)
	}
	o, key, trust := signedFixture12(t)
	for i := range o.Sections {
		o.Sections[i].Status = "partial"
		o.Sections[i].Complete = false
	}
	validate := func(o contracts.Observation) error {
		signed, _ := signFixture12(t, o, key, trust.KeyID)
		batch := contracts.Batch{Version: contracts.Version{Major: 1, Minor: 2}, TenantID: o.TenantID, DeliveryID: trust.KeyID, Records: []json.RawMessage{signed}}
		b, _ := RecordJSON(batch)
		p, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return err
		}
		return schema.Validate(p)
	}
	if err = validate(o); err != nil {
		t.Fatal("published request rejects runtime partial12", err)
	}
	o.Sections[0].Status = "ok"
	o.Sections[0].Complete = true
	if validate(o) == nil {
		t.Fatal("published API advertises unsupported complete12")
	}
}
