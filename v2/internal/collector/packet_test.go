package collector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// The payload is deliberately an opaque synthetic JSON object: this tests the
// storage codec, not admission/signature authorization of an inventory batch.
func TestPacketJSONExpansionCannotBreakDurableRead(t *testing.T) {
	batch, err := wire.RecordJSON(map[string]string{"synthetic": strings.Repeat("<>&", 220000)})
	if err != nil {
		t.Fatal(err)
	}
	batch, err = wire.Canonical(batch)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(batch)
	uuid := "00000000-0000-4000-8000-000000000001"
	p := packet{Tenant: uuid, Source: uuid, ID: uuid, Digest: hex.EncodeToString(sum[:]), Batch: batch}
	old, _ := json.Marshal(p)
	if len(old) <= maxPacketBytes {
		t.Fatal("regression fixture no longer exceeds old reader bound")
	}
	body, err := marshalPacket(p)
	if err != nil || len(body) > maxPacketBytes || bytes.Contains(body, []byte(`\u003c`)) {
		t.Fatal("safe JSON expanded beyond storage bound", err)
	}
	path := filepath.Join(t.TempDir(), uuid+".pending")
	if err = atomicWrite(path, body); err != nil {
		t.Fatal(err)
	}
	restored, err := readPacket(path)
	if err != nil || restored.Digest != p.Digest || !bytes.Equal(restored.Batch, p.Batch) {
		t.Fatal("pending canonical bytes/digest lost after disk roundtrip", err)
	}
	// Existing small HTML-escaped packets remain readable and canonical-equivalent.
	p.Batch = json.RawMessage(`{"synthetic":"<old>&"}`)
	canonical, _ := wire.Canonical(p.Batch)
	sum = sha256.Sum256(canonical)
	p.Digest = hex.EncodeToString(sum[:])
	old, _ = json.Marshal(p)
	if err = atomicWrite(path, old); err != nil {
		t.Fatal(err)
	}
	restored, err = readPacket(path)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ = wire.Canonical(restored.Batch)
	if !bytes.Equal(canonical, p.Batch) {
		t.Fatal("old escaped packet changed canonical data")
	}
}

func TestPacketSerializationRejectsUnreadableSize(t *testing.T) {
	p := packet{Batch: json.RawMessage(`{"synthetic":"` + strings.Repeat("x", maxPacketBytes) + `"}`)}
	if _, err := marshalPacket(p); err == nil {
		t.Fatal("writer accepted a packet larger than the reader bound")
	}
}
