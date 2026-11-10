package portable

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

func fixtureObs(t *testing.T, id, collected string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../../docs/plans/surveyscan-v2/contracts/C15/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx []struct {
		ID      string
		Payload map[string]any
	}
	if err = json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	for _, f := range fx {
		if f.ID == "all-sections" {
			f.Payload["observation_id"] = id
			f.Payload["origin"].(map[string]any)["source_kind"] = "portable"
			if collected != "" {
				f.Payload["collected_at"] = collected
				for _, sec := range f.Payload["sections"].([]any) {
					sec.(map[string]any)["collected_at"] = collected // секции не могут быть новее наблюдения
				}
			}
			out, _ := json.Marshal(f.Payload)
			return out
		}
	}
	t.Fatal("fixture missing")
	return nil
}

func tenantSource(t *testing.T, raw []byte) (string, string) {
	var h struct {
		Tenant string `json:"tenant_id"`
		Origin struct {
			Source string `json:"source_id"`
		} `json:"origin"`
	}
	_ = json.Unmarshal(raw, &h)
	return h.Tenant, h.Origin.Source
}

const (
	id1 = "11111111-1111-4111-8111-111111111111"
	id2 = "22222222-2222-4222-8222-222222222222"
)

func build(t *testing.T, priv ed25519.PrivateKey, obs ...[]byte) []byte {
	tenant, source := tenantSource(t, obs[0])
	signed := [][]byte{}
	for _, o := range obs {
		so, err := SignObservation(priv, o)
		if err != nil {
			t.Fatal(err)
		}
		signed = append(signed, so)
	}
	var buf bytes.Buffer
	if err := Write(&buf, priv, tenant, source, time.Now(), signed); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func keys() (ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return priv, map[string]ed25519.PublicKey{KeyID(pub): pub}
}

func TestRoundTripDedupAndLateObservation(t *testing.T) {
	priv, trust := keys()
	v, _ := wire.NewInventory12()
	late := fixtureObs(t, id2, "2026-01-01T00:00:00Z") // старое наблюдение, пришедшее поздно
	pkg := build(t, priv, fixtureObs(t, id1, ""), late)
	known := Known{}
	res, err := Import(pkg, trust, known, DefaultLimits(), v)
	if err != nil || len(res.Accepted) != 2 || len(res.Quarantined) != 0 {
		t.Fatal(err, res.Quarantined)
	}
	res, err = Import(pkg, trust, known, DefaultLimits(), v) // повторная загрузка того же пакета
	if err != nil || len(res.Accepted) != 0 || len(res.Duplicates) != 2 {
		t.Fatal("repeat import must dedup:", err, res)
	}
	// тот же ID, другое содержимое → карантин, а не молчаливая замена
	other := build(t, priv, fixtureObs(t, id1, "2026-02-02T00:00:00Z"))
	res, _ = Import(other, trust, known, DefaultLimits(), v)
	if len(res.Accepted) != 0 || len(res.Quarantined) != 1 || res.Quarantined[0].Reason != "SAME_ID_DIFFERENT_DIGEST" {
		t.Fatal(res)
	}
}

func TestSignatureAndTrust(t *testing.T) {
	priv, trust := keys()
	pkg := build(t, priv, fixtureObs(t, id1, ""))
	_, otherTrust := keys()
	if _, err := Import(pkg, otherTrust, Known{}, DefaultLimits(), nil); !errors.Is(err, ErrSignature) {
		t.Fatal("untrusted key must be refused:", err)
	}
	// подмена manifest при сохранённой подписи
	rewritten := rewrite(t, pkg, func(name string, b []byte) []byte {
		if name == "manifest.json" {
			return []byte(strings.Replace(string(b), `"source_id"`, `"source_id" `, 1))
		}
		return b
	}, nil)
	if _, err := Import(rewritten, trust, Known{}, DefaultLimits(), nil); !errors.Is(err, ErrSignature) {
		t.Fatal("tampered manifest must break the signature:", err)
	}
}

func TestTamperedObservationGoesToQuarantine(t *testing.T) {
	priv, trust := keys()
	pkg := build(t, priv, fixtureObs(t, id1, ""), fixtureObs(t, id2, ""))
	rewritten := rewrite(t, pkg, func(name string, b []byte) []byte {
		if name == "obs/"+id1+".json" {
			return append([]byte(nil), []byte(strings.Replace(string(b), "portable", "portablX", 1))...)
		}
		return b
	}, nil)
	res, err := Import(rewritten, trust, Known{}, DefaultLimits(), nil)
	if err != nil || len(res.Accepted) != 1 || len(res.Quarantined) != 1 || res.Quarantined[0].Reason != "DIGEST_MISMATCH" {
		t.Fatal(err, res)
	}
}

func rewrite(t *testing.T, pkg []byte, edit func(string, []byte) []byte, extra map[string][]byte) []byte {
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range zr.File {
		rc, _ := f.Open()
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(rc)
		rc.Close()
		w, _ := zw.Create(f.Name)
		_, _ = w.Write(edit(f.Name, b.Bytes()))
	}
	for name, b := range extra {
		w, _ := zw.Create(name)
		_, _ = w.Write(b)
	}
	_ = zw.Close()
	return out.Bytes()
}

func TestHostileArchivesAreRejected(t *testing.T) {
	priv, trust := keys()
	pkg := build(t, priv, fixtureObs(t, id1, ""))
	for _, name := range []string{"../evil.json", "obs/../../evil.json", "/etc/passwd", "obs\\x.json", "obs/not-a-uuid.json", "extra.txt"} {
		bad := rewrite(t, pkg, func(_ string, b []byte) []byte { return b }, map[string][]byte{name: []byte("x")})
		if _, err := Import(bad, trust, Known{}, DefaultLimits(), nil); !errors.Is(err, ErrFormat) {
			t.Errorf("entry %q must be rejected: %v", name, err)
		}
	}
	// файл, распакованный в разы больше разрешённого коэффициента сжатия (zip-бомба)
	bomb := rewrite(t, pkg, func(_ string, b []byte) []byte { return b }, map[string][]byte{"obs/33333333-3333-4333-8333-333333333333.json": bytes.Repeat([]byte("0"), 3<<20)})
	lim := DefaultLimits()
	if _, err := Import(bomb, trust, Known{}, lim, nil); !errors.Is(err, ErrLimits) {
		t.Fatal("compression bomb must hit limits:", err)
	}
	lim = DefaultLimits()
	lim.MaxFiles = 2
	if _, err := Import(pkg, trust, Known{}, lim, nil); !errors.Is(err, ErrLimits) {
		t.Fatal("file count limit:", err)
	}
	if _, err := Import([]byte("not a zip"), trust, Known{}, DefaultLimits(), nil); !errors.Is(err, ErrFormat) {
		t.Fatal(err)
	}
}

func TestSchemaInvalidObservationIsQuarantinedAndNoSecretsInPackage(t *testing.T) {
	priv, trust := keys()
	v, _ := wire.NewInventory12()
	raw := fixtureObs(t, id1, "")
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["unexpected_field"] = "x"
	broken, _ := json.Marshal(m)
	pkg := build(t, priv, broken)
	res, err := Import(pkg, trust, Known{}, DefaultLimits(), v)
	if err != nil || len(res.Accepted) != 0 || len(res.Quarantined) != 1 || res.Quarantined[0].Reason != "SCHEMA_INVALID" {
		t.Fatal(err, res)
	}
	// закрытый ключ подписи и маркеры секретов в пакет не попадают
	good := build(t, priv, fixtureObs(t, id1, ""))
	if bytes.Contains(good, priv.Seed()) || bytes.Contains(good, []byte("password")) {
		t.Fatal("package must not contain key material or password fields")
	}
}

func TestRecordSignedByOtherKeyIsRejected(t *testing.T) {
	priv, trust := keys()
	other, _ := keys()
	so, err := SignObservation(other, fixtureObs(t, id1, ""))
	if err != nil {
		t.Fatal(err)
	}
	tenant, source := tenantSource(t, fixtureObs(t, id1, ""))
	var buf bytes.Buffer
	if err = Write(&buf, priv, tenant, source, time.Now(), [][]byte{so}); !errors.Is(err, ErrFormat) {
		t.Fatal("writer must refuse records signed by a foreign key:", err)
	}
	_ = trust
}

func TestKeyIDIsUUID(t *testing.T) {
	_, trust := keys()
	for k := range trust {
		if !idPattern.MatchString(k) {
			t.Fatal("key id must be a UUID (centre ingest binding key_id):", k)
		}
	}
}
