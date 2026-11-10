package portableaudit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/agent"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/QgMixtate/surveyscan/v2/internal/portable"
)

func setup(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	_, pub, err := Init(dir, identifier.New(), identifier.New(), identifier.New())
	if err != nil {
		t.Fatal(err)
	}
	return dir, pub
}

func hostTarget(t *testing.T) Target {
	if runtime.GOOS != "linux" {
		t.Skip("живой сбор хоста в тесте — только Linux")
	}
	return Target{Kind: "host", Name: "host", Collect: agent.CollectHost12}
}

func TestInitLoadAndNoOverwrite(t *testing.T) {
	dir, pub := setup(t)
	id, key, err := Load(dir)
	if err != nil || !bytes.Equal(key.Public().(ed25519.PublicKey), pub) || id.KeyID != portable.KeyID(pub) {
		t.Fatal(err)
	}
	if _, _, err = Init(dir, identifier.New(), identifier.New(), identifier.New()); !errors.Is(err, ErrExists) {
		t.Fatal("existing identity must not be replaced:", err)
	}
	if err = os.Chmod(filepath.Join(dir, "signing.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = Load(dir); err == nil {
		t.Fatal("world-readable signing key must be refused")
	}
	if _, _, err = Init(filepath.Join(t.TempDir(), "x"), "bad", identifier.New(), identifier.New()); err == nil {
		t.Fatal("non-UUID tenant must be refused")
	}
}

func TestRunExportsVerifiablePackageAndIsolatesFailures(t *testing.T) {
	dir, pub := setup(t)
	failing := Target{Kind: "ssh", Name: "10.0.0.9:22", Collect: func(context.Context) (agent.Snapshot, error) {
		return agent.Snapshot{}, errors.New("ssh: authentication failed")
	}}
	out := filepath.Join(t.TempDir(), "audit.ssp")
	var lines []string
	rep, err := Run(context.Background(), dir, []Target{hostTarget(t), failing}, out, func(s string) { lines = append(lines, s) })
	if err != nil {
		t.Fatal(err)
	}
	if rep.Exported != 1 || len(rep.Results) != 2 || rep.Results[1].Err == "" || len(lines) < 4 {
		t.Fatalf("one target ok, one failed: %+v / %v", rep, lines)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := wire.NewInventory12()
	res, err := portable.Import(data, map[string]ed25519.PublicKey{portable.KeyID(pub): pub}, portable.Known{}, portable.DefaultLimits(), v)
	if err != nil || len(res.Accepted) != 1 || len(res.Quarantined) != 0 {
		t.Fatal("package must import cleanly:", err, res.Quarantined)
	}
	var so struct {
		Payload json.RawMessage `json:"payload"`
	}
	_ = json.Unmarshal(res.Accepted[0], &so)
	var o struct {
		Origin struct {
			Kind string `json:"source_kind"`
		} `json:"origin"`
		Record struct {
			Namespace string `json:"namespace"`
		} `json:"source_record"`
		Clock string `json:"clock_quality"`
		Seq   string `json:"source_sequence"`
	}
	_ = json.Unmarshal(so.Payload, &o)
	if o.Origin.Kind != "portable" || o.Clock != "estimated" || o.Seq != "1" || o.Record.Namespace != "host" {
		t.Fatalf("%+v", o)
	}
	key, _ := os.ReadFile(filepath.Join(dir, "signing.key"))
	if bytes.Contains(data, bytes.TrimSpace(key)) {
		t.Fatal("signing key must never be in the package")
	}
	if _, err = os.Stat(out + ".partial"); !os.IsNotExist(err) {
		t.Fatal("no partial file may remain")
	}
	// пакеты не перезаписываются
	if _, err = Run(context.Background(), dir, []Target{hostTarget(t)}, out, nil); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatal("existing package must not be overwritten:", err)
	}
}

func TestDryRunAndSequenceAndCancel(t *testing.T) {
	dir, _ := setup(t)
	rep, err := Run(context.Background(), dir, []Target{hostTarget(t)}, "", nil)
	if err != nil || rep.Exported != 0 || len(rep.Observation) != 1 {
		t.Fatal("dry run builds and validates but does not export", err, rep)
	}
	out := filepath.Join(t.TempDir(), "a.ssp")
	if _, err = Run(context.Background(), dir, []Target{hostTarget(t)}, out, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "sequence"))
	if strings.TrimSpace(string(raw)) != "2" {
		t.Fatal("sequence must be monotonic across runs (dry run consumed 1):", string(raw))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out2 := filepath.Join(t.TempDir(), "b.ssp")
	if _, err = Run(ctx, dir, []Target{hostTarget(t)}, out2, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = os.Stat(out2); !os.IsNotExist(err) {
		t.Fatal("cancelled run must not leave a package")
	}
}

func TestInvalidObservationIsNotExported(t *testing.T) {
	dir, _ := setup(t)
	bad := Target{Kind: "ssh", Name: "x", Collect: func(context.Context) (agent.Snapshot, error) {
		return agent.Snapshot{}, nil // нет 12 секций — схема 1.2 отвергает
	}}
	out := filepath.Join(t.TempDir(), "c.ssp")
	rep, err := Run(context.Background(), dir, []Target{bad}, out, nil)
	if err != nil || rep.Exported != 0 || rep.Results[0].Err == "" {
		t.Fatal(err, rep)
	}
	if _, err = os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("nothing valid — no package")
	}
}
