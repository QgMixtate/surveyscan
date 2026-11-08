//go:build !windows

package diskspool

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

func TestQuotaNeverEvictsPendingOrQuarantine(t *testing.T) {
	dir := t.TempDir()
	id := identifier.New()
	pending := filepath.Join(dir, id+".pending")
	receipt := filepath.Join(dir, id+".receipt")
	if e := Atomic(pending, make([]byte, 900)); e != nil {
		t.Fatal(e)
	}
	if e := Atomic(receipt, make([]byte, 90)); e != nil {
		t.Fatal(e)
	}
	if e := Capacity(dir, 1000, 20); !errors.Is(e, Full) {
		t.Fatal("over-quota admission", e)
	}
	for _, path := range []string{pending, receipt} {
		if _, e := os.Stat(path); e != nil {
			t.Fatal("quarantine evicted", e)
		}
	}
	if e := os.Remove(pending); e != nil {
		t.Fatal(e)
	}
	if e := Capacity(dir, 1000, 950); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(receipt); !os.IsNotExist(e) {
		t.Fatal("committed receipt failed to reclaim capacity")
	}
}
func TestRecoverOnlyTemporaryFilesAndExpireCommittedReceipts(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, identifier.New()+".pending")
	receipt := filepath.Join(dir, identifier.New()+".receipt")
	for _, path := range []string{pending, receipt, filepath.Join(dir, ".spool-orphan"), filepath.Join(dir, ".agent-orphan")} {
		if e := os.WriteFile(path, []byte("durable"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := RecoverTemps(dir); e != nil {
		t.Fatal(e)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatal("recovery deleted committed data or left incomplete temp")
	}
	old := time.Now().Add(-8 * 24 * time.Hour)
	if e := os.Chtimes(receipt, old, old); e != nil {
		t.Fatal(e)
	}
	if e := Capacity(dir, 1000, 1); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(pending); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(receipt); !os.IsNotExist(e) {
		t.Fatal("expired receipt retained")
	}
}

func TestFileAdmissionLeavesAcknowledgementCapacity(t *testing.T) {
	dir := t.TempDir()
	ids := []string{identifier.New(), identifier.New(), identifier.New()}
	for _, id := range ids {
		if e := Atomic(filepath.Join(dir, id+".pending"), []byte("pending")); e != nil {
			t.Fatal(e)
		}
	}
	// Малый inode budget моделирует тот же reserve, что production4094/4096.
	if e := capacity(dir, 1000, 10, 3); !errors.Is(e, Full) {
		t.Fatal("new packet bypassed inode backpressure", e)
	}
	if e := capacity(dir, 1000, 10, 5); e != nil {
		t.Fatal("ACK cannot make progress at data inode limit", e)
	}
	if e := Atomic(filepath.Join(dir, ids[0]+".receipt"), []byte("ack")); e != nil {
		t.Fatal(e)
	}
	for _, id := range ids {
		if _, e := os.Stat(filepath.Join(dir, id+".pending")); e != nil {
			t.Fatal("pending evicted to fit ACK", e)
		}
	}
}
