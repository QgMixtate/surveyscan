package telemetry

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSpoolTelemetryEmptyAndOldPending(t *testing.T) {
	dir := t.TempDir()
	expires := time.Now().Add(time.Hour)
	snapshot, e := Snapshot(dir, expires)
	if e != nil || snapshot.PendingFiles != 0 || snapshot.PendingBytes != 0 || snapshot.OldestPending != nil {
		t.Fatal("empty queue misreported", snapshot, e)
	}
	path := filepath.Join(dir, "original.pending")
	if e = os.WriteFile(path, []byte("synthetic-pending"), 0600); e != nil {
		t.Fatal(e)
	}
	old := time.Now().Add(-10 * time.Minute)
	if e = os.Chtimes(path, old, old); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "applied.receipt"), []byte("cached receipt"), 0600); e != nil {
		t.Fatal(e)
	}
	snapshot, e = Snapshot(dir, expires)
	if e != nil || snapshot.PendingFiles != 1 || snapshot.PendingBytes != 17 || snapshot.OldestPending == nil {
		t.Fatal(snapshot, e)
	}
	if snapshot.DiskAvailable != nil && *snapshot.DiskAvailable < 0 {
		t.Fatal("negative disk space")
	}
	if e = Write(dir, snapshot); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(filepath.Join(dir, "diagnostics.json"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("local diagnostics not private", e)
	}
}
