//go:build diskfault

package diskspool

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRealDiskFullPreservesCommittedFile(t *testing.T) {
	dir := os.Getenv("SURVEYSCAN_DISKFAULT_DIRECTORY")
	if dir == "" {
		t.Fatal("explicit disposable small filesystem required")
	}
	path := filepath.Join(dir, "committed")
	if e := Atomic(path, []byte("previously committed")); e != nil {
		t.Fatal(e)
	}
	e := Atomic(path, make([]byte, 262144))
	if !errors.Is(e, syscall.ENOSPC) {
		t.Fatal("expected real ENOSPC", e)
	}
	b, e := os.ReadFile(path)
	if e != nil || string(b) != "previously committed" {
		t.Fatal("partial write replaced committed state", e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 {
		t.Fatal("failed write left temporary garbage", e)
	}
}
