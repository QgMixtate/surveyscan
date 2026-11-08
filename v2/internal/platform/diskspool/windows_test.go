//go:build windows

package diskspool

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
)

func TestWindowsLockAtomicRecoverAndPrivateRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	file := filepath.Join(dir, "state.json")
	if Atomic(file, []byte("x")) == nil {
		t.Fatal("atomic write allowed without writer lock")
	}
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal("lock", err)
	}
	if _, err = Lock(dir); err == nil {
		t.Fatal("second writer accepted in the same process")
	}
	if err = Atomic(file, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err = Atomic(file, []byte("two")); err != nil {
		t.Fatal("replace", err)
	}
	if err = SyncDir(dir); err != nil {
		t.Fatal(err)
	}
	data, err := privatefile.Read(file, 64)
	if err != nil || string(data) != "two" {
		t.Fatal("private read", err)
	}
	// Удаление остатков проверено в winstate; здесь — допустимость вызова под блокировкой.
	if err = RecoverTemps(dir); err != nil {
		t.Fatal("recover", err)
	}
	unlock()
	if Atomic(file, []byte("three")) == nil {
		t.Fatal("atomic write allowed after unlock")
	}
	again, err := Lock(dir)
	if err != nil {
		t.Fatal("relock after unlock", err)
	}
	again()
	data, err = privatefile.Read(file, 64)
	if err != nil || string(data) != "two" {
		t.Fatal("state changed across lock cycle", err)
	}
}

func TestWindowsPrivateReadRejectsOrdinaryDirectory(t *testing.T) {
	// MkdirAll даёт унаследованный ACL: приватное чтение отказывает, а не молча читает.
	dir := filepath.Join(t.TempDir(), "plain")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "k")
	if err := os.WriteFile(file, []byte("canary-private"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := privatefile.Read(file, 64); err == nil {
		t.Fatal("file from a non-private directory accepted")
	}
	if _, err := Lock(dir); err == nil {
		t.Fatal("non-private directory adopted as spool")
	}
}
