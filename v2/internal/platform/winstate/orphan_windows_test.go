//go:build windows

package winstate

import (
	"os"
	"path/filepath"
	"testing"
)

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	t.Fatal("stat fixture", err)
	return false
}

func TestRecoverOrphansRemovesOnlyStagedLeftoversUnderLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	root, err := CreateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = root.RecoverOrphans(); err == nil {
		t.Fatal("recovery allowed without exclusive state lock")
	}
	unlock, err := root.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err = root.AtomicReplace("profile", []byte("keep")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".tmp-one", ".TMP-two"} {
		if err = root.CreateNew(name, []byte("partial")); err != nil {
			t.Fatal("orphan fixture", err)
		}
	}
	if err = root.CreateNew("tmp-not-orphan", []byte("other")); err != nil {
		t.Fatal(err)
	}
	removed, err := root.RecoverOrphans()
	if err != nil || removed != 2 {
		t.Fatal("orphan recovery result", removed, err)
	}
	for _, name := range []string{".tmp-one", ".TMP-two"} {
		if exists(t, filepath.Join(path, name)) {
			t.Fatal("orphan survived", name)
		}
	}
	for name, want := range map[string]string{"profile": "keep", "tmp-not-orphan": "other"} {
		data, err := root.Read(name, 64)
		if err != nil || string(data) != want {
			t.Fatal("non-orphan state altered", name, err)
		}
	}
	if removed, err = root.RecoverOrphans(); err != nil || removed != 0 {
		t.Fatal("second recovery not idempotent", removed, err)
	}
}

func TestRecoverOrphansPreservesUnsafeLeftovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	root, err := CreateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	unlock, err := root.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err = root.CreateNew("target", []byte("canary-private")); err != nil {
		t.Fatal(err)
	}
	// Hardlink-остаток: удаление могло бы затронуть внешний файл, значит отказ.
	if err = os.Link(filepath.Join(path, "target"), filepath.Join(path, ".tmp-link")); err != nil {
		t.Fatal("hardlink fixture unavailable")
	}
	if _, err = root.RecoverOrphans(); err == nil {
		t.Fatal("hardlinked orphan was accepted")
	}
	if !exists(t, filepath.Join(path, ".tmp-link")) || !exists(t, filepath.Join(path, "target")) {
		t.Fatal("unsafe orphan or its target was deleted")
	}
	// root.Read по замыслу отвергает файл с двумя ссылками, поэтому байты цели
	// проверяются обычным чтением: важно лишь, что отказ ничего не изменил.
	data, err := os.ReadFile(filepath.Join(path, "target"))
	if err != nil || string(data) != "canary-private" {
		t.Fatal("target bytes altered", err)
	}
}

func TestRecoverOrphansAfterCrashBeforeRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	root, err := CreateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := root.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if err = root.AtomicReplace("profile", []byte("old")); err != nil {
		t.Fatal(err)
	}
	// Имитация остатка упавшего процесса: стадия создана, rename не выполнен.
	if err = root.CreateNew(".tmp-crashed", []byte("new-partial")); err != nil {
		t.Fatal(err)
	}
	unlock()
	root.Close()
	reopened, err := OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	unlock, err = reopened.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	removed, err := reopened.RecoverOrphans()
	if err != nil || removed != 1 {
		t.Fatal("restart recovery", removed, err)
	}
	data, err := reopened.Read("profile", 64)
	if err != nil || string(data) != "old" {
		t.Fatal("old state not preserved", err)
	}
}
