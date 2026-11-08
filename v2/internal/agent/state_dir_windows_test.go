//go:build windows

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsStateDirIsPrivateAndLocked(t *testing.T) {
	state := filepath.Join(t.TempDir(), "nested", "state")
	if err := ensureStateDir(state); err != nil {
		t.Fatal("create private state", err)
	}
	if err := ensureStateDir(state); err != nil {
		t.Fatal("existing private state must be accepted", err)
	}
	if err := ensureStateDir(filepath.Join(state, "spool")); err != nil {
		t.Fatal("private spool inside state", err)
	}
	unlock, err := lockState(state)
	if err != nil {
		t.Fatal("state lock", err)
	}
	if _, err = lockState(state); err == nil {
		t.Fatal("second state writer accepted")
	}
	unlock()
	plain := filepath.Join(t.TempDir(), "plain")
	if err = os.MkdirAll(plain, 0700); err != nil {
		t.Fatal(err)
	}
	if ensureStateDir(plain) == nil {
		t.Fatal("directory with an inherited ACL accepted as private state")
	}
}
