//go:build linux

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func lockState(directory string) (func(), error) {
	f, e := os.OpenFile(filepath.Join(directory, "agent.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("agent state already in use")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
