//go:build linux

package diskspool

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func Lock(directory string) (func(), error) {
	f, e := os.OpenFile(filepath.Join(directory, "writer.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("spool already has an active writer")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
