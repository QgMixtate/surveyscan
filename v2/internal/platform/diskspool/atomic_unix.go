//go:build !windows

package diskspool

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func SyncDir(directory string) error {
	f, e := os.Open(directory)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func Atomic(path string, raw []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".spool-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(raw); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	return SyncDir(filepath.Dir(path))
}

// RecoverTemps допустим только при эксклюзивной process lock: после crash ни один writer не жив.
func RecoverTemps(directory string) error {
	entries, e := os.ReadDir(directory)
	if e != nil {
		return e
	}
	changed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".spool-") && !strings.HasPrefix(entry.Name(), ".agent-") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return errors.New("invalid spool temporary entry")
		}
		if e = os.Remove(filepath.Join(directory, entry.Name())); e != nil {
			return e
		}
		changed = true
	}
	if changed {
		return SyncDir(directory)
	}
	return nil
}

// Remove удаляет файл и сбрасывает каталог, как это делал Linux-код доставки.
func Remove(path string) error {
	if e := os.Remove(path); e != nil {
		return e
	}
	return SyncDir(filepath.Dir(path))
}
