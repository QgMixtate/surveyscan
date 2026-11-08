// Package diskspool содержит файловые примитивы однописательной durable очереди.
package diskspool

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

const AckReserve int64 = 65536
const MaxFiles = 4096

var Full = errors.New("spool capacity exhausted; pending records retained")

// Capacity вызывается под writer mutex. Удаляются только receipt без pending того же ID.
// Сохранённые pending/quarantine не вытесняются даже при полном диске.
func Capacity(directory string, limit, incoming int64) error {
	return capacity(directory, limit, incoming, MaxFiles)
}

// Data оставляет два inode слота для ACK/recovery поверх основного packet budget.
func Data(directory string, limit, incoming int64) error {
	return capacity(directory, limit, incoming, MaxFiles-2)
}
func capacity(directory string, limit, incoming int64, maxFiles int) error {
	if limit < 0 || incoming < 0 || incoming > limit {
		return Full
	}
	entries, e := os.ReadDir(directory)
	if e != nil {
		return e
	}
	type receipt struct {
		path string
		size int64
		at   time.Time
	}
	eligible := []receipt{}
	var used int64
	count := 0
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("spool symlink is not permitted")
		}
		if entry.IsDir() {
			return errors.New("unexpected spool subdirectory")
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		used += info.Size()
		count++
		if !strings.HasSuffix(entry.Name(), ".receipt") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".receipt")
		if !identifier.Valid(id) {
			continue
		}
		if _, e = os.Lstat(filepath.Join(directory, id+".pending")); e == nil {
			continue
		} else if !os.IsNotExist(e) {
			return e
		}
		eligible = append(eligible, receipt{filepath.Join(directory, entry.Name()), info.Size(), info.ModTime()})
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].at.Before(eligible[j].at) })
	changed := false
	for _, r := range eligible {
		if used+incoming <= limit && count+1 <= maxFiles && time.Since(r.at) <= 7*24*time.Hour {
			continue
		}
		if e = os.Remove(r.path); e != nil {
			return e
		}
		used -= r.size
		count--
		changed = true
	}
	if changed {
		if e = SyncDir(directory); e != nil {
			return e
		}
	}
	if used+incoming > limit || count+1 > maxFiles {
		return Full
	}
	return nil
}
