//go:build linux

package telemetry

import "syscall"

func DiskAvailable(path string) *int64 {
	var stats syscall.Statfs_t
	if syscall.Statfs(path, &stats) != nil {
		return nil
	}
	value := uint64(stats.Bavail) * uint64(stats.Bsize)
	if value > 9007199254740991 {
		value = 9007199254740991
	}
	n := int64(value)
	return &n
}
