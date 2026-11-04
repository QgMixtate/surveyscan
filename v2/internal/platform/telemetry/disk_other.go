//go:build !linux

package telemetry

func DiskAvailable(string) *int64 { return nil }
