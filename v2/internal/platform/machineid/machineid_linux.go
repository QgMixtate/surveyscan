//go:build linux

package machineid

import "os"

// Local читает /etc/machine-id.
func Local() (string, error) {
	raw, e := os.ReadFile("/etc/machine-id")
	if e != nil || len(raw) > 128 {
		return "", ErrUnavailable
	}
	return normalize(string(raw))
}
