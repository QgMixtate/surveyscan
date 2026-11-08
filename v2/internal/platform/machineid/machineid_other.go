//go:build !linux && !windows

package machineid

// Local на остальных платформах недоступен: привязка хоста не заявляется.
func Local() (string, error) { return "", ErrUnavailable }
