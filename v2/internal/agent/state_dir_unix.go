//go:build !windows

package agent

import "os"

// ensureStateDir на POSIX создаёт каталог с правами 0700 (поведение Linux E1 без изменений).
func ensureStateDir(path string) error { return os.MkdirAll(path, 0700) }
