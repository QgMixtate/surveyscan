//go:build windows

package agent

import (
	"os"
	"path/filepath"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/winstate"
)

// ensureStateDir создаёт каталог состояния как приватный корень (защищённый DACL).
// Существующий каталог проверяется, а не «исправляется»: каталог с обычным унаследованным
// ACL отвергается. Родители создаются обычным образом: приватность относится к самому
// каталогу состояния, а не к пути до него.
func ensureStateDir(path string) error {
	if _, e := os.Lstat(path); e == nil {
		root, e := winstate.OpenRoot(path)
		if e != nil {
			return e
		}
		return root.Close()
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	root, e := winstate.CreateRoot(path)
	if e != nil {
		return e
	}
	return root.Close()
}
