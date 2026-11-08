//go:build windows

package privatefile

import (
	"errors"
	"path/filepath"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/winstate"
)

// Read на Windows читает файл только из каталога с приватным DACL, относительно
// открытого дескриптора каталога: reparse/hardlink и небезопасный ACL отвергаются,
// а не «чинятся». POSIX-проверка прав здесь бессмысленна.
func Read(path string, max int64) ([]byte, error) {
	root, e := winstate.OpenRoot(filepath.Dir(path))
	if e != nil {
		return nil, errors.New("private file unavailable")
	}
	defer root.Close()
	b, e := root.Read(filepath.Base(path), max)
	if e != nil {
		return nil, errors.New("private regular file required")
	}
	return b, nil
}
