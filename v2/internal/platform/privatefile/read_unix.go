//go:build !windows

package privatefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func Read(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("private file unavailable")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || (info.Mode().Perm()&0077 != 0 && !systemdCredential(path, info)) || info.Size() > max {
		return nil, errors.New("private regular file required")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, errors.New("private file size/read error")
	}
	return b, nil
}

// systemdCredential допускает файл учётных данных systemd (LoadCredential): на systemd>=255 он принадлежит root:root,
// имеет режим 0440 и доступен сервисному пользователю по ACL. Принимается только файл прямо внутри
// $CREDENTIALS_DIRECTORY, владелец root:root, права не шире 0440 (нет записи и доступа «остальным»), каталог без доступа «остальным».
func systemdCredential(path string, info os.FileInfo) bool {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" || !filepath.IsAbs(dir) || filepath.Dir(filepath.Clean(path)) != filepath.Clean(dir) {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 || info.Mode().Perm()&^0o440 != 0 {
		return false
	}
	d, err := os.Stat(dir)
	return err == nil && d.IsDir() && d.Mode().Perm()&0o007 == 0
}
