package privatefile

import (
	"errors"
	"io"
	"os"
)

func Read(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("private file unavailable")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > max {
		return nil, errors.New("private regular file required")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, errors.New("private file size/read error")
	}
	return b, nil
}
