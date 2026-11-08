//go:build windows

package diskspool

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/winstate"
)

// held — каталоги, на которых этот процесс держит эксклюзивную блокировку писателя.
// Atomic/RecoverTemps разрешены только для них: так же, как на Linux, запись без
// владения блокировкой невозможна. Блокировка — файл .state.lock внутри winstate-корня.
var (
	heldMu sync.Mutex
	held   = map[string]*heldRoot{}
)

type heldRoot struct {
	root   *winstate.Root
	unlock func()
}

var errActive = errors.New("spool already has an active writer")

func key(directory string) (string, error) {
	abs, e := filepath.Abs(directory)
	if e != nil {
		return "", e
	}
	return strings.ToLower(filepath.Clean(abs)), nil
}

func holder(directory string) (*heldRoot, error) {
	k, e := key(directory)
	if e != nil {
		return nil, e
	}
	heldMu.Lock()
	defer heldMu.Unlock()
	if h := held[k]; h != nil {
		return h, nil
	}
	return nil, errors.New("spool writer lock required")
}

// Lock открывает каталог как приватный winstate-корень (несуществующий создаёт,
// существующий с небезопасным ACL/reparse отвергает без исправления) и берёт блокировку.
func Lock(directory string) (func(), error) {
	k, e := key(directory)
	if e != nil {
		return nil, e
	}
	heldMu.Lock()
	defer heldMu.Unlock()
	if held[k] != nil {
		return nil, errActive
	}
	var root *winstate.Root
	if _, e = os.Lstat(directory); os.IsNotExist(e) {
		root, e = winstate.CreateRoot(directory)
	} else {
		root, e = winstate.OpenRoot(directory)
	}
	if e != nil {
		return nil, e
	}
	unlock, e := root.Lock()
	if e != nil {
		root.Close()
		return nil, errActive
	}
	h := &heldRoot{root: root, unlock: unlock}
	held[k] = h
	return func() {
		heldMu.Lock()
		defer heldMu.Unlock()
		if held[k] == h {
			h.unlock()
			h.root.Close()
			delete(held, k)
		}
	}, nil
}
