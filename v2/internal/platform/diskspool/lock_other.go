//go:build !linux && !windows

package diskspool

import "errors"

func Lock(string) (func(), error) {
	return nil, errors.New("durable process lock currently supports Linux only")
}
