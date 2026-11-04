//go:build !linux

package agent

import "errors"

func lockState(string) (func(), error) {
	return nil, errors.New("agent runtime currently supports Linux only")
}
