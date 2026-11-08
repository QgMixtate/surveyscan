//go:build !windows

package main

import "errors"

func runServiceCommand(args []string) (bool, error) {
	if len(args) > 0 {
		switch args[0] {
		case "install-service", "uninstall-service", "service":
			return true, errors.New("служба Windows недоступна на этой платформе")
		}
	}
	return false, nil
}
