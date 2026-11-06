//go:build windows

package main

import (
	"os"

	"github.com/QgMixtate/surveyscan/v2/internal/agent/windowsinventory"
)

func runNativeWorker(args []string) (bool, error) {
	if len(args) == 0 || args[0] != "inventory-worker" {
		return false, nil
	}
	if len(args) != 2 {
		return true, windowsinventory.ErrWorkerArguments
	}
	return true, windowsinventory.WriteWorkerSection(args[1], os.Stdout)
}
