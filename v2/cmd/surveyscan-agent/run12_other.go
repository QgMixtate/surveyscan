//go:build !linux && !windows

package main

import (
	"context"
	"errors"

	"github.com/QgMixtate/surveyscan/v2/internal/agent"
)

func runLinux12(context.Context, agent.Config, func(string)) error {
	return errors.New("run12 поддерживается только на Linux")
}

func runSSH12(context.Context, agent.Config, agent.SSHTarget, func(string)) error {
	return errors.New("run-ssh12 поддерживается только на Linux")
}

func runWinRM12(context.Context, agent.Config, agent.WinRMTarget, func(string)) error {
	return errors.New("run-winrm12 поддерживается только на Linux-хосте коллектора")
}
