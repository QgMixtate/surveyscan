//go:build !windows

package main

import (
	"context"
	"errors"
	"runtime"

	"github.com/QgMixtate/surveyscan/v2/internal/agent"
)

func runAgent(ctx context.Context, c agent.Config, report func(string)) error {
	return agent.Run(ctx, c, report)
}

func runAgent12(ctx context.Context, c agent.Config, report func(string)) error {
	if runtime.GOOS != "linux" {
		return errors.New("run12 поддерживается только на Linux")
	}
	return runLinux12(ctx, c, report)
}
