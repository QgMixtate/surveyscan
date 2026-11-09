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
