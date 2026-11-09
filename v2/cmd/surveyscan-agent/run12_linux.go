//go:build linux

package main

import (
	"context"

	"github.com/QgMixtate/surveyscan/v2/internal/agent"
)

func runLinux12(ctx context.Context, c agent.Config, report func(string)) error {
	return agent.RunLinux12(ctx, c, report)
}
