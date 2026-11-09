//go:build windows

package main

import (
	"context"

	"github.com/QgMixtate/surveyscan/v2/internal/agent"
)

func runAgent(ctx context.Context, c agent.Config, report func(string)) error {
	return agent.RunWindows(ctx, c, report)
}

func runAgent12(ctx context.Context, c agent.Config, report func(string)) error {
	return agent.RunWindows(ctx, c, report)
}
