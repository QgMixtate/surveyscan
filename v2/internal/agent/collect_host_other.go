//go:build !linux && !windows

package agent

import (
	"context"
	"errors"
)

// CollectHost12 — сбор этого хоста поддерживается только на Linux и Windows.
func CollectHost12(context.Context) (Snapshot, error) {
	return Snapshot{}, errors.New("host collection requires Linux or Windows")
}
