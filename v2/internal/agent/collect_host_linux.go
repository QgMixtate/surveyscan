//go:build linux

package agent

import "context"

// CollectHost12 — сбор этого хоста по профилю 1.2 (для разового portable-аудита без службы).
func CollectHost12(ctx context.Context) (Snapshot, error) { return CollectLinux12(ctx) }
