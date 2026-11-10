//go:build windows

package agent

import (
	"context"

	"github.com/QgMixtate/surveyscan/v2/internal/agent/windowsinventory"
)

// CollectHost12 — сбор этого хоста по профилю 1.2 (для разового portable-аудита без службы).
func CollectHost12(ctx context.Context) (Snapshot, error) {
	sections, err := windowsinventory.Collect(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Candidates: candidatesFromSections(sections), Sections: sections}, nil
}
