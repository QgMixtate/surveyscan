//go:build windows

package agent

import (
	"context"
	"path/filepath"

	"github.com/QgMixtate/surveyscan/v2/internal/agent/windowsinventory"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// RunWindows — постоянный цикл Windows-агента. Состояние и очередь — приватные корни под
// эксклюзивными блокировками; сбор — 12 изолированных воркеров; наблюдения идут batch 1.2
// и только при проверенном профиле. Linux Run не затрагивается.
func RunWindows(ctx context.Context, c Config, report func(string)) error {
	unlock, e := lockState(c.State)
	if e != nil {
		return stage(StageState, e)
	}
	defer unlock()
	if e = diskspool.RecoverTemps(c.State); e != nil {
		return stage(StageState, e)
	}
	// Open создаёт приватный корень очереди, поэтому блокировка очереди берётся после него.
	client, e := Open(c)
	if e != nil {
		return stage(StageOpen, e)
	}
	defer client.http.CloseIdleConnections()
	spool := filepath.Join(c.State, "spool")
	unlockSpool, e := diskspool.Lock(spool)
	if e != nil {
		return stage(StageSpool, e)
	}
	defer unlockSpool()
	if e = diskspool.RecoverTemps(spool); e != nil {
		return stage(StageSpool, e)
	}
	cl, e := newWindowsClient12(client)
	if e != nil {
		return stage(StageSetup, e)
	}
	own, e := wire.InventorySpoolOffer12(c.Limit)
	if e != nil {
		return stage(StageSetup, e)
	}
	collect := func(ctx context.Context) (Snapshot, error) {
		sections, e := windowsinventory.Collect(ctx)
		if e != nil {
			return Snapshot{}, e
		}
		return Snapshot{Candidates: candidatesFromSections(sections), Sections: sections}, nil
	}
	return runLoop12(ctx, cl, report, collect, own, defaultLoop12Timing)
}
