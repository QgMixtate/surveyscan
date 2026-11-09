//go:build linux

package agent

import (
	"context"
	"os"
	"path/filepath"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// RunLinux12 — постоянный цикл Linux-агента по профилю 1.2 (явное включение командой run12).
// Прежний Run (профиль 1.0, три секции) не затронут. Сбор разрешён только при проверенном
// профиле 1.2 для зарегистрированной платформы linux/amd64.
func RunLinux12(ctx context.Context, c Config, report func(string)) error {
	unlock, e := lockState(c.State)
	if e != nil {
		return stage(StageState, e)
	}
	defer unlock()
	if e = diskspool.RecoverTemps(c.State); e != nil {
		return stage(StageState, e)
	}
	if e = diskspool.RecoverTemps(filepath.Join(c.State, "spool")); e != nil && !os.IsNotExist(e) {
		return stage(StageSpool, e)
	}
	client, e := Open(c)
	if e != nil {
		return stage(StageOpen, e)
	}
	defer client.http.CloseIdleConnections()
	cl, e := newWindowsClient12(client) // клиент 1.2 не зависит от ОС; имя историческое
	if e != nil {
		return stage(StageSetup, e)
	}
	own, e := wire.InventorySpoolOffer12(c.Limit)
	if e != nil {
		return stage(StageSetup, e)
	}
	return runLoop12(ctx, cl, report, CollectLinux12, own, defaultLoop12Timing)
}
