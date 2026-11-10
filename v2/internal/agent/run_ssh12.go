//go:build linux

package agent

import (
	"context"
	"os"
	"path/filepath"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/sshlinux"
)

// RunSSH12 — цикл профиля 1.2 для безагентной Linux-цели: личность, очередь, подписи и доставка те же, что у
// агента (отдельная зарегистрированная личность на цель, платформа linux/amd64), но данные собираются по SSH
// с хоста коллектора, а не локально. Состояние привязано к хосту, где работает процесс.
func RunSSH12(ctx context.Context, c Config, target SSHTarget, report func(string)) error {
	return runVirtual12(ctx, c, NewSSHCollect12(target, sshlinux.Policy{}), report)
}

// runVirtual12 — общий цикл «виртуальной агентской личности» с подменённой функцией удалённого сбора.
func runVirtual12(ctx context.Context, c Config, collect func(context.Context) (Snapshot, error), report func(string)) error {
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
	cl, e := newWindowsClient12(client)
	if e != nil {
		return stage(StageSetup, e)
	}
	own, e := wire.InventorySpoolOffer12(c.Limit)
	if e != nil {
		return stage(StageSetup, e)
	}
	return runLoop12(ctx, cl, report, collect, own, defaultLoop12Timing)
}

// RunWinRM12 — то же для безагентной Windows-цели по WinRM (личность должна быть выдана с платформой windows/amd64).
func RunWinRM12(ctx context.Context, c Config, target WinRMTarget, report func(string)) error {
	return runVirtual12(ctx, c, NewWinRMCollect12(target), report)
}
