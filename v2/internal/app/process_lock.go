package app

import (
	"context"
	"errors"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
)

// C35.02/C36.01: межпроцессная взаимоисключающая работа при нескольких worker/combined экземплярах центра — аренда
// строки messaging.work_leases (без состояния сессии БД, совместимо с пулом в режиме транзакций). Держатель продлевает
// аренду каждые leaseTTL/4; упавший процесс теряет её по истечении leaseTTL.

var ErrBusy = errors.New("the same work is running in another center process")

const leaseTTL = 2 * time.Minute

// exclusive выполняет fn, только если ни один процесс сейчас не выполняет работу key; иначе — ErrBusy.
func (r *Registry) exclusive(ctx context.Context, key string, fn func(context.Context) error) error {
	key = "surveyscan:" + key
	holder, e := messaging.AcquireLease(ctx, r.Pool, key, leaseTTL)
	if errors.Is(e, messaging.ErrLeaseBusy) {
		return ErrBusy
	}
	if e != nil {
		return e
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		ticker := time.NewTicker(leaseTTL / 4)
		defer ticker.Stop()
		for {
			select {
			case <-work.Done():
				return
			case <-ticker.C:
				if ok, _ := messaging.RenewLease(work, r.Pool, key, holder, leaseTTL); !ok {
					cancel() // аренда потеряна: прекращаем работу, чтобы не выполнять её вдвоём
					return
				}
			}
		}
	}()
	e = fn(work)
	cancel()
	<-renewed
	_ = messaging.ReleaseLease(context.WithoutCancel(ctx), r.Pool, key, holder)
	return e
}
