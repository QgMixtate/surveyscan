package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/responsibility"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
)

// C36.03 (ADR decisions/C36-postgres-operations.md): очистка служебных журналов. Наблюдения и аудит не удаляются.

type RetentionPolicy struct {
	EventAge, DeliveryAge time.Duration
	KeepSyncRuns, Batch   int
}

var DefaultRetention = RetentionPolicy{EventAge: 30 * 24 * time.Hour, DeliveryAge: 30 * 24 * time.Hour, KeepSyncRuns: 500, Batch: 1000}

type RetentionReport struct {
	messaging.RetentionResult
	SyncRuns int64
}

// RunRetention — один проход очистки под арендой (один процесс контура).
func (r *Registry) RunRetention(ctx context.Context, p RetentionPolicy) (RetentionReport, error) {
	var out RetentionReport
	e := r.exclusive(ctx, "retention", func(ctx context.Context) error {
		for {
			n, e := messaging.PruneOutbox(ctx, r.Pool, p.EventAge, r.Search != nil, p.Batch)
			if e != nil {
				return e
			}
			out.Events += n.Events
			out.Checkpoints += n.Checkpoints
			out.Deliveries += n.Deliveries
			if n.Events < int64(p.Batch) {
				break
			}
		}
		for {
			n, e := messaging.PruneDeliveries(ctx, r.Pool, p.DeliveryAge, p.Batch)
			if e != nil {
				return e
			}
			out.Deliveries += n
			if n < int64(p.Batch) {
				break
			}
		}
		n, e := messaging.PruneLeases(ctx, r.Pool)
		if e != nil {
			return e
		}
		out.Leases = n
		tx, e := r.Pool.Begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback(ctx)
		if out.SyncRuns, e = responsibility.PruneSyncRuns(ctx, tx, p.KeepSyncRuns); e != nil {
			return e
		}
		return tx.Commit(ctx)
	})
	return out, e
}

// RetentionMaintain — фоновая роль worker/combined: очистка раз в час.
func (r *Registry) RetentionMaintain(ctx context.Context, log func(string)) {
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		task, done := context.WithTimeout(ctx, 30*time.Minute)
		rep, e := r.RunRetention(task, DefaultRetention)
		done()
		switch {
		case errors.Is(e, ErrBusy):
		case e != nil:
			log("retention failed: " + e.Error())
		case rep.Events+rep.Deliveries+rep.SyncRuns > 0:
			log(fmt.Sprintf("retention: events=%d checkpoints=%d deliveries=%d sync_runs=%d", rep.Events, rep.Checkpoints, rep.Deliveries, rep.SyncRuns))
		}
		timer.Reset(time.Hour)
	}
}
