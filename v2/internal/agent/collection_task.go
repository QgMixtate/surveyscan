package agent

import (
	"context"
	"time"
)

type collectionResult struct {
	snapshot Snapshot
	at       time.Time
	err      error
}

// The worker reads the host only. It never receives Client, counters, TLS keys,
// profiles or spool paths. The actor retains the task until it actually exits,
// including after cancellation, so a stuck provider cannot spawn replacements.
type collectionTask struct {
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan collectionResult
	reported bool
}

func startCollection(parent context.Context, collect func(context.Context) (Snapshot, error), limit time.Duration) *collectionTask {
	ctx, cancel := context.WithTimeout(parent, limit)
	task := &collectionTask{ctx: ctx, cancel: cancel, done: make(chan collectionResult, 1)}
	go func() {
		defer cancel()
		snapshot, err := collect(ctx)
		if err == nil {
			err = ctx.Err()
		}
		task.done <- collectionResult{snapshot: snapshot, at: time.Now().UTC(), err: err}
	}()
	return task
}
