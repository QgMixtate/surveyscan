package router

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Переключение писателя ячейки и ограждение старого (C38, ADR decisions/C38-ha-postgres.md).

// Nodes — узлы PostgreSQL ячейки: имя → подключение (административное).
type Nodes map[string]func(context.Context) (*pgx.Conn, error)

type FailoverReport struct {
	Shard          string   `json:"shard_id"`
	From           string   `json:"from_node"`
	To             string   `json:"to_node"`
	OldFenced      bool     `json:"old_fenced"`
	OldUnreachable bool     `json:"old_unreachable"`
	LagBytes       *int64   `json:"lag_bytes_at_promotion,omitempty"` // старый доступен: 0 — ничего не потеряно
	LastReplayAt   *string  `json:"last_replayed_transaction_at,omitempty"`
	Epoch          int64    `json:"writer_epoch"`
	WindowMS       int64    `json:"window_ms"`
	Outcome        string   `json:"outcome"` // promoted | aborted
	Problems       []string `json:"problems"`
}

// Writer — текущий писатель ячейки и его эпоха.
func (c Catalog) Writer(ctx context.Context, shard string) (string, int64, string, error) {
	var node *string
	var epoch int64
	var state string
	e := c.Pool.QueryRow(ctx, "SELECT writer_node,writer_epoch,state FROM catalog.shards WHERE shard_id=$1", shard).Scan(&node, &epoch, &state)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", 0, "", ErrUnknown
	}
	if node == nil {
		return "", epoch, state, e
	}
	return *node, epoch, state, e
}

// SetWriter — первичное назначение писателя ячейки (без повышения эпохи).
func (c Catalog) SetWriter(ctx context.Context, shard, node, actor string) error {
	return c.tx(ctx, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, "UPDATE catalog.shards SET writer_node=$2 WHERE shard_id=$1 AND writer_node IS NULL", shard, node)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return errors.New("shard unknown or writer already assigned (use failover)")
		}
		return record(ctx, tx, actor, "shard.writer.assigned", nil, fmt.Sprintf(`{"shard":%q,"node":%q}`, shard, node))
	})
}

func (c Catalog) shardState(ctx context.Context, shard, from, to, actor string) error {
	return c.tx(ctx, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, "UPDATE catalog.shards SET state=$3 WHERE shard_id=$1 AND state=$2", shard, from, to)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return errors.New("catalog shard state changed concurrently")
		}
		return record(ctx, tx, actor, "shard.state."+to, nil, fmt.Sprintf(`{"shard":%q}`, shard))
	})
}

func (c Catalog) promoted(ctx context.Context, shard, from, to, actor string, detail string) (int64, error) {
	var epoch int64
	e := c.tx(ctx, func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, "UPDATE catalog.shards SET writer_node=$2,writer_epoch=writer_epoch+1,state='active' WHERE shard_id=$1 AND state='failover' RETURNING writer_epoch", shard, to).Scan(&epoch); e != nil {
			return errors.New("catalog promotion precondition failed")
		}
		return record(ctx, tx, actor, "shard.writer.promoted", nil, detail)
	})
	return epoch, e
}

// Fence ограждает узел: запрет записи сохраняется в настройках узла (переживает перезапуск), клиентские
// соединения завершаются. Узел-реплика не меняется (на реплике запись и так запрещена).
func Fence(ctx context.Context, c *pgx.Conn) error {
	if _, e := c.Exec(ctx, "ALTER SYSTEM SET default_transaction_read_only = on"); e != nil {
		return e
	}
	if _, e := c.Exec(ctx, "SELECT pg_reload_conf()"); e != nil {
		return e
	}
	if _, e := c.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND backend_type='client backend'"); e != nil {
		return e
	}
	return nil
}

// writable — узел принимает запись: не реплика и без запрета записи.
func writable(ctx context.Context, c *pgx.Conn) (bool, error) {
	var recovery bool
	var ro string
	e := c.QueryRow(ctx, "SELECT pg_is_in_recovery(),current_setting('default_transaction_read_only')").Scan(&recovery, &ro)
	return !recovery && ro == "off", e
}

func dialTimeout(ctx context.Context, dial func(context.Context) (*pgx.Conn, error), d time.Duration) (*pgx.Conn, error) {
	c, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return dial(c)
}

// Failover переключает писателя ячейки shard на узел to.
func Failover(ctx context.Context, cat Catalog, shard string, nodes Nodes, to string, oldUnreachable bool, catchUp time.Duration, actor string) (FailoverReport, error) {
	rep := FailoverReport{Shard: shard, To: to, Problems: []string{}, Outcome: "aborted"}
	started := time.Now()
	from, _, state, e := cat.Writer(ctx, shard)
	if e != nil {
		return rep, e
	}
	rep.From = from
	if state != "active" || from == "" || from == to || nodes[to] == nil || nodes[from] == nil {
		return rep, fmt.Errorf("shard %s: state %s, writer %q, target %q — not eligible", shard, state, from, to)
	}
	target, e := dialTimeout(ctx, nodes[to], 5*time.Second)
	if e != nil {
		return rep, errors.New("target node unavailable")
	}
	defer target.Close(context.WithoutCancel(ctx))
	var recovery bool
	if e = target.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&recovery); e != nil || !recovery {
		return rep, errors.New("target node is not a replica")
	}
	// 1. новые запросы к организациям ячейки — 503
	if e = cat.shardState(ctx, shard, "active", "failover", actor); e != nil {
		return rep, e
	}
	abort := func(cause error) (FailoverReport, error) {
		rep.Problems = append(rep.Problems, cause.Error())
		if rep.OldFenced {
			rep.Problems = append(rep.Problems, "old writer stays fenced: unfence it manually (ALTER SYSTEM RESET default_transaction_read_only) or retry failover")
		} else if err := cat.shardState(context.WithoutCancel(ctx), shard, "failover", "active", actor); err != nil {
			rep.Problems = append(rep.Problems, "catalog: "+err.Error())
		}
		rep.WindowMS = time.Since(started).Milliseconds()
		return rep, cause
	}
	// 2. ограждение старого писателя
	var oldLSN string
	old, e := dialTimeout(ctx, nodes[from], 5*time.Second)
	if e == nil {
		defer old.Close(context.WithoutCancel(ctx))
		if e = Fence(ctx, old); e != nil {
			return abort(fmt.Errorf("fence old writer: %w", e))
		}
		rep.OldFenced = true
		// после ограждения новых записей нет; позиция WAL — то, что реплика должна проиграть
		if e = old.QueryRow(ctx, "SELECT pg_current_wal_lsn()::text").Scan(&oldLSN); e != nil {
			return abort(e)
		}
	} else if !oldUnreachable {
		return abort(errors.New("old writer unreachable: confirm it is powered off or isolated and rerun with -old-unreachable"))
	} else {
		rep.OldUnreachable = true
	}
	// 3. догон реплики
	if oldLSN != "" {
		deadline := time.Now().Add(catchUp)
		for {
			var lag int64
			if e = target.QueryRow(ctx, "SELECT pg_wal_lsn_diff($1::pg_lsn, pg_last_wal_replay_lsn())::bigint", oldLSN).Scan(&lag); e != nil {
				return abort(e)
			}
			if lag <= 0 {
				lag = 0
				rep.LagBytes = &lag
				break
			}
			if time.Now().After(deadline) {
				rep.LagBytes = &lag
				return abort(fmt.Errorf("replica did not catch up within %s (lag %d bytes)", catchUp, lag))
			}
			time.Sleep(100 * time.Millisecond)
		}
	} else {
		var at *time.Time
		if e = target.QueryRow(ctx, "SELECT pg_last_xact_replay_timestamp()").Scan(&at); e == nil && at != nil {
			s := at.UTC().Format(time.RFC3339Nano)
			rep.LastReplayAt = &s
		}
	}
	// 4. повышение
	var ok bool
	if e = target.QueryRow(ctx, "SELECT pg_promote(true, 60)").Scan(&ok); e != nil || !ok {
		return abort(fmt.Errorf("promote failed: %v", e))
	}
	if _, e = target.Exec(ctx, "ALTER SYSTEM RESET default_transaction_read_only"); e != nil {
		return abort(e)
	}
	if _, e = target.Exec(ctx, "SELECT pg_reload_conf()"); e != nil {
		return abort(e)
	}
	// 5. каталог
	detail := fmt.Sprintf(`{"shard":%q,"from":%q,"to":%q,"old_unreachable":%t}`, shard, from, to, rep.OldUnreachable)
	if rep.Epoch, e = cat.promoted(ctx, shard, from, to, actor, detail); e != nil {
		rep.Problems = append(rep.Problems, "target already promoted; catalog update failed: "+e.Error())
		return rep, e
	}
	rep.Outcome = "promoted"
	rep.WindowMS = time.Since(started).Milliseconds()
	return rep, nil
}

// CheckWriters — сторож: узел, который принимает запись, но не является писателем по каталогу, ограждается.
// Возвращает огражденные узлы и недоступные узлы.
func CheckWriters(ctx context.Context, cat Catalog, shard string, nodes Nodes, actor string) (fenced, unreachable []string, err error) {
	writer, _, state, e := cat.Writer(ctx, shard)
	if e != nil {
		return nil, nil, e
	}
	if state == "failover" || writer == "" {
		return nil, nil, nil // переключение идёт — им управляет команда failover
	}
	for name, dial := range nodes {
		if name == writer {
			continue
		}
		c, e := dialTimeout(ctx, dial, 3*time.Second)
		if e != nil {
			unreachable = append(unreachable, name)
			continue
		}
		w, e := writable(ctx, c)
		if e == nil && w {
			if e = Fence(ctx, c); e == nil {
				fenced = append(fenced, name)
				_ = cat.tx(ctx, func(tx pgx.Tx) error {
					return record(ctx, tx, actor, "shard.writer.fenced", nil, fmt.Sprintf(`{"shard":%q,"node":%q}`, shard, name))
				})
			}
		}
		c.Close(context.WithoutCancel(ctx))
		if e != nil {
			err = errors.Join(err, fmt.Errorf("node %s: %w", name, e))
		}
	}
	return fenced, unreachable, err
}
