package app

import (
	"context"
	"errors"
)

// C35.02: межпроцессная взаимоисключающая работа при нескольких worker/combined экземплярах центра. Блокировка —
// advisory lock PostgreSQL на выделенном соединении (держится, пока идёт работа; падение процесса снимает её
// вместе с соединением). Не полагается на память процесса.

var ErrBusy = errors.New("the same work is running in another center process")

// exclusive выполняет fn, только если ни один процесс сейчас не выполняет работу key; иначе — ErrBusy.
func (r *Registry) exclusive(ctx context.Context, key string, fn func(context.Context) error) error {
	conn, e := r.Pool.Acquire(ctx)
	if e != nil {
		return e
	}
	defer conn.Release()
	var got bool
	if e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", "surveyscan:"+key).Scan(&got); e != nil {
		return e
	}
	if !got {
		return ErrBusy
	}
	defer func() {
		// соединение возвращается в пул: снимаем блокировку явно (при обрыве соединения её снимет PostgreSQL)
		if _, e := conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock(hashtextextended($1,0))", "surveyscan:"+key); e != nil {
			conn.Conn().Close(context.WithoutCancel(ctx))
		}
	}()
	return fn(ctx)
}
