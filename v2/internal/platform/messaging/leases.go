package messaging

import (
	"context"
	"errors"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Аренда работы (C35.02/C36.01): только строки таблицы, никакого состояния сессии — работает и через пул
// соединений в режиме транзакций.

var ErrLeaseBusy = errors.New("lease held by another process")

// AcquireLease берёт аренду key на ttl, если она свободна или истекла. Возвращает идентификатор держателя.
func AcquireLease(ctx context.Context, pool *pgxpool.Pool, key string, ttl time.Duration) (string, error) {
	holder := identifier.New()
	var got string
	e := pool.QueryRow(ctx, `INSERT INTO messaging.work_leases(lease_key,holder,acquired_at,lease_until) VALUES($1,$2,clock_timestamp(),clock_timestamp()+$3*interval '1 second')
ON CONFLICT(lease_key) DO UPDATE SET holder=excluded.holder,acquired_at=excluded.acquired_at,lease_until=excluded.lease_until WHERE messaging.work_leases.lease_until<clock_timestamp()
RETURNING holder::text`, key, holder, ttl.Seconds()).Scan(&got)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", ErrLeaseBusy
	}
	return got, e
}

// RenewLease продлевает аренду держателя; false — аренда потеряна (истекла и взята другим).
func RenewLease(ctx context.Context, pool *pgxpool.Pool, key, holder string, ttl time.Duration) (bool, error) {
	tag, e := pool.Exec(ctx, "UPDATE messaging.work_leases SET lease_until=clock_timestamp()+$3*interval '1 second' WHERE lease_key=$1 AND holder=$2", key, holder, ttl.Seconds())
	return e == nil && tag.RowsAffected() == 1, e
}

func ReleaseLease(ctx context.Context, pool *pgxpool.Pool, key, holder string) error {
	_, e := pool.Exec(ctx, "DELETE FROM messaging.work_leases WHERE lease_key=$1 AND holder=$2", key, holder)
	return e
}
