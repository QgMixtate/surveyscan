//go:build integration

package app_test

import (
	"errors"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
)

// C35.02/C36.01: аренда работ без состояния сессии — занятая не берётся, истёкшая (упавший процесс) переходит
// к новому держателю, прежний держатель её больше не продлевает.
func TestWorkLeases(t *testing.T) {
	f := registrySetup(t)
	a, err := messaging.AcquireLease(f.ctx, f.pool, "test:lease", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = messaging.AcquireLease(f.ctx, f.pool, "test:lease", time.Minute); !errors.Is(err, messaging.ErrLeaseBusy) {
		t.Fatal("held lease must be busy", err)
	}
	if ok, err := messaging.RenewLease(f.ctx, f.pool, "test:lease", a, time.Minute); !ok || err != nil {
		t.Fatal("holder renews", ok, err)
	}
	_, _ = f.pool.Exec(f.ctx, "UPDATE messaging.work_leases SET acquired_at=now()-interval '3 minutes',lease_until=now()-interval '1 second' WHERE lease_key='test:lease'")
	b, err := messaging.AcquireLease(f.ctx, f.pool, "test:lease", time.Minute)
	if err != nil || b == a {
		t.Fatal("expired lease must be taken over", err)
	}
	if ok, _ := messaging.RenewLease(f.ctx, f.pool, "test:lease", a, time.Minute); ok {
		t.Fatal("previous holder must not renew a lost lease")
	}
	_ = messaging.ReleaseLease(f.ctx, f.pool, "test:lease", a) // чужой держатель — ничего не удаляет
	if _, err = messaging.AcquireLease(f.ctx, f.pool, "test:lease", time.Minute); !errors.Is(err, messaging.ErrLeaseBusy) {
		t.Fatal("release by a non-holder must not free the lease", err)
	}
	_ = messaging.ReleaseLease(f.ctx, f.pool, "test:lease", b)
	if _, err = messaging.AcquireLease(f.ctx, f.pool, "test:lease", time.Minute); err != nil {
		t.Fatal("released lease must be free", err)
	}
}
