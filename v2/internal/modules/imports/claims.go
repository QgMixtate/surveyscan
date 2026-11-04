package imports

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
)

var ErrQuota = errors.New("staging admission limit reached")
var ErrLeaseLost = errors.New("processing lease lost")
var ErrDeadLetter = errors.New("delivery awaits operator retry")

type Limits struct {
	SourceBytes, TenantBytes           int64
	SourceDeliveries, TenantDeliveries int
}

func (s *UploadService) limits() Limits {
	v := s.Limits
	if v.SourceBytes == 0 {
		v.SourceBytes = 64 << 20
	}
	if v.TenantBytes == 0 {
		v.TenantBytes = 256 << 20
	}
	if v.SourceDeliveries == 0 {
		v.SourceDeliveries = 256
	}
	if v.TenantDeliveries == 0 {
		v.TenantDeliveries = 1024
	}
	return v
}
func (s *UploadService) admit(ctx context.Context, tx pgx.Tx, tenant, source string, incoming int64) error {
	if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "staging:"+tenant); e != nil {
		return e
	}
	var total, own int64
	var count, mine int
	e := tx.QueryRow(ctx, `SELECT COALESCE(sum(octet_length(payload)),0),COALESCE(sum(octet_length(payload)) FILTER(WHERE principal_source=$2),0),count(*),count(*) FILTER(WHERE principal_source=$2) FROM imports.delivery_payloads WHERE tenant_id=$1 AND payload IS NOT NULL`, tenant, source).Scan(&total, &own, &count, &mine)
	if e != nil {
		return e
	}
	v := s.limits()
	if total+incoming > v.TenantBytes || own+incoming > v.SourceBytes || count >= v.TenantDeliveries || mine >= v.SourceDeliveries {
		return ErrQuota
	}
	return nil
}
func (s *UploadService) claim(ctx context.Context, tenant, id string) (string, bool, error) {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return "", false, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `INSERT INTO imports.processing_claims(tenant_id,delivery_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, tenant, id); e != nil {
		return "", false, e
	}
	var owner *string
	var until, retry *time.Time
	var state string
	var failures int
	var now time.Time
	e = tx.QueryRow(ctx, `SELECT owner::text,lease_until,retry_at,state,failures,clock_timestamp() FROM imports.processing_claims WHERE tenant_id=$1 AND delivery_id=$2 FOR UPDATE`, tenant, id).Scan(&owner, &until, &retry, &state, &failures, &now)
	if e != nil {
		return "", false, e
	}
	if state == "completed" {
		return "", false, nil
	}
	if state == "dead_letter" {
		return "", false, ErrDeadLetter
	}
	if owner != nil && until != nil && now.Before(*until) {
		return "", false, nil
	}
	if state == "processing" && owner != nil {
		failures++
	}
	if failures >= 5 {
		_, e = tx.Exec(ctx, `UPDATE imports.processing_claims SET state='dead_letter',owner=NULL,lease_until=NULL,failures=$3,failure_code='LEASE_EXPIRED' WHERE tenant_id=$1 AND delivery_id=$2`, tenant, id, failures)
		if e != nil {
			return "", false, e
		}
		if e = tx.Commit(ctx); e != nil {
			return "", false, e
		}
		return "", false, ErrDeadLetter
	}
	if retry != nil && now.Before(*retry) {
		return "", false, nil
	}
	token := identifier.New()
	_, e = tx.Exec(ctx, `UPDATE imports.processing_claims SET owner=$3,lease_until=clock_timestamp()+interval '120 seconds',attempts=attempts+1,failures=$4,retry_at=NULL,state='processing' WHERE tenant_id=$1 AND delivery_id=$2`, tenant, id, token, failures)
	if e != nil {
		return "", false, e
	}
	return token, true, tx.Commit(ctx)
}
func (s *UploadService) fence(ctx context.Context, tx pgx.Tx, tenant, id, owner string, progress bool) error {
	tag, e := tx.Exec(ctx, `UPDATE imports.processing_claims SET lease_until=clock_timestamp()+interval '120 seconds',failures=CASE WHEN $4 THEN 0 ELSE failures END WHERE tenant_id=$1 AND delivery_id=$2 AND owner=$3 AND state='processing' AND lease_until>clock_timestamp()`, tenant, id, owner, progress)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return nil
}
func (s *UploadService) renew(ctx context.Context, tenant, id, owner string) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = s.fence(ctx, tx, tenant, id, owner, false); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *UploadService) failClaim(tenant, id, owner string, cause error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if errors.Is(cause, domain.DependencyUnavailable) {
		_, _ = s.Pool.Exec(ctx, "UPDATE imports.processing_claims SET state='retry',retry_at=clock_timestamp()+interval '30 seconds',failure_code='DEPENDENCY_UNAVAILABLE',owner=NULL,lease_until=NULL WHERE tenant_id=$1 AND delivery_id=$2 AND owner=$3", tenant, id, owner)
		return
	}
	// Ошибка в журнале фиксированная: никакой raw payload/SQL/credential error text.
	_, _ = s.Pool.Exec(ctx, `UPDATE imports.processing_claims SET failures=failures+1,state=CASE WHEN failures+1>=5 THEN 'dead_letter' ELSE 'retry' END,retry_at=clock_timestamp()+LEAST(4.0,0.25*power(2,LEAST(failures,4)))*$4*interval '1 second',failure_code='PROCESSING_FAILED',owner=NULL,lease_until=NULL WHERE tenant_id=$1 AND delivery_id=$2 AND owner=$3`, tenant, id, owner, (.75 + rand.Float64()*.5))
}
