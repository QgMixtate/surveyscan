package messaging

import (
	"context"
	"encoding/json"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"regexp"
	"strconv"
)

type Event struct {
	ID, Tenant, Producer, Aggregate, AssetID, Version, Type, Correlation string
	Data                                                                 map[string]string
}
type Writer struct{}

func (Writer) Emit(ctx context.Context, tx pgx.Tx, event Event) error {
	if _, e := strconv.ParseUint(event.Version, 10, 64); e != nil {
		return domain.Invalid
	}

	kinds := map[string][3]string{"asset.created.v1": {"Assets", "asset", "asset_uid"}, "asset.facts_changed.v1": {"Assets", "asset", "asset_uid"}, "responsibility.assigned.v1": {"Responsibility", "asset", "asset_uid"}, "observation.recorded.v1": {"Inventory", "observation", "observation_id"}, "source.contact_updated.v1": {"Sources", "source", "source_id"}, "source.profile_updated.v1": {"Sources", "source", "source_id"}}
	binding, ok := kinds[event.Type]
	if !ok || binding[0] != event.Producer || binding[1] != event.Aggregate || event.Data[binding[2]] != event.AssetID || !identifier.Valid(event.Tenant) || !identifier.Valid(event.AssetID) || event.Version == "0" {
		return domain.Invalid
	}
	for key, value := range event.Data {
		switch key {
		case "asset_uid", "observation_id", "source_id", "subject_id":
			if !identifier.Valid(value) {
				return domain.Invalid
			}
		case "reason_code":
			if !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`).MatchString(value) {
				return domain.Invalid
			}
		default:
			return domain.Invalid
		}
	}
	payload, e := json.Marshal(event.Data)
	if e != nil {
		return e
	}
	if event.ID == "" {
		event.ID = identifier.New()
	}
	if event.Correlation == "" {
		event.Correlation = identifier.New()
	}
	_, e = tx.Exec(ctx, `INSERT INTO messaging.outbox_events(tenant_id,event_id,producer_module,aggregate_type,aggregate_id,aggregate_version,event_type,correlation_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, event.Tenant, event.ID, event.Producer, event.Aggregate, event.AssetID, event.Version, event.Type, event.Correlation, payload)
	return e
}

type Effect func(context.Context, pgx.Tx, Event) error

func ConsumeOne(ctx context.Context, pool *pgxpool.Pool, tenant, consumer string, effect Effect) (bool, error) {
	tx, e := pool.Begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "consumer:"+tenant+":"+consumer); e != nil {
		return false, e
	}
	var event Event
	var payload []byte
	e = tx.QueryRow(ctx, `SELECT e.event_id::text,e.tenant_id::text,e.producer_module,e.aggregate_type,e.aggregate_id::text,e.aggregate_version::text,e.event_type,e.correlation_id::text,e.payload FROM messaging.outbox_events e LEFT JOIN messaging.consumer_checkpoints c ON c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name=$2 WHERE e.tenant_id=$1 AND (c.state IS NULL OR (c.state='retry' AND c.lease_until<=clock_timestamp())) AND NOT EXISTS(SELECT 1 FROM messaging.outbox_events prev WHERE prev.tenant_id=e.tenant_id AND prev.aggregate_type=e.aggregate_type AND prev.aggregate_id=e.aggregate_id AND prev.aggregate_version<e.aggregate_version AND NOT EXISTS(SELECT 1 FROM messaging.consumer_checkpoints pc WHERE pc.tenant_id=prev.tenant_id AND pc.event_id=prev.event_id AND pc.consumer_name=$2 AND pc.state='applied')) ORDER BY e.aggregate_type,e.aggregate_id,e.aggregate_version LIMIT 1`, tenant, consumer).Scan(&event.ID, &event.Tenant, &event.Producer, &event.Aggregate, &event.AssetID, &event.Version, &event.Type, &event.Correlation, &payload)
	if e == pgx.ErrNoRows {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if e = json.Unmarshal(payload, &event.Data); e != nil {
		return false, e
	}
	var attempts int
	e = tx.QueryRow(ctx, `INSERT INTO messaging.consumer_checkpoints(tenant_id,consumer_name,event_id,state,attempts,lease_until) VALUES($1,$2,$3,'claimed',1,clock_timestamp()+interval '30 seconds') ON CONFLICT(tenant_id,consumer_name,event_id) DO UPDATE SET state='claimed',attempts=messaging.consumer_checkpoints.attempts+1 RETURNING attempts`, tenant, consumer, event.ID).Scan(&attempts)
	if e != nil {
		return false, e
	}
	save, e := tx.Begin(ctx)
	if e != nil {
		return false, e
	}
	failure := effect(ctx, save, event)
	if failure != nil {
		_ = save.Rollback(ctx)
		state := "retry"
		if attempts >= 5 {
			state = "dead_letter"
		}
		_, e = tx.Exec(ctx, "UPDATE messaging.consumer_checkpoints SET state=$4,lease_until=clock_timestamp()+$5*interval '1 second' WHERE tenant_id=$1 AND consumer_name=$2 AND event_id=$3", tenant, consumer, event.ID, state, attempts*2)
	} else {
		if e = save.Commit(ctx); e != nil {
			return false, e
		}
		_, e = tx.Exec(ctx, "UPDATE messaging.consumer_checkpoints SET state='applied',applied_at=clock_timestamp(),lease_until=NULL WHERE tenant_id=$1 AND consumer_name=$2 AND event_id=$3", tenant, consumer, event.ID)
	}
	if e != nil {
		return false, e
	}
	return true, tx.Commit(ctx)
}
func PendingTenants(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	return PendingTenantsFor(ctx, pool, "registry-version")
}

// PendingTenantsFor — тенанты с событиями, ещё не применёнными потребителем consumer (C29: потребитель поиска).
func PendingTenantsFor(ctx context.Context, pool *pgxpool.Pool, consumer string) ([]string, error) {
	rows, e := pool.Query(ctx, "SELECT tenant_id::text FROM messaging.outbox_events e WHERE NOT EXISTS(SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name=$1 AND c.state IN ('applied','dead_letter')) GROUP BY tenant_id ORDER BY tenant_id LIMIT 100", consumer)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
