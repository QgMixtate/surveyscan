//go:build integration

package app_test

import (
	"fmt"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/app"
)

// C36.03: очистка журналов — удаляются только события, применённые нужными потребителями и без незавершённых
// доставок; неизменяемость событий вне транзакции очистки сохраняется; наблюдения и аудит не трогаются.
func TestRetention(t *testing.T) {
	f := registrySetup(t)
	for i := range 3 {
		o := f.observation("1")
		mu := fmt.Sprintf("00000000-0000-4000-8000-%012d", 950+i)
		o.Record.LocalID = fmt.Sprintf("ret-%d", i)
		o.Candidates = []contracts.Candidate{{Kind: "machine_uuid", Namespace: "host", Value: mu}}
		o.Sections[0].Records = []map[string]any{{"hostname": fmt.Sprintf("ret-%d", i), "machine_uuid": mu}}
		f.ingest(t, o)
	}
	count := func(q string) (n int) { _ = f.pool.QueryRow(f.ctx, q).Scan(&n); return }
	events := count("SELECT count(*) FROM messaging.outbox_events")
	observations, audits := count("SELECT count(*) FROM inventory.observations"), count("SELECT count(*) FROM audit.audit_events")
	if events == 0 {
		t.Fatal("fixture must emit events")
	}
	policy := app.DefaultRetention
	policy.EventAge, policy.DeliveryAge = 0, 0
	// ничего не применено потребителем версий — ничего не удаляется
	if rep, err := f.registry.RunRetention(f.ctx, policy); err != nil || rep.Events != 0 {
		t.Fatal("unapplied events must stay", rep, err)
	}
	for {
		worked, err := f.registry.ConsumeOne(f.ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			break
		}
	}
	// одно событие держит незавершённая доставка уведомления
	var held string
	_ = f.pool.QueryRow(f.ctx, "SELECT event_id::text FROM messaging.outbox_events ORDER BY occurred_at LIMIT 1").Scan(&held)
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO messaging.webhook_subscriptions(tenant_id,subscription_id,url,event_types,actor_ref) VALUES($1,gen_random_uuid(),'https://x.example.test/h',ARRAY['asset.created.v1'],'t')", tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO messaging.consumer_checkpoints(tenant_id,consumer_name,event_id,state,attempts,applied_at) SELECT tenant_id,'webhook-fanout',event_id,'applied',1,now() FROM messaging.outbox_events"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO messaging.webhook_deliveries(tenant_id,subscription_id,event_id) SELECT $1,subscription_id,$2 FROM messaging.webhook_subscriptions", tenant, held); err != nil {
		t.Fatal(err)
	}
	rep, err := f.registry.RunRetention(f.ctx, policy)
	if err != nil || rep.Events != int64(events-1) {
		t.Fatalf("applied events must be pruned except the one with a pending delivery: %+v %v (events %d)", rep, err, events)
	}
	if count("SELECT count(*) FROM messaging.outbox_events") != 1 || count("SELECT count(*) FROM messaging.outbox_events WHERE event_id='"+held+"'") != 1 {
		t.Fatal("held event must remain")
	}
	if count("SELECT count(*) FROM inventory.observations") != observations || count("SELECT count(*) FROM audit.audit_events") < audits {
		t.Fatal("observations and audit must never be pruned")
	}
	// вне транзакции очистки событие по-прежнему нельзя удалить или изменить
	if _, err = f.pool.Exec(f.ctx, "DELETE FROM messaging.outbox_events"); err == nil {
		t.Fatal("outbox delete outside retention must be refused")
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE messaging.outbox_events SET event_type=event_type"); err == nil {
		t.Fatal("outbox update must be refused")
	}
}
