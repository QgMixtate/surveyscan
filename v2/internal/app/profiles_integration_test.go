//go:build integration

package app_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/sourceprofile"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func profileRequest(t *testing.T, u *uploadFixture, applied *string) contracts.ProfileFrame {
	t.Helper()
	p := contracts.ProfileRequestPayload{Version: contracts.Version{Major: 1}, Tenant: tenant, Origin: u.observation("1").Origin, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Sent: time.Now().UTC(), Applied: applied}
	frame, e := sourceprofile.SignRequest(p, u.f.keyID, u.f.key)
	if e != nil {
		t.Fatal(e)
	}
	return frame
}
func TestC12ProfileConcurrentRevisionAuditAndOutbox(t *testing.T) {
	u := uploadSetup(t)
	initial, e := u.sources.Profile(u.f.ctx, u.f.identity, u.source)
	if e != nil || initial.Managed || initial.Config.Revision != "1" {
		t.Fatal(initial, e)
	}
	options := contracts.ProfileOptions{Heartbeat: 30, Inventory: 900, SpoolBytes: 1048576}
	var successes atomic.Int32
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, e := u.sources.UpdateProfile(u.f.ctx, u.f.identity, u.source, "1", options)
			if e == nil {
				successes.Add(1)
				if p.Config.Revision != "2" {
					errs <- errors.New("profile revision skipped")
				}
			} else if !errors.Is(e, domain.Revision) {
				errs <- e
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if successes.Load() != 1 {
		t.Fatal("concurrent stale writes committed", successes.Load())
	}
	var n int
	for _, query := range []string{"SELECT count(*) FROM messaging.outbox_events WHERE event_type='source.profile_updated.v1'", "SELECT count(*) FROM audit.audit_events WHERE action='source.profile_updated'"} {
		if e = u.f.pool.QueryRow(u.f.ctx, query).Scan(&n); e != nil || n != 1 {
			t.Fatal("profile event/audit not atomic", n, e)
		}
	}
	options.Inventory = 60
	if _, e = u.sources.UpdateProfile(u.f.ctx, u.f.identity, u.source, "2", options); !errors.Is(e, domain.Invalid) {
		t.Fatal("collector unsupported autonomous inventory interval accepted", e)
	}
}
func TestC12ProfileOriginProofAckAndFreshnessIsolation(t *testing.T) {
	u := uploadSetup(t)
	options := contracts.ProfileOptions{Heartbeat: 30, Inventory: 900, SpoolBytes: 1048576}
	if _, e := u.sources.UpdateProfile(u.f.ctx, u.f.identity, u.source, "1", options); e != nil {
		t.Fatal(e)
	}
	revision := "2"
	frame := profileRequest(t, u, &revision)
	out, e := u.sources.PollProfile(u.f.ctx, u.fingerprint, frame)
	if e != nil || !out.Managed || out.Config.Revision != "2" {
		t.Fatal(out, e)
	}
	view, e := u.sources.Profile(u.f.ctx, u.f.identity, u.source)
	if e != nil || view.Applied == nil || *view.Applied != "2" || view.LastConfigContact == nil || view.LastContact != nil || view.LastInventory != nil {
		t.Fatal("config poll fabricated heartbeat/inventory freshness", view, e)
	}
	future := "3"
	if _, e = u.sources.PollProfile(u.f.ctx, u.fingerprint, profileRequest(t, u, &future)); !errors.Is(e, domain.Invalid) {
		t.Fatal("future revision ACK accepted", e)
	}
	var req contracts.ProfileRequestPayload
	_ = json.Unmarshal(frame.Payload, &req)
	req.Sent = time.Now().Add(-3 * time.Minute)
	expired, _ := sourceprofile.SignRequest(req, u.f.keyID, u.f.key)
	if _, e = u.sources.PollProfile(u.f.ctx, u.fingerprint, expired); !errors.Is(e, domain.Invalid) {
		t.Fatal("expired profile request accepted", e)
	}
	frame.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(u.f.key, []byte("wrong-domain")))
	if _, e = u.sources.PollProfile(u.f.ctx, u.fingerprint, frame); !errors.Is(e, domain.Invalid) {
		t.Fatal("courier forged application status", e)
	}
	if e = u.sources.Revoke(u.f.ctx, u.f.identity, u.source); e != nil {
		t.Fatal(e)
	}
	if _, e = u.sources.PollProfile(u.f.ctx, u.fingerprint, profileRequest(t, u, &revision)); !errors.Is(e, domain.Unauthorized) {
		t.Fatal("revoked source polled", e)
	}
	count(t, u.f, "assets.assets", 0)
}
func TestC12ProfileTenantViewerAndRevokedWriteIsolation(t *testing.T) {
	u := uploadSetup(t)
	options := contracts.ProfileOptions{Heartbeat: 30, Inventory: 900, SpoolBytes: 1048576}
	if e := u.f.users.Provision(u.f.ctx, false, tenant, "", "profile-viewer", password, "viewer"); e != nil {
		t.Fatal(e)
	}
	session, cookie, e := u.f.users.Login(u.f.ctx, "profile-viewer", password)
	if e != nil {
		t.Fatal(e)
	}
	viewer, e := u.f.users.Authenticate(u.f.ctx, cookie, "session", session.CSRFToken, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = u.sources.Profile(u.f.ctx, viewer, u.source); e != nil {
		t.Fatal(e)
	}
	if _, e = u.sources.UpdateProfile(u.f.ctx, viewer, u.source, "1", options); !errors.Is(e, access.ErrForbidden) {
		t.Fatal("viewer changed source profile", e)
	}
	foreign := u.f.identity
	foreign.TenantID = identifier.New()
	if _, e = u.sources.Profile(u.f.ctx, foreign, u.source); e == nil {
		t.Fatal("credential tenant replaced")
	}
	if e = u.sources.Revoke(u.f.ctx, u.f.identity, u.source); e != nil {
		t.Fatal(e)
	}
	if _, e = u.sources.UpdateProfile(u.f.ctx, u.f.identity, u.source, "1", options); !errors.Is(e, domain.Conflict) {
		t.Fatal("revoked source profile changed", e)
	}
	count(t, u.f, "sources.profiles", 0)
}

func TestC12DiagnosticsSignedRuntimeAndTenantQueues(t *testing.T) {
	u := uploadSetup(t)
	frame := profileRequest(t, u, nil)
	var req contracts.ProfileRequestPayload
	_ = json.Unmarshal(frame.Payload, &req)
	disk := int64(123456789)
	oldest := time.Now().UTC().Add(-10 * time.Minute)
	req.Version.Minor = 1
	req.Diagnostics = &contracts.RuntimeDiagnostics{Collected: time.Now().UTC(), PendingFiles: 6, PendingBytes: 1024, OldestPending: &oldest, DiskAvailable: &disk, CertificateExpires: time.Now().UTC().Add(30 * time.Minute)}
	frame, e := sourceprofile.SignRequest(req, u.f.keyID, u.f.key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = u.sources.PollProfile(u.f.ctx, u.fingerprint, frame); e != nil {
		t.Fatal(e)
	}
	diagnostic, e := u.sources.Diagnostics(u.f.ctx, u.f.identity)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, item := range diagnostic {
		if item.Source == u.source {
			found = true
			if item.Reported == nil || item.Reported.PendingFiles != 6 || item.HeartbeatAge != nil || item.InventoryAge != nil {
				t.Fatal("diagnostics fabricated inventory/HB", item)
			}
		}
	}
	if !found {
		t.Fatal("origin runtime diagnostics missing")
	}
	batch, raw := u.batch(t, u.observation("1"))
	if _, e = u.service.Stage(u.f.ctx, u.fingerprint, raw); e != nil {
		t.Fatal(e)
	}
	queues, e := u.service.Diagnostics(u.f.ctx, tenant)
	if e != nil || queues.Pending != 1 || queues.PendingBytes == 0 || queues.OldestAge == nil {
		t.Fatal(queues, e)
	}
	otherTenant := identifier.New()
	if _, e = u.f.pool.Exec(u.f.ctx, "INSERT INTO access.tenants(tenant_id,name,status) VALUES($1,'diagnostics other','active')", otherTenant); e != nil {
		t.Fatal(e)
	}
	if e = u.f.users.Provision(u.f.ctx, false, otherTenant, "", "diagnostics-other", password, "viewer"); e != nil {
		t.Fatal(e)
	}
	session, cookie, e := u.f.users.Login(u.f.ctx, "diagnostics-other", password)
	if e != nil {
		t.Fatal(e)
	}
	actor, e := u.f.users.Authenticate(u.f.ctx, cookie, "session", session.CSRFToken, true)
	if e != nil {
		t.Fatal(e)
	}
	empty, e := u.sources.Diagnostics(u.f.ctx, actor)
	if e != nil || len(empty) != 0 {
		t.Fatal("foreign tenant saw source diagnostics", e)
	}
	queues, e = u.service.Diagnostics(u.f.ctx, otherTenant)
	if e != nil || queues.Pending != 0 || queues.OldestAge != nil {
		t.Fatal("foreign tenant saw pending payload", queues, e)
	}
	if _, e = u.service.Process(u.f.ctx, u.fingerprint, batch.DeliveryID); e != nil {
		t.Fatal(e)
	}
	queues, e = u.service.Diagnostics(u.f.ctx, tenant)
	if e != nil || queues.Pending != 0 || queues.PendingBytes != 0 || queues.OldestAge != nil {
		t.Fatal("committed payload GC remained in queue metrics", queues, e)
	}
}
