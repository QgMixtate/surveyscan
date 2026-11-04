package sources

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	access "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	audit "github.com/QgMixtate/surveyscan/v2/internal/modules/audit/port"
	sourceport "github.com/QgMixtate/surveyscan/v2/internal/modules/sources/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

var ErrEnrollmentLimit = errors.New("enrollment rate limited")

type MachineService struct {
	Pool                         *pgxpool.Pool
	Auth                         access.Authorizer
	Audit                        audit.Writer
	Issuer                       pki.Issuer
	Wire                         *wire.Validator
	CenterKeyID, CenterPublicKey string
}
type MachineActor = sourceport.Actor

func hashToken(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
func newGrantToken() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic("secure randomness unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func (s *MachineService) rate(ctx context.Context, key string, max int) error {
	var n int
	e := s.Pool.QueryRow(ctx, `INSERT INTO sources.enrollment_buckets(bucket,window_id,attempts) VALUES($1,floor(extract(epoch FROM clock_timestamp())/60)::bigint,1) ON CONFLICT(bucket) DO UPDATE SET window_id=excluded.window_id,attempts=CASE WHEN sources.enrollment_buckets.window_id=excluded.window_id THEN sources.enrollment_buckets.attempts+1 ELSE 1 END RETURNING attempts`, key).Scan(&n)
	if e != nil {
		return e
	}
	if n > max {
		return ErrEnrollmentLimit
	}
	_, e = s.Pool.Exec(ctx, "DELETE FROM sources.enrollment_buckets WHERE window_id<floor(extract(epoch FROM clock_timestamp())/60)::bigint-2")
	return e
}
func (s *MachineService) Grant(ctx context.Context, actor access.Identity, req contracts.EnrollmentGrantRequest) (contracts.EnrollmentGrant, error) {
	raw, _ := json.Marshal(req)
	if e := s.Wire.Validate("EnrollmentGrantRequest", raw); e != nil {
		return contracts.EnrollmentGrant{}, e
	}
	if actor.TenantID != req.TenantID {
		return contracts.EnrollmentGrant{}, domain.Unauthorized
	}
	public, e := base64.RawURLEncoding.Strict().DecodeString(req.PublicKey)
	if e != nil || len(public) != 32 {
		return contracts.EnrollmentGrant{}, domain.Invalid
	}
	if (req.Kind == "agent") != (req.CollectorID != nil) {
		return contracts.EnrollmentGrant{}, domain.Invalid
	}
	if e = s.rate(ctx, "grant:"+actor.UserID, 30); e != nil {
		return contracts.EnrollmentGrant{}, e
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return contracts.EnrollmentGrant{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = s.Auth.Authorize(ctx, tx, actor.CredentialID, actor.TenantID, "sources:admin"); e != nil {
		return contracts.EnrollmentGrant{}, e
	}
	rows, e := tx.Query(ctx, "SELECT scope_id::text FROM scope.network_scopes WHERE tenant_id=$1 AND site_id=$2 ORDER BY scope_id LIMIT 2 FOR SHARE", req.TenantID, req.SiteID)
	if e != nil {
		return contracts.EnrollmentGrant{}, e
	}
	scopes := []string{}
	for rows.Next() {
		var scope string
		if e = rows.Scan(&scope); e != nil {
			rows.Close()
			return contracts.EnrollmentGrant{}, e
		}
		scopes = append(scopes, scope)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return contracts.EnrollmentGrant{}, e
	}
	if len(scopes) != 1 {
		return contracts.EnrollmentGrant{}, domain.Conflict
	}
	if req.CollectorID != nil {
		var active bool
		e = tx.QueryRow(ctx, "SELECT s.state='active' FROM sources.collectors c JOIN sources.sources s USING(tenant_id,source_id) WHERE c.tenant_id=$1 AND c.collector_id=$2 AND s.site_id=$3 FOR SHARE OF c,s", req.TenantID, *req.CollectorID, req.SiteID).Scan(&active)
		if e == pgx.ErrNoRows {
			return contracts.EnrollmentGrant{}, domain.Unauthorized
		}
		if e != nil {
			return contracts.EnrollmentGrant{}, e
		}
		if !active {
			return contracts.EnrollmentGrant{}, domain.Unauthorized
		}
	}
	var exists bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sources.sources WHERE tenant_id=$1 AND source_id=$2)", req.TenantID, req.SourceID).Scan(&exists); e != nil {
		return contracts.EnrollmentGrant{}, e
	}
	if exists {
		return contracts.EnrollmentGrant{}, domain.Conflict
	}
	generation := identifier.New()
	_, e = tx.Exec(ctx, "INSERT INTO sources.sources(tenant_id,source_id,source_kind,site_id,state,generation_id) VALUES($1,$2,$3,$4,'pending',$5)", req.TenantID, req.SourceID, req.Kind, req.SiteID, generation)
	if e != nil {
		return contracts.EnrollmentGrant{}, e
	}
	collector := req.CollectorID
	if req.Kind == "collector" {
		id := identifier.New()
		collector = &id
		_, e = tx.Exec(ctx, "INSERT INTO sources.collectors(tenant_id,collector_id,source_id) VALUES($1,$2,$3)", req.TenantID, id, req.SourceID)
	} else if req.Kind == "agent" {
		_, e = tx.Exec(ctx, "INSERT INTO sources.agents(tenant_id,agent_id,source_id,collector_id) VALUES($1,$2,$3,$4)", req.TenantID, identifier.New(), req.SourceID, *req.CollectorID)
	}
	if e != nil {
		return contracts.EnrollmentGrant{}, e
	}
	result := contracts.EnrollmentGrant{ID: identifier.New(), SourceID: req.SourceID, Token: newGrantToken()}
	e = tx.QueryRow(ctx, "INSERT INTO sources.enrollment_grants(grant_id,tenant_id,source_id,token_hash,csr_sha256,public_key,scope_id,signing_key_id,collector_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()+$10*interval '1 second') RETURNING expires_at", result.ID, req.TenantID, req.SourceID, hashToken(result.Token), req.CSRHash, public, scopes[0], identifier.New(), collector, req.TTL).Scan(&result.Expires)
	if e != nil {
		return result, e
	}
	result.Expires = result.Expires.UTC()
	if e = s.Audit.Record(ctx, tx, req.TenantID, actor.UserID, "source.enrollment_granted", "source", req.SourceID); e != nil {
		return result, e
	}
	return result, tx.Commit(ctx)
}
func (s *MachineService) Enroll(ctx context.Context, token string, req contracts.EnrollmentRequest) (contracts.EnrollmentResult, error) {
	raw, _ := json.Marshal(req)
	if e := s.Wire.Validate("EnrollmentRequest", raw); e != nil {
		return contracts.EnrollmentResult{}, e
	}
	if len(token) != 43 {
		return contracts.EnrollmentResult{}, domain.Unauthorized
	}
	if e := s.rate(ctx, "all", 120); e != nil {
		return contracts.EnrollmentResult{}, e
	}
	if e := s.rate(ctx, "token:"+hashToken(token), 10); e != nil {
		return contracts.EnrollmentResult{}, e
	}
	csr, csrHash, e := pki.ParseCSR(req.CSR)
	if e != nil {
		return contracts.EnrollmentResult{}, e
	}
	public, e := base64.RawURLEncoding.Strict().DecodeString(req.PublicKey)
	if e != nil || len(public) != 32 {
		return contracts.EnrollmentResult{}, domain.Invalid
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return contracts.EnrollmentResult{}, e
	}
	defer tx.Rollback(ctx)
	// Source → grant → identity: тот же порядок, что при отзыве.
	var tenant string
	e = tx.QueryRow(ctx, "SELECT tenant_id::text FROM sources.enrollment_grants WHERE grant_id=$1 AND source_id=$2 AND token_hash=$3", req.GrantID, req.SourceID, hashToken(token)).Scan(&tenant)
	if e == pgx.ErrNoRows {
		return contracts.EnrollmentResult{}, domain.Unauthorized
	}
	if e != nil {
		return contracts.EnrollmentResult{}, e
	}
	var kind, site, generation, state string
	e = tx.QueryRow(ctx, "SELECT source_kind,site_id::text,generation_id::text,state FROM sources.sources WHERE tenant_id=$1 AND source_id=$2 FOR UPDATE", tenant, req.SourceID).Scan(&kind, &site, &generation, &state)
	if e != nil {
		return contracts.EnrollmentResult{}, e
	}
	if state == "revoked" || state == "disabled" {
		return contracts.EnrollmentResult{}, domain.Unauthorized
	}
	var expectedCSR, scope, key string
	var expectedPublic []byte
	var collector *string
	var previous []byte
	var expires time.Time
	e = tx.QueryRow(ctx, "SELECT csr_sha256,public_key,scope_id::text,signing_key_id::text,collector_id::text,expires_at,result FROM sources.enrollment_grants WHERE grant_id=$1 AND token_hash=$2 FOR UPDATE", req.GrantID, hashToken(token)).Scan(&expectedCSR, &expectedPublic, &scope, &key, &collector, &expires, &previous)
	if e != nil {
		return contracts.EnrollmentResult{}, e
	}
	var live bool
	if e = tx.QueryRow(ctx, "SELECT $1::timestamptz>clock_timestamp()", expires).Scan(&live); e != nil {
		return contracts.EnrollmentResult{}, e
	}
	if !live || expectedCSR != csrHash || !equalBytes(expectedPublic, public) {
		return contracts.EnrollmentResult{}, domain.Unauthorized
	}
	if len(previous) > 0 {
		var result contracts.EnrollmentResult
		if e = json.Unmarshal(previous, &result); e != nil {
			return result, e
		}
		return result, nil
	}
	var activeTenant bool
	if e = tx.QueryRow(ctx, "SELECT status='active' FROM access.tenants WHERE tenant_id=$1 FOR SHARE", tenant).Scan(&activeTenant); e != nil {
		return contracts.EnrollmentResult{}, e
	}
	if !activeTenant {
		return contracts.EnrollmentResult{}, domain.Unauthorized
	}
	claims := pki.Claims{Tenant: tenant, Source: req.SourceID, Generation: generation, Kind: kind, KeyID: key, SigningPublic: public}
	if collector != nil {
		claims.Collector = *collector
	}
	claims.CenterKeyID = s.CenterKeyID
	claims.CenterPublic, e = base64.RawURLEncoding.Strict().DecodeString(s.CenterPublicKey)
	if e != nil {
		return contracts.EnrollmentResult{}, domain.Invalid
	}
	issued, e := s.Issuer.Issue(ctx, csr, claims)
	if e != nil {
		return contracts.EnrollmentResult{}, e
	}
	result := contracts.EnrollmentResult{SourceID: req.SourceID, GenerationID: generation, Chain: issued.PEM, Expires: issued.Leaf.NotAfter.UTC(), KeyID: key, CenterKeyID: s.CenterKeyID, CenterPublicKey: s.CenterPublicKey}
	body, _ := json.Marshal(result)
	if e = s.Wire.Validate("EnrollmentResult", body); e != nil {
		return result, e
	}
	_, e = tx.Exec(ctx, "INSERT INTO sources.machine_identities(fingerprint,tenant_id,source_id,generation_id,expires_at) VALUES($1,$2,$3,$4,$5)", pki.Fingerprint(issued.Leaf), tenant, req.SourceID, generation, result.Expires)
	if e != nil {
		return result, e
	}
	_, e = tx.Exec(ctx, "INSERT INTO sources.ingest_bindings(tenant_id,source_id,generation_id,key_id,namespace,scope_id,public_key) VALUES($1,$2,$3,$4,'host',$5,$6)", tenant, req.SourceID, generation, key, scope, public)
	if e != nil {
		return result, e
	}
	_, e = tx.Exec(ctx, "UPDATE sources.sources SET state='active',revision=revision+1 WHERE tenant_id=$1 AND source_id=$2", tenant, req.SourceID)
	if e != nil {
		return result, e
	}
	_, e = tx.Exec(ctx, "UPDATE sources.enrollment_grants SET result=$2 WHERE grant_id=$1", req.GrantID, body)
	if e != nil {
		return result, e
	}
	if e = s.Audit.Record(ctx, tx, tenant, req.SourceID, "source.enrolled", "source", req.SourceID); e != nil {
		return result, e
	}
	return result, tx.Commit(ctx)
}
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (s *MachineService) Peer(ctx context.Context, tx pgx.Tx, certificate *x509.Certificate) (MachineActor, error) {
	if certificate == nil {
		return MachineActor{}, domain.Unauthorized
	}
	return s.PeerFingerprint(ctx, tx, pki.Fingerprint(certificate))
}

// Fingerprint приходит из уже проверенного TLS transport, не пользовательского header.
func (s *MachineService) PeerFingerprint(ctx context.Context, tx pgx.Tx, fingerprint string) (MachineActor, error) {
	var result MachineActor
	result.Fingerprint = fingerprint
	var source, tenant string
	e := tx.QueryRow(ctx, "SELECT source_id::text,tenant_id::text FROM sources.machine_identities WHERE fingerprint=$1", fingerprint).Scan(&source, &tenant)
	if e == pgx.ErrNoRows {
		return result, domain.Unauthorized
	}
	if e != nil {
		return result, e
	}
	var state string
	e = tx.QueryRow(ctx, "SELECT tenant_id::text,source_id::text,generation_id::text,site_id::text,source_kind,state FROM sources.sources WHERE tenant_id=$1 AND source_id=$2 FOR SHARE", tenant, source).Scan(&result.Tenant, &result.Source, &result.Generation, &result.Site, &result.Kind, &state)
	if e != nil {
		return result, e
	}
	if state != "active" {
		return result, domain.Unauthorized
	}
	var valid bool
	e = tx.QueryRow(ctx, "SELECT NOT revoked AND expires_at>clock_timestamp() AND generation_id=$2 FROM sources.machine_identities WHERE fingerprint=$1 FOR SHARE", fingerprint, result.Generation).Scan(&valid)
	if e != nil {
		return result, e
	}
	if !valid {
		return result, domain.Unauthorized
	}
	e = tx.QueryRow(ctx, "SELECT status='active' FROM access.tenants WHERE tenant_id=$1 FOR SHARE", tenant).Scan(&valid)
	if e != nil {
		return result, e
	}
	if !valid {
		return result, domain.Unauthorized
	}
	if result.Kind == "collector" {
		e = tx.QueryRow(ctx, "SELECT collector_id::text FROM sources.collectors WHERE tenant_id=$1 AND source_id=$2 FOR SHARE", tenant, source).Scan(&result.Collector)
	} else if result.Kind == "agent" {
		e = tx.QueryRow(ctx, "SELECT collector_id::text FROM sources.agents WHERE tenant_id=$1 AND source_id=$2 FOR SHARE", tenant, source).Scan(&result.Collector)
	}
	return result, e
}
func (s *MachineService) AllowOrigin(ctx context.Context, tx pgx.Tx, fingerprint string, o contracts.Observation) error {
	return s.allowOrigin(ctx, tx, fingerprint, o, false)
}

// AllowRecordedOrigin разрешает только чтение уже committed доказательства; новый ingest всё равно требует active binding.
func (s *MachineService) AllowRecordedOrigin(ctx context.Context, tx pgx.Tx, fingerprint string, o contracts.Observation) error {
	return s.allowOrigin(ctx, tx, fingerprint, o, true)
}
func (s *MachineService) allowOrigin(ctx context.Context, tx pgx.Tx, fingerprint string, o contracts.Observation, recorded bool) error {
	actor, e := s.PeerFingerprint(ctx, tx, fingerprint)
	if e != nil {
		return e
	}
	if actor.Tenant != o.TenantID || actor.Site != o.Scope.SiteID {
		return domain.Unauthorized
	}
	if actor.Source == o.Origin.SourceID {
		if actor.Generation != o.Origin.GenerationID || actor.Kind != o.Origin.SourceKind {
			return domain.Unauthorized
		}
		return nil
	}
	if actor.Kind != "collector" || actor.Collector == nil || o.Origin.SourceKind != "agent" {
		return domain.Unauthorized
	}
	var valid bool
	e = tx.QueryRow(ctx, "SELECT ($6 OR s.state='active') AND s.generation_id=$4 AND s.site_id=$5 FROM sources.agents a JOIN sources.sources s USING(tenant_id,source_id) WHERE a.tenant_id=$1 AND a.source_id=$2 AND a.collector_id=$3 FOR SHARE OF s,a", actor.Tenant, o.Origin.SourceID, *actor.Collector, o.Origin.GenerationID, o.Scope.SiteID, recorded).Scan(&valid)
	if e == pgx.ErrNoRows {
		return domain.Unauthorized
	}
	if e != nil {
		return e
	}
	if !valid {
		return domain.Unauthorized
	}
	return nil
}
func (s *MachineService) Revoke(ctx context.Context, actor access.Identity, source string) error {
	if !identifier.Valid(source) {
		return domain.Invalid
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = s.Auth.Authorize(ctx, tx, actor.CredentialID, actor.TenantID, "sources:admin"); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, "UPDATE sources.sources SET state='revoked',revision=revision+1 WHERE tenant_id=$1 AND source_id=$2", actor.TenantID, source)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return domain.NotFound
	}
	if _, e = tx.Exec(ctx, "UPDATE sources.machine_identities SET revoked=true WHERE tenant_id=$1 AND source_id=$2", actor.TenantID, source); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE sources.ingest_bindings SET active=false WHERE tenant_id=$1 AND source_id=$2", actor.TenantID, source); e != nil {
		return e
	}
	if e = s.Audit.Record(ctx, tx, actor.TenantID, actor.UserID, "source.revoked", "source", source); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s *MachineService) viewTx(ctx context.Context, tx pgx.Tx, tenant, id string) (contracts.Source, error) {
	var out contracts.Source
	e := tx.QueryRow(ctx, "SELECT tenant_id::text,source_id::text,source_kind,site_id::text,state,GREATEST(last_contact_at,(SELECT max(h.last_contact_at) FROM sources.heartbeat_state h WHERE h.tenant_id=sources.sources.tenant_id AND h.source_id=sources.sources.source_id AND h.generation_id=sources.sources.generation_id)),GREATEST(last_successful_inventory_at,(SELECT p.last_successful_inventory_at FROM sources.inventory_progress p WHERE p.tenant_id=sources.sources.tenant_id AND p.source_id=sources.sources.source_id AND p.generation_id=sources.sources.generation_id)) FROM sources.sources WHERE tenant_id=$1 AND source_id=$2", tenant, id).Scan(&out.TenantID, &out.SourceID, &out.Kind, &out.SiteID, &out.State, &out.LastContact, &out.LastInventory)
	if e == pgx.ErrNoRows {
		e = domain.NotFound
	}
	if out.LastContact != nil {
		v := out.LastContact.UTC()
		out.LastContact = &v
	}
	if out.LastInventory != nil {
		v := out.LastInventory.UTC()
		out.LastInventory = &v
	}
	return out, e
}
func (s *MachineService) View(ctx context.Context, actor access.Identity, id string) (contracts.Source, error) {
	if !identifier.Valid(id) {
		return contracts.Source{}, domain.NotFound
	}
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return contracts.Source{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = s.Auth.Authorize(ctx, tx, actor.CredentialID, actor.TenantID, "sources:read"); e != nil {
		return contracts.Source{}, e
	}
	result, e := s.viewTx(ctx, tx, actor.TenantID, id)
	if e != nil {
		return result, e
	}
	return result, tx.Commit(ctx)
}
func (s *MachineService) List(ctx context.Context, actor access.Identity, after string, limit int) (contracts.SourcePage, error) {
	page := contracts.SourcePage{Items: []contracts.Source{}}
	if limit < 1 || limit > 200 || after != "" && !identifier.Valid(after) {
		return page, domain.Invalid
	}
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		return page, e
	}
	defer tx.Rollback(ctx)
	if _, e = s.Auth.Authorize(ctx, tx, actor.CredentialID, actor.TenantID, "sources:read"); e != nil {
		return page, e
	}
	rows, e := tx.Query(ctx, "SELECT source_id::text FROM sources.sources WHERE tenant_id=$1 AND ($2='' OR source_id>NULLIF($2,'')::uuid) ORDER BY source_id LIMIT $3", actor.TenantID, after, limit+1)
	if e != nil {
		return page, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return page, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return page, e
	}
	if len(ids) > limit {
		ids = ids[:limit]
		b, _ := json.Marshal([]string{actor.TenantID, ids[len(ids)-1]})
		cursor := base64.RawURLEncoding.EncodeToString(b)
		page.NextCursor = &cursor
	}
	for _, id := range ids {
		item, e := s.viewTx(ctx, tx, actor.TenantID, id)
		if e != nil {
			return page, e
		}
		page.Items = append(page.Items, item)
	}
	return page, tx.Commit(ctx)
}
func (s *MachineService) Config(ctx context.Context, fingerprint string) (contracts.MachineConfig, error) {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return contracts.MachineConfig{}, e
	}
	defer tx.Rollback(ctx)
	actor, e := s.PeerFingerprint(ctx, tx, fingerprint)
	if e != nil {
		return contracts.MachineConfig{}, e
	}
	result, _, e := s.configTx(ctx, tx, actor.Tenant, actor.Source)
	if e != nil {
		return result, e
	}
	return result, tx.Commit(ctx)
}
