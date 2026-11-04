package sources

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/jackc/pgx/v5"
)

func (s *MachineService) renewalChallenge(ctx context.Context, tx pgx.Tx, o contracts.Observation) (contracts.Challenge, error) {
	c := contracts.Challenge{Tenant: o.TenantID, Source: o.Origin.SourceID, Generation: o.Origin.GenerationID, Purpose: "cert_renew"}
	var now time.Time
	if e := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return c, e
	}
	_, e := tx.Exec(ctx, `INSERT INTO sources.renewal_challenges(tenant_id,source_id,generation_id,challenge_id,nonce,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, c.Tenant, c.Source, c.Generation, identifier.New(), newGrantToken(), now, now.Add(120*time.Second))
	if e != nil {
		return c, e
	}
	var consumed bool
	e = tx.QueryRow(ctx, `SELECT challenge_id::text,nonce,issued_at,expires_at,consumed FROM sources.renewal_challenges WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3 FOR UPDATE`, c.Tenant, c.Source, c.Generation).Scan(&c.ID, &c.Nonce, &c.Issued, &c.Expires, &consumed)
	if e != nil {
		return c, e
	}
	if consumed || !now.Before(c.Expires) {
		c.ID = identifier.New()
		c.Nonce = newGrantToken()
		c.Issued = now
		c.Expires = now.Add(120 * time.Second)
		_, e = tx.Exec(ctx, `UPDATE sources.renewal_challenges SET challenge_id=$4,nonce=$5,issued_at=$6,expires_at=$7,consumed=false WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3`, c.Tenant, c.Source, c.Generation, c.ID, c.Nonce, c.Issued, c.Expires)
	}
	c.Issued = c.Issued.UTC()
	c.Expires = c.Expires.UTC()
	return c, e
}

// Renew заменяет только TLS key/certificate. Origin signing key/generation и pending evidence сохраняются.
func (s *MachineService) Renew(ctx context.Context, fp string, raw []byte) (contracts.EnrollmentResult, error) {
	var out contracts.EnrollmentResult
	if e := s.Wire.Validate("RenewRequest", raw); e != nil {
		return out, e
	}
	var req contracts.RenewRequest
	_ = json.Unmarshal(raw, &req)
	var payload contracts.Renewal
	_ = json.Unmarshal(req.Payload, &payload)
	if payload.Version.Major != 1 || payload.Version.Minor != 0 {
		return out, domain.Invalid
	}
	canonical, e := wire.Canonical(req.Payload)
	if e != nil {
		return out, e
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != req.Digest {
		return out, domain.Invalid
	}
	csr, _, e := pki.ParseCSR(payload.CSR)
	if e != nil {
		return out, e
	}
	if e = s.rate(ctx, "renew:"+fp, 30); e != nil {
		return out, e
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	// Exclusive source lock serializes issuance/revoke before certificate/network work.
	var state string
	e = tx.QueryRow(ctx, "SELECT state FROM sources.sources WHERE tenant_id=$1 AND source_id=$2 FOR UPDATE", payload.Tenant, payload.Origin.SourceID).Scan(&state)
	if e == pgx.ErrNoRows {
		return out, domain.Unauthorized
	}
	if e != nil {
		return out, e
	}
	if state != "active" {
		return out, domain.Unauthorized
	}
	o, e := s.heartbeatOrigin(ctx, tx, fp, payload.Tenant, payload.Origin.SourceID)
	if e != nil {
		return out, e
	}
	if o.Origin != payload.Origin {
		return out, domain.Unauthorized
	}
	var public []byte
	e = tx.QueryRow(ctx, `SELECT public_key FROM sources.ingest_bindings WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3 AND key_id=$4 AND active LIMIT 1 FOR SHARE`, payload.Tenant, payload.Origin.SourceID, payload.Origin.GenerationID, req.KeyID).Scan(&public)
	if e == pgx.ErrNoRows {
		return out, domain.Unauthorized
	}
	if e != nil {
		return out, e
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(req.Signature)
	if e != nil || len(public) != 32 || !ed25519.Verify(public, append([]byte("SURVEYSCAN-RENEWAL-V1\n"), canonical...), sig) {
		return out, domain.Invalid
	}
	var priorDigest, priorSource, priorGeneration, priorKey string
	var result []byte
	e = tx.QueryRow(ctx, `SELECT digest,source_id::text,generation_id::text,key_id::text,result FROM sources.renewal_receipts WHERE tenant_id=$1 AND renewal_id=$2`, payload.Tenant, payload.ID).Scan(&priorDigest, &priorSource, &priorGeneration, &priorKey, &result)
	if e == nil {
		if priorDigest != req.Digest || priorSource != payload.Origin.SourceID || priorGeneration != payload.Origin.GenerationID || priorKey != req.KeyID {
			return out, domain.Conflict
		}
		if e = json.Unmarshal(result, &out); e != nil {
			return out, e
		}
		return out, tx.Commit(ctx)
	}
	if e != pgx.ErrNoRows {
		return out, e
	}
	var challenge, nonce string
	var expires time.Time
	var consumed bool
	var now time.Time
	e = tx.QueryRow(ctx, `SELECT challenge_id::text,nonce,expires_at,consumed,clock_timestamp() FROM sources.renewal_challenges WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3 FOR UPDATE`, payload.Tenant, payload.Origin.SourceID, payload.Origin.GenerationID).Scan(&challenge, &nonce, &expires, &consumed, &now)
	if e == pgx.ErrNoRows {
		return out, domain.Conflict
	}
	if e != nil {
		return out, e
	}
	if consumed || challenge != payload.Challenge || nonce != payload.Nonce || !now.Before(expires) {
		return out, domain.Conflict
	}
	claims := pki.Claims{Tenant: payload.Tenant, Source: payload.Origin.SourceID, Generation: payload.Origin.GenerationID, Kind: payload.Origin.SourceKind, KeyID: req.KeyID, SigningPublic: public, CenterKeyID: s.CenterKeyID}
	claims.CenterPublic, e = base64.RawURLEncoding.Strict().DecodeString(s.CenterPublicKey)
	if e != nil {
		return out, domain.Invalid
	}
	if claims.Kind == "agent" {
		e = tx.QueryRow(ctx, "SELECT collector_id::text FROM sources.agents WHERE tenant_id=$1 AND source_id=$2", claims.Tenant, claims.Source).Scan(&claims.Collector)
	} else if claims.Kind == "collector" {
		e = tx.QueryRow(ctx, "SELECT collector_id::text FROM sources.collectors WHERE tenant_id=$1 AND source_id=$2", claims.Tenant, claims.Source).Scan(&claims.Collector)
	}
	if e != nil {
		return out, e
	}
	issued, e := s.Issuer.Issue(ctx, csr, claims)
	if e != nil {
		return out, e
	}
	out = contracts.EnrollmentResult{SourceID: claims.Source, GenerationID: claims.Generation, Chain: issued.PEM, Expires: issued.Leaf.NotAfter.UTC(), KeyID: req.KeyID, CenterKeyID: s.CenterKeyID, CenterPublicKey: s.CenterPublicKey}
	result, _ = json.Marshal(out)
	if e = s.Wire.Validate("EnrollmentResult", result); e != nil {
		return out, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO sources.machine_identities(fingerprint,tenant_id,source_id,generation_id,expires_at) VALUES($1,$2,$3,$4,$5)`, pki.Fingerprint(issued.Leaf), claims.Tenant, claims.Source, claims.Generation, out.Expires)
	if e != nil {
		return out, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO sources.renewal_receipts(tenant_id,renewal_id,source_id,generation_id,digest,key_id,result) VALUES($1,$2,$3,$4,$5,$6,$7)`, claims.Tenant, payload.ID, claims.Source, claims.Generation, req.Digest, req.KeyID, result)
	if e != nil {
		return out, e
	}
	_, e = tx.Exec(ctx, `UPDATE sources.renewal_challenges SET consumed=true WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3`, claims.Tenant, claims.Source, claims.Generation)
	if e != nil {
		return out, e
	}
	if e = s.Audit.Record(ctx, tx, claims.Tenant, claims.Source, "source.certificate_renewed", "source", claims.Source); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
