package sources

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/jackc/pgx/v5"
)

func (s *MachineService) heartbeatOrigin(ctx context.Context, tx pgx.Tx, fp, tenant, source string) (contracts.Observation, error) {
	o := contracts.Observation{TenantID: tenant}
	e := tx.QueryRow(ctx, "SELECT source_id::text,source_kind,generation_id::text,site_id::text FROM sources.sources WHERE tenant_id=$1 AND source_id=$2 AND state='active'", tenant, source).Scan(&o.Origin.SourceID, &o.Origin.SourceKind, &o.Origin.GenerationID, &o.Scope.SiteID)
	if e == pgx.ErrNoRows {
		return o, domain.Unauthorized
	}
	if e != nil {
		return o, e
	}
	return o, s.AllowOrigin(ctx, tx, fp, o)
}
func (s *MachineService) Challenges(ctx context.Context, fp string, req contracts.ChallengeRequest) (contracts.ChallengeResponse, error) {
	out := contracts.ChallengeResponse{Challenges: []contracts.Challenge{}}
	raw, _ := json.Marshal(req)
	if e := s.Wire.Validate("ChallengeRequest", raw); e != nil {
		return out, e
	}
	if req.Purpose != "heartbeat" {
		return out, domain.Invalid
	}
	if e := s.rate(ctx, "challenge:"+fp, 60); e != nil {
		return out, e
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	actor, e := s.PeerFingerprint(ctx, tx, fp)
	if e != nil {
		return out, e
	}
	ids := append([]string(nil), req.Sources...)
	sort.Strings(ids)
	for i, id := range ids {
		if i > 0 && id == ids[i-1] {
			return out, domain.Invalid
		}
		o, e := s.heartbeatOrigin(ctx, tx, fp, actor.Tenant, id)
		if e != nil {
			return out, e
		}
		var now time.Time
		if e = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
			return out, e
		}
		now = now.UTC()
		_, e = tx.Exec(ctx, `INSERT INTO sources.heartbeat_state(tenant_id,source_id,generation_id,challenge_id,nonce,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, actor.Tenant, id, o.Origin.GenerationID, identifier.New(), newGrantToken(), now, now.Add(120*time.Second))
		if e != nil {
			return out, e
		}
		c := contracts.Challenge{Tenant: actor.Tenant, Source: id, Generation: o.Origin.GenerationID, Purpose: "heartbeat"}
		var consumed bool
		e = tx.QueryRow(ctx, `SELECT challenge_id::text,nonce,issued_at,expires_at,consumed FROM sources.heartbeat_state WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3 FOR UPDATE`, c.Tenant, c.Source, c.Generation).Scan(&c.ID, &c.Nonce, &c.Issued, &c.Expires, &consumed)
		if e != nil {
			return out, e
		}
		if consumed || !now.Before(c.Expires) {
			c.ID = identifier.New()
			c.Nonce = newGrantToken()
			c.Issued = now
			c.Expires = now.Add(120 * time.Second)
			_, e = tx.Exec(ctx, `UPDATE sources.heartbeat_state SET challenge_id=$4,nonce=$5,issued_at=$6,expires_at=$7,consumed=false WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3`, c.Tenant, c.Source, c.Generation, c.ID, c.Nonce, c.Issued, c.Expires)
			if e != nil {
				return out, e
			}
		}
		c.Issued = c.Issued.UTC()
		c.Expires = c.Expires.UTC()
		out.Challenges = append(out.Challenges, c)
	}
	return out, tx.Commit(ctx)
}
func (s *MachineService) Heartbeat(ctx context.Context, fp string, raw []byte) (contracts.HeartbeatResult, error) {
	var out contracts.HeartbeatResult
	if e := s.Wire.Validate("SignedHeartbeat", raw); e != nil {
		return out, e
	}
	var signed contracts.SignedHeartbeat
	_ = json.Unmarshal(raw, &signed)
	var h contracts.Heartbeat
	_ = json.Unmarshal(signed.Payload, &h)
	if h.Version.Major != 1 || h.Version.Minor != 0 {
		return out, domain.Invalid
	}
	canonical, e := wire.Canonical(signed.Payload)
	if e != nil {
		return out, e
	}
	sum := sha256.Sum256(canonical)
	if signed.Digest != hex.EncodeToString(sum[:]) {
		return out, domain.Invalid
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	o, e := s.heartbeatOrigin(ctx, tx, fp, h.Tenant, h.Origin.SourceID)
	if e != nil {
		return out, e
	}
	if o.Origin != h.Origin {
		return out, domain.Unauthorized
	}
	var public []byte
	e = tx.QueryRow(ctx, `SELECT public_key FROM sources.ingest_bindings WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3 AND key_id=$4 AND active LIMIT 1 FOR SHARE`, h.Tenant, h.Origin.SourceID, h.Origin.GenerationID, signed.KeyID).Scan(&public)
	if e == pgx.ErrNoRows {
		return out, domain.Unauthorized
	}
	if e != nil {
		return out, e
	}
	signature, e := base64.RawURLEncoding.Strict().DecodeString(signed.Signature)
	if e != nil || len(public) != 32 || !ed25519.Verify(public, append([]byte("SURVEYSCAN-HEARTBEAT-V1\n"), canonical...), signature) {
		return out, domain.Invalid
	}
	// State row сериализует consume/sequence; source остаётся locked против revoke.
	var challenge, nonce string
	var expires time.Time
	var consumed bool
	var sequence *string
	e = tx.QueryRow(ctx, `SELECT challenge_id::text,nonce,expires_at,consumed,last_sequence::text FROM sources.heartbeat_state WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3 FOR UPDATE`, h.Tenant, h.Origin.SourceID, h.Origin.GenerationID).Scan(&challenge, &nonce, &expires, &consumed, &sequence)
	if e == pgx.ErrNoRows {
		return out, domain.Conflict
	}
	if e != nil {
		return out, e
	}
	var priorDigest, priorSource, priorGeneration string
	var result []byte
	e = tx.QueryRow(ctx, `SELECT digest,source_id::text,generation_id::text,result FROM sources.heartbeat_receipts WHERE tenant_id=$1 AND heartbeat_id=$2`, h.Tenant, h.ID).Scan(&priorDigest, &priorSource, &priorGeneration, &result)
	if e == nil {
		if priorDigest != signed.Digest || priorSource != h.Origin.SourceID || priorGeneration != h.Origin.GenerationID {
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
	var now time.Time
	if e = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return out, e
	}
	now = now.UTC()
	if consumed || challenge != h.Challenge || nonce != h.Nonce || !now.Before(expires) {
		return out, domain.Conflict
	}
	if sequence != nil {
		var greater bool
		if e = tx.QueryRow(ctx, "SELECT $1::numeric>$2::numeric", h.Sequence, *sequence).Scan(&greater); e != nil {
			return out, e
		}
		if !greater {
			return out, domain.Conflict
		}
	}
	out = contracts.HeartbeatResult{ID: h.ID, Accepted: now, LastContact: now, Request: identifier.New()}
	result, _ = json.Marshal(out)
	_, e = tx.Exec(ctx, `INSERT INTO sources.heartbeat_receipts(tenant_id,heartbeat_id,source_id,generation_id,digest,sequence,result) VALUES($1,$2,$3,$4,$5,$6,$7)`, h.Tenant, h.ID, h.Origin.SourceID, h.Origin.GenerationID, signed.Digest, h.Sequence, result)
	if e != nil {
		return out, e
	}
	_, e = tx.Exec(ctx, `UPDATE sources.heartbeat_state SET consumed=true,last_sequence=$4,last_contact_at=$5 WHERE tenant_id=$1 AND source_id=$2 AND generation_id=$3`, h.Tenant, h.Origin.SourceID, h.Origin.GenerationID, h.Sequence, now)
	if e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
