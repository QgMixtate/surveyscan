package assets

import (
	"context"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/jackc/pgx/v5"
	"net"
	"net/netip"
	"sort"
	"strings"
)

type Store struct{}
type Resolution struct {
	RecordKey        string
	AssetID          string
	Created, Pending bool
	Reason           string
	// AutoMatched — запись привязана к существующему активу по единственному надёжному сильному
	// идентификатору (C25.01, вариант Б); вызывающий фиксирует аудит и историю актива.
	AutoMatched bool
}

// strongKind — сильные идентификаторы (C25.01 §1). IP/MAC/hostname — слабые и никогда не склеивают.
func strongKind(kind string) bool {
	return kind == "machine_uuid" || kind == "bios_uuid" || kind == "serial"
}

// placeholder — известные заглушки сильных идентификаторов (C25.01 §2): для авто-сведения не используются.
func placeholder(c contracts.Candidate) bool {
	v := strings.ToLower(strings.TrimSpace(c.Value))
	switch c.Kind {
	case "serial":
		switch v {
		case "", "0", "00000000", "none", "n/a", "na", "null", "default string", "to be filled by o.e.m.", "to be filled by oem", "system serial number", "not specified", "not applicable", "123456789", "0123456789", "chassis serial number", "invalid":
			return true
		}
		return len(strings.Trim(v, "0")) == 0
	case "bios_uuid", "machine_uuid":
		switch v {
		case "00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff", "03000200-0400-0500-0006-000700080009":
			return true
		}
	}
	return false
}

func Normalize(c contracts.Candidate) (contracts.Candidate, error) {
	c.Value = strings.TrimSpace(c.Value)
	if c.Value == "" {
		return c, domain.Invalid
	}
	switch c.Kind {
	case "hostname":
		c.Value = strings.ToLower(strings.TrimSuffix(c.Value, "."))
	case "machine_uuid", "bios_uuid":
		if !identifier.Valid(c.Value) {
			return c, domain.Invalid
		}
		c.Value = strings.ToLower(c.Value)
	case "ipv4", "ipv6":
		a, e := netip.ParseAddr(c.Value)
		if e != nil || c.Kind == "ipv4" && !a.Is4() || c.Kind == "ipv6" && !a.Is6() {
			return c, domain.Invalid
		}
		c.Value = a.String()
	case "mac":
		a, e := net.ParseMAC(c.Value)
		if e != nil || len(a) != 6 {
			return c, domain.Invalid
		}
		c.Value = a.String()
	case "serial":
	default:
		return c, domain.Invalid
	}
	return c, nil
}
func (Store) Resolve(ctx context.Context, tx pgx.Tx, o contracts.Observation) (Resolution, error) {
	var result Resolution
	var uid *string
	var state string
	e := tx.QueryRow(ctx, "SELECT source_record_key::text,asset_uid::text,resolution_state FROM assets.source_records WHERE tenant_id=$1 AND source_id=$2 AND namespace=$3 AND source_local_id=$4 FOR UPDATE", o.TenantID, o.Origin.SourceID, o.Record.Namespace, o.Record.LocalID).Scan(&result.RecordKey, &uid, &state)
	fresh := errors.Is(e, pgx.ErrNoRows)
	if e != nil && !fresh {
		return result, e
	}
	if fresh {
		result.RecordKey = identifier.New()
		_, e = tx.Exec(ctx, "INSERT INTO assets.source_records(tenant_id,source_record_key,source_id,namespace,source_local_id,resolution_state) VALUES($1,$2,$3,$4,$5,'unresolved')", o.TenantID, result.RecordKey, o.Origin.SourceID, o.Record.Namespace, o.Record.LocalID)
		if e != nil {
			return result, e
		}
	}
	scopeConflict := false
	if o.Asserted != nil && (uid == nil || *uid != *o.Asserted) {
		return result, domain.Unauthorized
	}
	if uid != nil {
		result.AssetID = *uid
		var scope string
		if e = tx.QueryRow(ctx, "SELECT scope_id::text FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2", o.TenantID, *uid).Scan(&scope); e != nil {
			return result, e
		}
		if scope != o.Scope.ScopeID {
			scopeConflict = true
		}
	}
	hits := map[string]bool{}
	strongHits := map[string]bool{} // активы, совпавшие по надёжному сильному идентификатору
	conflict := (!fresh && uid == nil) || scopeConflict
	normalized := []contracts.Candidate{}
	for _, candidate := range o.Candidates {
		c, e := Normalize(candidate)
		if e != nil {
			return result, e
		}
		normalized = append(normalized, c)
		rows, e := tx.Query(ctx, `SELECT DISTINCT i.asset_uid::text FROM assets.asset_identifiers i JOIN assets.assets a USING(tenant_id,asset_uid) WHERE i.tenant_id=$1 AND a.scope_id=$2 AND i.kind=$3 AND i.namespace=$4 AND i.normalized_value=$5 AND i.valid_to IS NULL ORDER BY i.asset_uid::text LIMIT 17`, o.TenantID, o.Scope.ScopeID, c.Kind, c.Namespace, c.Value)
		if e != nil {
			return result, e
		}
		for rows.Next() {
			var match string
			if e = rows.Scan(&match); e != nil {
				rows.Close()
				return result, e
			}
			hits[match] = true
			if strongKind(c.Kind) && !placeholder(c) {
				strongHits[match] = true
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return result, e
		}
		if uid != nil && (c.Kind == "machine_uuid" || c.Kind == "bios_uuid" || c.Kind == "serial") {
			var contradiction bool
			e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM assets.asset_identifiers WHERE tenant_id=$1 AND asset_uid=$2 AND kind=$3 AND namespace=$4 AND normalized_value<>$5 AND valid_to IS NULL)", o.TenantID, *uid, c.Kind, c.Namespace, c.Value).Scan(&contradiction)
			if e != nil {
				return result, e
			}
			conflict = conflict || contradiction
		}
	}
	// C25.01 вариант Б: запись без актива (новая или прежде ушедшая в конфликт) привязывается к существующему активу,
	// если ровно один актив совпал по надёжному сильному идентификатору, все прочие совпадения указывают на него же,
	// нет утверждения asserted_asset_uid, конфликта scope и противоречащего сильного идентификатора того же вида.
	if uid == nil && o.Asserted == nil && !scopeConflict && len(strongHits) == 1 {
		var candidate string
		for id := range strongHits {
			candidate = id
		}
		auto := true
		for hit := range hits {
			auto = auto && hit == candidate
		}
		if auto {
			// две разные записи ОДНОГО источника с одним сильным ID — признак клона, не авто-сведение (C06)
			var sameSource bool
			e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM assets.source_records WHERE tenant_id=$1 AND source_id=$2 AND asset_uid=$3 AND source_record_key<>$4)", o.TenantID, o.Origin.SourceID, candidate, result.RecordKey).Scan(&sameSource)
			if e != nil {
				return result, e
			}
			auto = !sameSource
		}
		for _, c := range normalized {
			if !auto || !strongKind(c.Kind) {
				continue
			}
			var contradiction bool
			e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM assets.asset_identifiers WHERE tenant_id=$1 AND asset_uid=$2 AND kind=$3 AND namespace=$4 AND normalized_value<>$5 AND valid_to IS NULL)", o.TenantID, candidate, c.Kind, c.Namespace, c.Value).Scan(&contradiction)
			if e != nil {
				return result, e
			}
			auto = !contradiction
		}
		if auto {
			uid = &candidate
			conflict = scopeConflict
			result.AssetID, result.AutoMatched, result.Reason = candidate, true, "AUTO_STRONG_MATCH"
			if _, e = tx.Exec(ctx, "UPDATE assets.source_records SET asset_uid=$3,resolution_state='resolved',revision=revision+1 WHERE tenant_id=$1 AND source_record_key=$2", o.TenantID, result.RecordKey, candidate); e != nil {
				return result, e
			}
			// прежние открытые конфликты этой записи закрываются (история остаётся)
			if _, e = tx.Exec(ctx, "UPDATE assets.reconciliation_conflicts SET state='resolved',revision=revision+1 WHERE tenant_id=$1 AND source_record_key=$2 AND state='open'", o.TenantID, result.RecordKey); e != nil {
				return result, e
			}
		}
	}
	for hit := range hits {
		if uid == nil || hit != *uid {
			conflict = true
		}
	}
	if o.Asserted != nil && (uid == nil || *o.Asserted != *uid) {
		conflict = true
	}
	if conflict {
		result.Pending = true
		result.Reason = "IDENTITY_CONFLICT"
		candidates := []string{}
		for hit := range hits {
			candidates = append(candidates, hit)
		}
		sort.Strings(candidates)
		if len(candidates) > 16 {
			candidates = candidates[:16]
		}
		if len(candidates) == 0 && uid != nil {
			candidates = append(candidates, *uid)
		}
		_, e = tx.Exec(ctx, "INSERT INTO assets.reconciliation_conflicts(tenant_id,conflict_id,source_record_key,candidate_asset_uids,reason_code,state) VALUES($1,$2,$3,$4,$5,'open')", o.TenantID, identifier.New(), result.RecordKey, candidates, result.Reason)
		if e != nil {
			return result, e
		}
		if uid == nil {
			_, e = tx.Exec(ctx, "UPDATE assets.source_records SET resolution_state='conflict',revision=revision+1 WHERE tenant_id=$1 AND source_record_key=$2", o.TenantID, result.RecordKey)
		}
		result.AssetID = ""
		return result, e
	}
	if uid == nil {
		result.AssetID = identifier.New()
		result.Created = true
		_, e = tx.Exec(ctx, "INSERT INTO assets.assets(tenant_id,asset_uid,site_id,scope_id) VALUES($1,$2,$3,$4)", o.TenantID, result.AssetID, o.Scope.SiteID, o.Scope.ScopeID)
		if e != nil {
			return result, e
		}
		_, e = tx.Exec(ctx, "INSERT INTO assets.asset_business_fields(tenant_id,asset_uid) VALUES($1,$2)", o.TenantID, result.AssetID)
		if e != nil {
			return result, e
		}
		_, e = tx.Exec(ctx, "UPDATE assets.source_records SET asset_uid=$3,resolution_state='resolved',revision=revision+1 WHERE tenant_id=$1 AND source_record_key=$2", o.TenantID, result.RecordKey, result.AssetID)
		if e != nil {
			return result, e
		}
	}
	for _, c := range normalized {
		strength := "weak"
		if c.Kind == "machine_uuid" || c.Kind == "bios_uuid" || c.Kind == "serial" {
			strength = "strong"
		}
		_, e = tx.Exec(ctx, `INSERT INTO assets.asset_identifiers(tenant_id,identifier_id,asset_uid,kind,namespace,normalized_value,strength,source_record_key) SELECT $1,$2,$3,$4,$5,$6,$7,$8 WHERE NOT EXISTS(SELECT 1 FROM assets.asset_identifiers WHERE tenant_id=$1 AND asset_uid=$3 AND kind=$4 AND namespace=$5 AND normalized_value=$6 AND source_record_key=$8 AND valid_to IS NULL)`, o.TenantID, identifier.New(), result.AssetID, c.Kind, c.Namespace, c.Value, strength, result.RecordKey)
		if e != nil {
			return result, e
		}
	}
	return result, nil
}
func (Store) Link(ctx context.Context, tx pgx.Tx, o contracts.Observation, asset string) (string, error) {
	id := identifier.New()
	_, e := tx.Exec(ctx, "INSERT INTO assets.observation_links(tenant_id,link_id,observation_id,asset_uid,reason_code) VALUES($1,$2,$3,$4,'SOURCE_MAPPING')", o.TenantID, id, o.ID, asset)
	return id, e
}
func (Store) Bump(ctx context.Context, tx pgx.Tx, tenant, asset string) (string, error) {
	var v string
	e := tx.QueryRow(ctx, "UPDATE assets.assets SET aggregate_version=aggregate_version+1 WHERE tenant_id=$1 AND asset_uid=$2 RETURNING aggregate_version::text", tenant, asset).Scan(&v)
	return v, e
}
func (Store) History(ctx context.Context, tx pgx.Tx, tenant, asset, version, reason, actor string) error {
	_, e := tx.Exec(ctx, "INSERT INTO assets.asset_changes(tenant_id,change_id,asset_uid,aggregate_version,reason_code,actor_ref) VALUES($1,$2,$3,$4,$5,$6)", tenant, identifier.New(), asset, version, reason, actor)
	return e
}
func (Store) Get(ctx context.Context, tx pgx.Tx, tenant, uid string) (contracts.Asset, error) {
	var a contracts.Asset
	a.Sections = []contracts.SectionState{}
	e := tx.QueryRow(ctx, "SELECT a.tenant_id::text,a.asset_uid::text,a.site_id::text,b.revision::text,b.display_name,b.purpose,b.criticality,b.tags FROM assets.assets a JOIN assets.asset_business_fields b USING(tenant_id,asset_uid) WHERE a.tenant_id=$1 AND a.asset_uid=$2", tenant, uid).Scan(&a.TenantID, &a.UID, &a.SiteID, &a.Revision, &a.Business.DisplayName, &a.Business.Purpose, &a.Business.Criticality, &a.Business.Tags)
	if errors.Is(e, pgx.ErrNoRows) {
		e = domain.NotFound
	}
	return a, e
}
func (Store) IDs(ctx context.Context, tx pgx.Tx, tenant, after string, limit int) ([]string, error) {
	rows, e := tx.Query(ctx, "SELECT asset_uid::text FROM assets.assets WHERE tenant_id=$1 AND ($2='' OR asset_uid>NULLIF($2,'')::uuid) ORDER BY asset_uid LIMIT $3", tenant, after, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (Store) Patch(ctx context.Context, tx pgx.Tx, tenant, uid, revision string, p contracts.BusinessPatch) error {
	var tags any
	if p.Tags != nil {
		tags = *p.Tags
	}
	tag, e := tx.Exec(ctx, "UPDATE assets.asset_business_fields SET display_name=COALESCE($4,display_name),purpose=COALESCE($5,purpose),criticality=COALESCE($6,criticality),tags=COALESCE($7,tags),revision=revision+1 WHERE tenant_id=$1 AND asset_uid=$2 AND revision::text=$3", tenant, uid, revision, p.DisplayName, p.Purpose, p.Criticality, tags)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return domain.Revision
	}
	return nil
}
func (Store) ApplyEvent(ctx context.Context, tx pgx.Tx, tenant, asset, version string) error {
	tag, e := tx.Exec(ctx, `INSERT INTO assets.consumer_versions(tenant_id,asset_uid,aggregate_version) SELECT $1,$2,$3::numeric WHERE $3::numeric=1 OR EXISTS(SELECT 1 FROM assets.consumer_versions WHERE tenant_id=$1 AND asset_uid=$2) ON CONFLICT(tenant_id,asset_uid) DO UPDATE SET aggregate_version=GREATEST(assets.consumer_versions.aggregate_version,excluded.aggregate_version) WHERE assets.consumer_versions.aggregate_version=excluded.aggregate_version-1 OR assets.consumer_versions.aggregate_version>=excluded.aggregate_version`, tenant, asset, version)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return domain.Conflict
	}
	return nil
}
