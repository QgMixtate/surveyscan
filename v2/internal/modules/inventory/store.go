package inventory

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/jackc/pgx/v5"
	"strconv"
	"sync/atomic"
	"time"
)

type Store struct{}
type Result struct {
	ObservationID string  `json:"observation_id"`
	AssetID       *string `json:"asset_uid"`
	Disposition   string  `json:"disposition"`
	Reason        string  `json:"reason_code"`
	Duplicate     bool    `json:"duplicate"`
}

func (Store) Duplicate(ctx context.Context, tx pgx.Tx, o contracts.Observation, digest string) (Result, bool, error) {
	var result Result
	var oldDigest string
	var disposition, reason *string
	e := tx.QueryRow(ctx, `SELECT o.observation_id::text,o.digest,r.asset_uid::text,r.disposition,r.reason_code FROM inventory.observations o JOIN assets.source_records s USING(tenant_id,source_record_key) LEFT JOIN inventory.observation_results r USING(tenant_id,observation_id) WHERE o.tenant_id=$1 AND (o.observation_id=$2 OR (o.source_id=$3 AND o.generation_id=$4 AND o.source_sequence=$5 AND s.namespace=$6 AND s.source_local_id=$7)) LIMIT 1`, o.TenantID, o.ID, o.Origin.SourceID, o.Origin.GenerationID, o.Sequence, o.Record.Namespace, o.Record.LocalID).Scan(&result.ObservationID, &oldDigest, &result.AssetID, &disposition, &reason)
	if errors.Is(e, pgx.ErrNoRows) {
		return result, false, nil
	}
	if e != nil {
		return result, false, e
	}
	if result.ObservationID != o.ID || oldDigest != digest || disposition == nil {
		return result, true, domain.Conflict
	}
	result.Disposition = *disposition
	result.Reason = *reason
	result.Duplicate = true
	return result, true, nil
}
func (Store) Record(ctx context.Context, tx pgx.Tx, o contracts.Observation, signed contracts.SignedObservation, canonical, signature []byte, record string, priority int) error {
	_, e := tx.Exec(ctx, `INSERT INTO inventory.observations(tenant_id,observation_id,source_record_key,source_id,generation_id,source_sequence,collected_at,clock_quality,digest,asserted_asset_uid,payload,origin_key_id,origin_signature,canonical_payload,source_priority) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, o.TenantID, o.ID, record, o.Origin.SourceID, o.Origin.GenerationID, o.Sequence, o.CollectedAt, o.Clock, signed.Digest, o.Asserted, signed.Payload, signed.KeyID, signature, canonical, priority)
	if e != nil {
		return e
	}
	for _, section := range o.Sections {
		facts, e := json.Marshal(section.Records)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, "INSERT INTO inventory.observation_sections(tenant_id,observation_id,section_name,status,collection_complete,reason_code,record_count,facts,collected_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", o.TenantID, o.ID, section.Name, section.Status, section.Complete, section.Reason, section.Count, facts, section.CollectedAt)
		if e != nil {
			return e
		}
	}
	return nil
}
func (Store) Result(ctx context.Context, tx pgx.Tx, tenant string, result Result) error {
	_, e := tx.Exec(ctx, "INSERT INTO inventory.observation_results(tenant_id,observation_id,asset_uid,disposition,reason_code) VALUES($1,$2,$3,$4,$5)", tenant, result.ObservationID, result.AssetID, result.Disposition, result.Reason)
	return e
}

type rank struct {
	Source, Generation, Record, Sequence, Clock string
	Priority                                    int
	Collected                                   time.Time
}

func Newer(next, old rank) bool {
	if next.Source == old.Source {
		if next.Generation != old.Generation || next.Record != old.Record {
			return false
		}
		a, _ := strconv.ParseUint(next.Sequence, 10, 64)
		b, _ := strconv.ParseUint(old.Sequence, 10, 64)
		return a > b
	}
	if next.Clock != "trusted" {
		return false
	}
	if old.Clock != "trusted" {
		return true
	}
	if next.Priority != old.Priority {
		// C26, решение 3А: приоритет источника действует, пока данные сопоставимы по свежести. Если время сбора
		// расходится больше порога, побеждают более свежие данные (остановившийся агент не держит карточку).
		if stale := time.Duration(priorityStaleAfter.Load()); stale > 0 {
			if d := next.Collected.Sub(old.Collected); d > stale {
				return true
			} else if -d > stale {
				return false
			}
		}
		return next.Priority > old.Priority
	}
	return next.Collected.After(old.Collected)
}

// DefaultPriorityStaleAfter — порог давности приоритета по умолчанию (решение пользователя 3А, R-027).
const DefaultPriorityStaleAfter = 24 * time.Hour

var priorityStaleAfter = func() *atomic.Int64 { v := &atomic.Int64{}; v.Store(int64(DefaultPriorityStaleAfter)); return v }()

// SetPriorityStaleAfter задаёт порог при старте центра; 0 — только приоритет (поведение до C26).
func SetPriorityStaleAfter(d time.Duration) {
	if d < 0 {
		d = 0
	}
	priorityStaleAfter.Store(int64(d))
}
func existingRank(ctx context.Context, tx pgx.Tx, tenant, obs, section string) (rank, error) {
	var r rank
	e := tx.QueryRow(ctx, "SELECT o.source_id::text,o.generation_id::text,o.source_record_key::text,o.source_sequence::text,o.clock_quality,o.source_priority,s.collected_at FROM inventory.observations o JOIN inventory.observation_sections s USING(tenant_id,observation_id) WHERE o.tenant_id=$1 AND o.observation_id=$2 AND s.section_name=$3", tenant, obs, section).Scan(&r.Source, &r.Generation, &r.Record, &r.Sequence, &r.Clock, &r.Priority, &r.Collected)
	return r, e
}
func flatten(s contracts.Section) (map[string]string, error) {
	out := map[string]string{}
	if s.Name != "identity" && s.Name != "os" && s.Name != "network" {
		return nil, domain.Invalid
	}
	for _, row := range s.Records {
		switch s.Name {
		case "identity":
			for k, v := range row {
				out[k] = v.(string)
			}
		case "os":
			for k, v := range row {
				out[k] = v.(string)
			}
		case "network":
			name := row["name"].(string)
			key := base64.RawURLEncoding.EncodeToString([]byte(name))
			if _, exists := out[key+".addresses"]; exists {
				return nil, domain.Invalid
			}
			if mac, ok := row["mac"].(string); ok {
				out[key+".mac"] = mac
			}
			addresses, e := json.Marshal(row["addresses"])
			if e != nil {
				return nil, e
			}
			out[key+".addresses"] = string(addresses)
		}
	}
	return out, nil
}
func (Store) Project(ctx context.Context, tx pgx.Tx, o contracts.Observation, asset, link, record string, priority int) (bool, error) {
	// Reject unsupported sections before any projection writes, including empty ones.
	for _, section := range o.Sections {
		if section.Name != "identity" && section.Name != "os" && section.Name != "network" {
			return false, domain.Invalid
		}
	}
	changed := false
	for _, section := range o.Sections {
		next := rank{o.Origin.SourceID, o.Origin.GenerationID, record, o.Sequence, o.Clock, priority, section.CollectedAt}
		if o.Clock == "skewed" || section.CollectedAt.After(time.Now().Add(5*time.Minute)) {
			continue
		}
		var attempt *string
		e := tx.QueryRow(ctx, "SELECT last_attempt_id::text FROM inventory.section_state WHERE tenant_id=$1 AND asset_uid=$2 AND section_name=$3", o.TenantID, asset, section.Name).Scan(&attempt)
		missing := errors.Is(e, pgx.ErrNoRows)
		if e != nil && !missing {
			return false, e
		}
		uncertain := o.Clock != "trusted"
		canState := missing || attempt == nil
		if !canState {
			old, e := existingRank(ctx, tx, o.TenantID, *attempt, section.Name)
			if e != nil {
				return false, e
			}
			canState = Newer(next, old)
			if next.Source == old.Source && next.Generation == old.Generation && next.Collected.Before(old.Collected) {
				uncertain = true
			}
		}
		if canState {
			var success *string
			if section.Status == "ok" && section.Complete {
				success = &o.ID
			}
			_, e = tx.Exec(ctx, `INSERT INTO inventory.section_state(tenant_id,asset_uid,section_name,last_attempt_id,last_success_id,last_status,clock_uncertain) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,asset_uid,section_name) DO UPDATE SET last_attempt_id=excluded.last_attempt_id,last_success_id=COALESCE(excluded.last_success_id,inventory.section_state.last_success_id),last_status=excluded.last_status,clock_uncertain=excluded.clock_uncertain,projection_revision=inventory.section_state.projection_revision+1`, o.TenantID, asset, section.Name, o.ID, success, section.Status, uncertain)
			if e != nil {
				return false, e
			}
			changed = true
		}
		if !canState || section.Status != "ok" && section.Status != "partial" {
			continue
		}
		values, e := flatten(section)
		if e != nil {
			return false, e
		}
		oldFacts := map[string]string{}
		rows, e := tx.Query(ctx, "SELECT fact_key,observation_id::text FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=$2 AND section_name=$3", o.TenantID, asset, section.Name)
		if e != nil {
			return false, e
		}
		for rows.Next() {
			var k, id string
			if e = rows.Scan(&k, &id); e != nil {
				rows.Close()
				return false, e
			}
			oldFacts[k] = id
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return false, e
		}
		for key, oldID := range oldFacts {
			old, e := existingRank(ctx, tx, o.TenantID, oldID, section.Name)
			if e != nil {
				return false, e
			}
			if !Newer(next, old) {
				delete(values, key)
				continue
			}
			if _, present := values[key]; !present && section.Status == "ok" && section.Complete && old.Source == next.Source && old.Generation == next.Generation && old.Record == next.Record {
				_, e = tx.Exec(ctx, "DELETE FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=$2 AND section_name=$3 AND fact_key=$4", o.TenantID, asset, section.Name, key)
				if e != nil {
					return false, e
				}
				changed = true
			}
		}
		for key, value := range values {
			_, e = tx.Exec(ctx, `INSERT INTO inventory.current_facts(tenant_id,asset_uid,section_name,fact_key,value,observation_id,link_id) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,asset_uid,section_name,fact_key) DO UPDATE SET value=excluded.value,observation_id=excluded.observation_id,link_id=excluded.link_id,projection_revision=inventory.current_facts.projection_revision+1`, o.TenantID, asset, section.Name, key, value, o.ID, link)
			if e != nil {
				return false, e
			}
			changed = true
		}
	}
	return changed, nil
}
func (s Store) Enrich(ctx context.Context, tx pgx.Tx, a *contracts.Asset) error {
	return s.EnrichMany(ctx, tx, []*contracts.Asset{a})
}

// EnrichMany дополняет активы одного тенанта наблюдаемыми именем, ОС, состояниями разделов и свежестью — по одному
// запросу на вид данных для всей страницы (C30, стенд: построчное чтение давало ~7 запросов на актив).
func (Store) EnrichMany(ctx context.Context, tx pgx.Tx, list []*contracts.Asset) error {
	if len(list) == 0 {
		return nil
	}
	tenant := list[0].TenantID
	uids := make([]string, len(list))
	by := map[string]*contracts.Asset{}
	osFields := map[string]map[string]string{}
	trusted, uncertain := map[string]bool{}, map[string]bool{}
	for i, a := range list {
		a.Freshness = "unknown"
		uids[i] = a.UID
		by[a.UID] = a
		osFields[a.UID] = map[string]string{}
	}
	rows, e := tx.Query(ctx, "SELECT asset_uid::text,section_name,fact_key,value FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=ANY($2::uuid[]) AND section_name IN ('identity','os')", tenant, uids)
	if e != nil {
		return e
	}
	for rows.Next() {
		var uid, section, key, value string
		if e = rows.Scan(&uid, &section, &key, &value); e != nil {
			rows.Close()
			return e
		}
		if section == "identity" && key == "hostname" {
			v := value
			by[uid].Hostname = &v
		}
		if section == "os" {
			osFields[uid][key] = value
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for uid, f := range osFields {
		if name, ok := f["name"]; ok {
			value := name
			if ver, ok := f["version"]; ok {
				value += " " + ver
			}
			if runes := []rune(value); len(runes) > 256 {
				value = string(runes[:256])
			}
			by[uid].OS = &value
		}
	}
	rows, e = tx.Query(ctx, "SELECT s.asset_uid::text,s.section_name,s.last_status,o.collected_at,o.clock_quality,s.clock_uncertain FROM inventory.section_state s LEFT JOIN inventory.observations o ON o.tenant_id=s.tenant_id AND o.observation_id=s.last_success_id WHERE s.tenant_id=$1 AND s.asset_uid=ANY($2::uuid[]) ORDER BY s.asset_uid,s.section_name", tenant, uids)
	if e != nil {
		return e
	}
	for rows.Next() {
		var uid string
		var state contracts.SectionState
		var at *time.Time
		var clock *string
		var unc bool
		if e = rows.Scan(&uid, &state.Name, &state.Status, &at, &clock, &unc); e != nil {
			rows.Close()
			return e
		}
		a := by[uid]
		a.Sections = append(a.Sections, state)
		uncertain[uid] = uncertain[uid] || unc
		if at != nil && (a.LastInventory == nil || at.After(*a.LastInventory)) {
			utc := at.UTC()
			a.LastInventory = &utc
			trusted[uid] = clock != nil && *clock == "trusted"
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	// Активы только с профилем 1.2 (run12-агенты, SSH/WinRM, portable): 1.0 первичен, 1.2 — где 1.0 пусто.
	if e = enrich12Many(ctx, tx, tenant, list, trusted, uncertain); e != nil {
		return e
	}
	for _, a := range list {
		if a.LastInventory != nil && trusted[a.UID] && !uncertain[a.UID] && !a.LastInventory.After(time.Now().Add(5*time.Minute)) {
			a.Freshness = "stale"
			if time.Since(*a.LastInventory) <= 24*time.Hour {
				a.Freshness = "fresh"
			}
		}
	}
	return nil
}

// RecordedExact не создаёт эффектов и сравнивает сохранённую исходную подпись, а не только observation digest.
func (s Store) RecordedExact(ctx context.Context, tx pgx.Tx, o contracts.Observation, digest, key string, signature []byte) (Result, bool, error) {
	result, exists, e := s.Duplicate(ctx, tx, o, digest)
	if e != nil || !exists {
		return result, exists, e
	}
	var storedKey string
	var storedSignature []byte
	if e = tx.QueryRow(ctx, "SELECT origin_key_id::text,origin_signature FROM inventory.observations WHERE tenant_id=$1 AND observation_id=$2", o.TenantID, o.ID).Scan(&storedKey, &storedSignature); e != nil {
		return result, false, e
	}
	if key != storedKey || !bytes.Equal(signature, storedSignature) {
		return result, false, domain.Invalid
	}
	return result, true, nil
}

func enrich12Many(ctx context.Context, tx pgx.Tx, tenant string, list []*contracts.Asset, trusted, uncertain map[string]bool) error {
	var host, osName, last []string
	by := map[string]*contracts.Asset{}
	for _, a := range list {
		by[a.UID] = a
		if a.Hostname == nil {
			host = append(host, a.UID)
		}
		if a.OS == nil {
			osName = append(osName, a.UID)
		}
		if a.LastInventory == nil {
			last = append(last, a.UID)
		}
	}
	if len(host) > 0 {
		rows, e := tx.Query(ctx, `SELECT DISTINCT ON (asset_uid) asset_uid::text,value #>> '{}' FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=ANY($2::uuid[]) AND section_name='identity' AND field_name='hostname' AND jsonb_typeof(value)='string' ORDER BY asset_uid,record_key`, tenant, host)
		if e != nil {
			return e
		}
		for rows.Next() {
			var uid string
			var name *string
			if e = rows.Scan(&uid, &name); e != nil {
				rows.Close()
				return e
			}
			if name != nil && *name != "" {
				by[uid].Hostname = name
			}
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return e
		}
	}
	if len(osName) > 0 {
		rows, e := tx.Query(ctx, `SELECT asset_uid::text,max(value #>> '{}') FILTER (WHERE field_name='name'),max(value #>> '{}') FILTER (WHERE field_name='version') FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=ANY($2::uuid[]) AND section_name='os' AND jsonb_typeof(value)='string' GROUP BY asset_uid`, tenant, osName)
		if e != nil {
			return e
		}
		for rows.Next() {
			var uid string
			var name, version *string
			if e = rows.Scan(&uid, &name, &version); e != nil {
				rows.Close()
				return e
			}
			if name != nil && *name != "" {
				value := *name
				if version != nil && *version != "" {
					value += " " + *version
				}
				if runes := []rune(value); len(runes) > 256 {
					value = string(runes[:256])
				}
				by[uid].OS = &value
			}
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return e
		}
	}
	if len(last) > 0 {
		rows, e := tx.Query(ctx, `SELECT DISTINCT ON (r.asset_uid) r.asset_uid::text,s.collected_at,o.clock_quality,bool_or(r.clock_uncertain) OVER (PARTITION BY r.asset_uid) FROM inventory.record_section_state12 r JOIN inventory.observations o ON o.tenant_id=r.tenant_id AND o.observation_id=r.last_attempt_id JOIN inventory.observation_sections s ON s.tenant_id=r.tenant_id AND s.observation_id=r.last_attempt_id AND s.section_name=r.section_name WHERE r.tenant_id=$1 AND r.asset_uid=ANY($2::uuid[]) AND r.last_status='partial' ORDER BY r.asset_uid,s.collected_at DESC`, tenant, last)
		if e != nil {
			return e
		}
		for rows.Next() {
			var uid string
			var at *time.Time
			var clock *string
			var anyUncertain bool
			if e = rows.Scan(&uid, &at, &clock, &anyUncertain); e != nil {
				rows.Close()
				return e
			}
			if at != nil {
				utc := at.UTC()
				by[uid].LastInventory = &utc
				trusted[uid] = clock != nil && *clock == "trusted"
				uncertain[uid] = uncertain[uid] || anyUncertain
			}
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return e
		}
	}
	return nil
}
