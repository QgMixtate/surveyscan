package inventory

import (
	"context"
	"errors"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/jackc/pgx/v5"
)

// RecordState12 and RecordFacts12 must be read in the same repeatable-read
// transaction after the composition root authorizes the tenant-bound asset.
func (Store) RecordState12(ctx context.Context, tx pgx.Tx, tenant, asset, section string) (string, *contracts.RecordState12, error) {
	if !contracts.InventorySection12(section) {
		return "", nil, domain.Invalid
	}
	state := &contracts.RecordState12{}
	p := &state.Attempt
	var revision string
	// R-027 (1А): статус раздела — лучшая из последних попыток источников актива, при равенстве — более поздняя.
	// Попытки всех источников отдаются списком sources. Если по-источниковых попыток ещё нет — последняя попытка любого.
	err := tx.QueryRow(ctx, `WITH best AS (
 SELECT x.last_attempt_id,x.last_status FROM inventory.record_section_source_state12 x WHERE x.tenant_id=$1 AND x.asset_uid=$2 AND x.section_name=$3
 ORDER BY CASE x.last_status WHEN 'partial' THEN 0 WHEN 'unavailable' THEN 1 WHEN 'unsupported' THEN 2 ELSE 3 END, x.collected_at DESC, x.source_id LIMIT 1)
SELECT r.projection_revision::text,COALESCE(b.last_status,r.last_status),r.clock_uncertain,o.observation_id::text,o.source_id::text,o.payload->'origin'->>'source_kind',o.generation_id::text,o.source_sequence::text,s.collected_at,o.clock_quality
FROM inventory.record_section_state12 r LEFT JOIN best b ON true
JOIN inventory.observations o ON o.tenant_id=r.tenant_id AND o.observation_id=COALESCE(b.last_attempt_id,r.last_attempt_id)
JOIN inventory.observation_sections s ON s.tenant_id=r.tenant_id AND s.observation_id=o.observation_id AND s.section_name=r.section_name
WHERE r.tenant_id=$1 AND r.asset_uid=$2 AND r.section_name=$3`, tenant, asset, section).Scan(&revision, &state.Status, &state.ClockUncertain, &p.Observation, &p.Origin.SourceID, &p.Origin.SourceKind, &p.Origin.GenerationID, &p.Sequence, &p.Collected, &p.Clock)
	if errors.Is(err, pgx.ErrNoRows) {
		return "0", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	p.Collected = p.Collected.UTC()
	rows, err := tx.Query(ctx, `SELECT source_id::text,last_status,collected_at FROM inventory.record_section_source_state12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name=$3 ORDER BY source_id LIMIT 16`, tenant, asset, section)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var x contracts.SectionSource12
		if err = rows.Scan(&x.SourceID, &x.Status, &x.Collected); err != nil {
			return "", nil, err
		}
		x.Collected = x.Collected.UTC()
		state.Sources = append(state.Sources, x)
	}
	return revision, state, rows.Err()
}

func (Store) RecordFacts12(ctx context.Context, tx pgx.Tx, tenant, asset, section, afterRecord, afterField string, limit int) ([]contracts.RecordFact12, bool, error) {
	items := []contracts.RecordFact12{}
	if !contracts.InventorySection12(section) || limit < 1 || limit > wire.RecordPage12MaxItems {
		return nil, false, domain.Invalid
	}
	rows, err := tx.Query(ctx, `SELECT f.record_key,f.field_name,f.value,o.observation_id::text,o.source_id::text,o.payload->'origin'->>'source_kind',o.generation_id::text,o.source_sequence::text,s.collected_at,o.clock_quality FROM inventory.record_facts12 f JOIN inventory.observations o ON o.tenant_id=f.tenant_id AND o.observation_id=f.observation_id JOIN inventory.observation_sections s ON s.tenant_id=f.tenant_id AND s.observation_id=f.observation_id AND s.section_name=f.section_name WHERE f.tenant_id=$1 AND f.asset_uid=$2 AND f.section_name=$3 AND (f.record_key COLLATE "C",f.field_name COLLATE "C")>($4,$5) ORDER BY f.record_key COLLATE "C",f.field_name COLLATE "C" LIMIT $6`, tenant, asset, section, afterRecord, afterField, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	bytes := 4096 // Reserve bounded response metadata and cursor overhead.
	for rows.Next() {
		var f contracts.RecordFact12
		p := &f.Evidence
		if err = rows.Scan(&f.Record, &f.Field, &f.Value, &p.Observation, &p.Origin.SourceID, &p.Origin.SourceKind, &p.Origin.GenerationID, &p.Sequence, &p.Collected, &p.Clock); err != nil {
			return nil, false, err
		}
		p.Collected = p.Collected.UTC()
		b, err := wire.RecordJSON(f)
		if err != nil {
			return nil, false, err
		}
		if len(items) == limit || bytes+len(b)+1 > wire.RecordPage12MaxBytes {
			if len(items) == 0 {
				return nil, false, errors.New("record fact exceeds page capacity")
			}
			return items, true, nil
		}
		bytes += len(b) + 1
		items = append(items, f)
	}
	return items, false, rows.Err()
}

// SourceIDs12 возвращает источники, данные которых есть в проекции профиля 1.2 актива:
// последние попытки секций и наблюдения, из которых взяты текущие факты. Нужна сводке
// источников карточки C09 наравне с источниками проекции 1.0. Читать в той же транзакции
// после авторизации актива.
func (Store) SourceIDs12(ctx context.Context, tx pgx.Tx, tenant, asset string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT o.source_id::text FROM inventory.observations o WHERE o.tenant_id=$1 AND o.observation_id IN (
SELECT r.last_attempt_id FROM inventory.record_section_state12 r WHERE r.tenant_id=$1 AND r.asset_uid=$2
UNION SELECT DISTINCT f.observation_id FROM inventory.record_facts12 f WHERE f.tenant_id=$1 AND f.asset_uid=$2)`, tenant, asset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
