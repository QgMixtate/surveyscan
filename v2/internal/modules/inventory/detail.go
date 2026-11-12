package inventory

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/jackc/pgx/v5"
)

// Detail читает только inventory-owned проекции/evidence; доступ к asset проверяет composition root.
func (Store) Detail(ctx context.Context, tx pgx.Tx, tenant, asset string) ([]contracts.CurrentFact, []contracts.SectionDetail, error) {
	facts := []contracts.CurrentFact{}
	sections := []contracts.SectionDetail{}
	rows, e := tx.Query(ctx, `SELECT f.section_name,f.fact_key,f.value,o.observation_id::text,o.source_id::text,(SELECT x.source_kind FROM sources.sources x WHERE x.tenant_id=o.tenant_id AND x.source_id=o.source_id),o.generation_id::text,o.source_sequence::text,s.collected_at,o.clock_quality FROM inventory.current_facts f JOIN inventory.observations o ON o.tenant_id=f.tenant_id AND o.observation_id=f.observation_id JOIN inventory.observation_sections s ON s.tenant_id=f.tenant_id AND s.observation_id=f.observation_id AND s.section_name=f.section_name WHERE f.tenant_id=$1 AND f.asset_uid=$2 ORDER BY f.section_name,f.fact_key LIMIT 2049`, tenant, asset)
	if e != nil {
		return facts, sections, e
	}
	for rows.Next() {
		var f contracts.CurrentFact
		p := &f.Evidence
		if e = rows.Scan(&f.Section, &f.Key, &f.Value, &p.Observation, &p.Origin.SourceID, &p.Origin.SourceKind, &p.Origin.GenerationID, &p.Sequence, &p.Collected, &p.Clock); e != nil {
			rows.Close()
			return facts, sections, e
		}
		p.Collected = p.Collected.UTC()
		if f.Section == "network" {
			key, _, ok := strings.Cut(f.Key, ".")
			if !ok {
				rows.Close()
				return facts, sections, domain.Invalid
			}
			name, err := base64.RawURLEncoding.Strict().DecodeString(key)
			if err != nil {
				rows.Close()
				return facts, sections, domain.Invalid
			}
			text := string(name)
			f.Interface = &text
		}
		facts = append(facts, f)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return facts, sections, e
	}
	if len(facts) > 2048 {
		return nil, nil, errors.New("inventory detail capacity exceeded")
	}
	rows, e = tx.Query(ctx, `SELECT section_name,last_status,clock_uncertain,last_attempt_id::text,last_success_id::text FROM inventory.section_state WHERE tenant_id=$1 AND asset_uid=$2 ORDER BY section_name`, tenant, asset)
	if e != nil {
		return facts, sections, e
	}
	type state struct {
		value            contracts.SectionDetail
		attempt, success *string
	}
	states := []state{}
	for rows.Next() {
		var x state
		if e = rows.Scan(&x.value.Name, &x.value.Status, &x.value.ClockUncertain, &x.attempt, &x.success); e != nil {
			rows.Close()
			return facts, sections, e
		}
		states = append(states, x)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return facts, sections, e
	}
	evidence := func(id, section string) (*contracts.FactEvidence, error) {
		p := &contracts.FactEvidence{}
		err := tx.QueryRow(ctx, `SELECT o.observation_id::text,o.source_id::text,(SELECT x.source_kind FROM sources.sources x WHERE x.tenant_id=o.tenant_id AND x.source_id=o.source_id),o.generation_id::text,o.source_sequence::text,s.collected_at,o.clock_quality FROM inventory.observations o JOIN inventory.observation_sections s USING(tenant_id,observation_id) WHERE o.tenant_id=$1 AND o.observation_id=$2 AND s.section_name=$3`, tenant, id, section).Scan(&p.Observation, &p.Origin.SourceID, &p.Origin.SourceKind, &p.Origin.GenerationID, &p.Sequence, &p.Collected, &p.Clock)
		p.Collected = p.Collected.UTC()
		return p, err
	}
	for _, s := range states {
		if s.attempt != nil {
			s.value.Attempt, e = evidence(*s.attempt, s.value.Name)
			if e != nil {
				return facts, sections, e
			}
		}
		if s.success != nil {
			s.value.Success, e = evidence(*s.success, s.value.Name)
			if e != nil {
				return facts, sections, e
			}
		}
		sections = append(sections, s.value)
	}
	return facts, sections, nil
}
