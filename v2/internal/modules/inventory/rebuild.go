package inventory

import (
	"context"
	"encoding/json"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/jackc/pgx/v5"
)

// C25.03: после слияния или разделения проекция актива пересобирается из его наблюдений, а не «склеивается»:
// значения, перезаписанные чужой записью до разделения, иначе были бы потеряны. Наблюдения применяются в порядке
// приёма с их ранговыми правилами — результат тот же, что дал бы последовательный приём только этих наблюдений.

// Clear удаляет текущую проекцию актива (наблюдения и связи неизменны).
func (Store) Clear(ctx context.Context, tx pgx.Tx, tenant, asset string) error {
	if _, e := tx.Exec(ctx, "DELETE FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, "DELETE FROM inventory.section_state WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, "DELETE FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, "DELETE FROM inventory.record_section_state12 WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, "DELETE FROM inventory.record_section_source_state12 WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset); e != nil {
		return e
	}
	return nil
}

// Rebuild очищает проекцию актива и применяет заново все наблюдения с активной связью на него. Возвращает число
// применённых наблюдений.
func (s Store) Rebuild(ctx context.Context, tx pgx.Tx, tenant, asset string) (int, error) {
	if e := s.Clear(ctx, tx, tenant, asset); e != nil {
		return 0, e
	}
	type item struct {
		o            contracts.Observation
		link, record string
		priority     int
	}
	var items []item
	rows, e := tx.Query(ctx, `SELECT o.payload,o.source_priority,l.link_id::text,o.source_record_key::text FROM assets.observation_links l
JOIN inventory.observations o ON o.tenant_id=l.tenant_id AND o.observation_id=l.observation_id
WHERE l.tenant_id=$1 AND l.asset_uid=$2 AND l.valid_to IS NULL ORDER BY o.received_at,o.source_sequence::numeric,o.observation_id`, tenant, asset)
	if e != nil {
		return 0, e
	}
	for rows.Next() {
		var raw []byte
		var it item
		if e = rows.Scan(&raw, &it.priority, &it.link, &it.record); e != nil {
			rows.Close()
			return 0, e
		}
		if e = json.Unmarshal(raw, &it.o); e != nil {
			rows.Close()
			return 0, e
		}
		items = append(items, it)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return 0, e
	}
	replay := newReplay12()
	for _, it := range items {
		if it.o.Version.Minor == 2 {
			e = replay.apply(it.o, it.link, it.record, it.priority)
		} else {
			_, e = s.Project(ctx, tx, it.o, asset, it.link, it.record, it.priority)
		}
		if e != nil {
			return 0, e
		}
	}
	return len(items), replay.write(ctx, tx, tenant, asset)
}

// replay12 — пересборка проекции 1.2 в памяти: те же решения, что ProjectPartial12 принял бы при последовательном
// приёме наблюдений (ранг раздела и поля — Newer по рангу наблюдения-владельца), но запись в БД одним пакетом.
// Последовательная пересборка через ProjectPartial12 на активе стенда (сотни наблюдений × тысячи записей) не
// укладывалась в таймаут запроса.
type owner12 struct {
	obs, link string
	rank      rank
}
type field12 struct {
	value json.RawMessage
	owner *owner12
}
type state12 struct {
	owner     *owner12
	status    string
	uncertain bool
}
type sourceState12 struct {
	obs, status string
	collected   time.Time
}
type replay12 struct {
	facts   map[string]map[[2]string]field12 // раздел → (запись, поле)
	state   map[string]state12
	sources map[[2]string]sourceState12 // (раздел, источник)
}

func newReplay12() *replay12 {
	return &replay12{facts: map[string]map[[2]string]field12{}, state: map[string]state12{}, sources: map[[2]string]sourceState12{}}
}

func (r *replay12) apply(o contracts.Observation, link, record string, priority int) error {
	prepared, err := splitRecords12(o, false)
	if err != nil {
		return err
	}
	for _, section := range o.Sections {
		if o.Clock == "skewed" || section.CollectedAt.After(time.Now().Add(5*time.Minute)) {
			continue
		}
		key := [2]string{section.Name, o.Origin.SourceID}
		if old, ok := r.sources[key]; !ok || section.CollectedAt.After(old.collected) {
			r.sources[key] = sourceState12{o.ID, section.Status, section.CollectedAt}
		}
		next := &owner12{o.ID, link, rank{o.Origin.SourceID, o.Origin.GenerationID, record, o.Sequence, o.Clock, priority, section.CollectedAt}}
		uncertain := o.Clock != "trusted"
		if old, ok := r.state[section.Name]; ok {
			if !Newer(next.rank, old.owner.rank) {
				continue
			}
			uncertain = uncertain || next.rank.Source == old.owner.rank.Source && next.rank.Collected.Before(old.owner.rank.Collected)
		}
		r.state[section.Name] = state12{next, section.Status, uncertain}
		facts := r.facts[section.Name]
		if facts == nil {
			facts = map[[2]string]field12{}
			r.facts[section.Name] = facts
		}
		wins := map[*owner12]bool{}
		for _, row := range prepared[section.Name] {
			for field, value := range row.fields {
				k := [2]string{row.key, field}
				if current, ok := facts[k]; ok {
					w, cached := wins[current.owner]
					if !cached {
						w = Newer(next.rank, current.owner.rank)
						wins[current.owner] = w
					}
					if !w {
						continue
					}
				}
				facts[k] = field12{value, next}
			}
		}
	}
	return nil
}

func (r *replay12) write(ctx context.Context, tx pgx.Tx, tenant, asset string) error {
	if len(r.state) == 0 && len(r.sources) == 0 {
		return nil
	}
	if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,1512))", tenant+"/"+asset); e != nil {
		return e
	}
	for key, s := range r.sources {
		if _, e := tx.Exec(ctx, "INSERT INTO inventory.record_section_source_state12(tenant_id,asset_uid,section_name,source_id,last_attempt_id,last_status,collected_at) VALUES($1,$2,$3,$4,$5,$6,$7)", tenant, asset, key[0], key[1], s.obs, s.status, s.collected); e != nil {
			return e
		}
	}
	for section, s := range r.state {
		if _, e := tx.Exec(ctx, "INSERT INTO inventory.record_section_state12(tenant_id,asset_uid,section_name,last_attempt_id,last_status,clock_uncertain) VALUES($1,$2,$3,$4,$5,$6)", tenant, asset, section, s.owner.obs, s.status, s.uncertain); e != nil {
			return e
		}
	}
	for section, facts := range r.facts {
		var keys, fields, values, observations, links []string
		flush := func() error {
			if len(keys) == 0 {
				return nil
			}
			_, e := tx.Exec(ctx, `INSERT INTO inventory.record_facts12(tenant_id,asset_uid,section_name,record_key,field_name,value,observation_id,link_id) SELECT $1,$2,$3,k,f,v::jsonb,o,l FROM unnest($4::text[],$5::text[],$6::text[],$7::uuid[],$8::uuid[]) AS u(k,f,v,o,l)`, tenant, asset, section, keys, fields, values, observations, links)
			keys, fields, values, observations, links = keys[:0], fields[:0], values[:0], observations[:0], links[:0]
			return e
		}
		for k, v := range facts {
			keys, fields, values = append(keys, k[0]), append(fields, k[1]), append(values, string(v.value))
			observations, links = append(observations, v.owner.obs), append(links, v.owner.link)
			if len(keys) == 5000 {
				if e := flush(); e != nil {
					return e
				}
			}
		}
		if e := flush(); e != nil {
			return e
		}
	}
	return nil
}
