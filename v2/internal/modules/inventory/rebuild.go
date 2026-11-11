package inventory

import (
	"context"
	"encoding/json"

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
	for _, it := range items {
		if it.o.Version.Minor == 2 {
			_, e = s.ProjectPartial12(ctx, tx, it.o, asset, it.link, it.record, it.priority)
		} else {
			_, e = s.Project(ctx, tx, it.o, asset, it.link, it.record, it.priority)
		}
		if e != nil {
			return 0, e
		}
	}
	return len(items), nil
}
