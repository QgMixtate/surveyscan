package inventory

import (
	"context"
	"encoding/json"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/jackc/pgx/v5"
)

// PendingObservation — сохранённое, но ещё не привязанное к активу наблюдение записи источника.
type PendingObservation struct {
	Observation contracts.Observation
	Priority    int
}

// PendingObservations возвращает наблюдения записи без связи с активом (ожидали разбора конфликта), по возрастанию
// source_sequence. Неизменяемый payload читается как есть; проекция применяет обычные правила ранга (C25.02).
func (Store) PendingObservations(ctx context.Context, tx pgx.Tx, tenant, record string, limit int) ([]PendingObservation, error) {
	rows, err := tx.Query(ctx, `SELECT o.payload,o.source_priority FROM inventory.observations o WHERE o.tenant_id=$1 AND o.source_record_key=$2
AND NOT EXISTS(SELECT 1 FROM assets.observation_links l WHERE l.tenant_id=o.tenant_id AND l.observation_id=o.observation_id)
ORDER BY o.source_sequence::numeric LIMIT $3`, tenant, record, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PendingObservation{}
	for rows.Next() {
		var raw []byte
		var p PendingObservation
		if err = rows.Scan(&raw, &p.Priority); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &p.Observation); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
