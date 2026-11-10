package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/QgMixtate/surveyscan/v2/internal/portable"
)

// PortableRecord — итог по одной записи пакета.
type PortableRecord struct {
	ObservationID string `json:"observation_id"`
	Disposition   string `json:"disposition"` // applied | duplicate | rejected | quarantined | …
	AssetID       string `json:"asset_id,omitempty"`
	Reason        string `json:"reason_code,omitempty"`
}

// PortableReport — итог импорта portable-пакета.
type PortableReport struct {
	SourceID string           `json:"source_id"`
	Records  []PortableRecord `json:"records"`
	// Complete=false — обработка остановлена по бюджету времени; Remaining записей ещё не обработано.
	// Повторная отправка того же пакета продолжает: обработанные записи вернутся как duplicate.
	Complete  bool `json:"complete"`
	Remaining int  `json:"remaining"`
}

// ImportPortable проверяет пакет ключом зарегистрированного portable-источника (подпись манифеста, digest, подпись
// каждой записи, лимиты, схема 1.2) и проводит записи через общий конвейер IngestAuthorized: та же проверка привязки
// ключа, дедупликация и сопоставление с активами, что у агентов. Повторная загрузка того же пакета идемпотентна.
func (r *Registry) ImportPortable(ctx context.Context, machine *sources.MachineService, tenant, source string, pkg []byte) (PortableReport, error) {
	return r.ImportPortableUntil(ctx, machine, tenant, source, pkg, time.Time{})
}

// ImportPortableUntil — то же с бюджетом времени: после until новые записи не начинаются (нулевое until — без
// ограничения). Нужен HTTP-пути, где запрос ограничен таймаутами сервера и прокси.
func (r *Registry) ImportPortableUntil(ctx context.Context, machine *sources.MachineService, tenant, source string, pkg []byte, until time.Time) (PortableReport, error) {
	report := PortableReport{SourceID: source, Records: []PortableRecord{}, Complete: true}
	keyID, pub, err := machine.PortableTrust(ctx, tenant, source)
	if err != nil {
		return report, err
	}
	v, err := wire.NewInventory12()
	if err != nil {
		return report, err
	}
	res, err := portable.Import(pkg, map[string]ed25519.PublicKey{keyID: ed25519.PublicKey(pub)}, portable.Known{}, portable.DefaultLimits(), v)
	if err != nil {
		return report, err // пакет целиком не прошёл проверку — ничего не применено
	}
	if res.Manifest.Tenant != tenant || res.Manifest.SourceID != source {
		return report, domain.Unauthorized
	}
	for _, q := range res.Quarantined {
		report.Records = append(report.Records, PortableRecord{ObservationID: q.ID, Disposition: "quarantined", Reason: q.Reason})
	}
	authorize := func(_ context.Context, _ pgx.Tx, o contracts.Observation) error {
		if o.Origin.SourceKind != "portable" || o.Origin.SourceID != source || o.TenantID != tenant {
			return domain.Unauthorized
		}
		return nil
	}
	for i, raw := range res.Accepted {
		if !until.IsZero() && time.Now().After(until) {
			report.Complete, report.Remaining = false, len(res.Accepted)-i
			break
		}
		var signed contracts.SignedObservation
		var o contracts.Observation
		_ = json.Unmarshal(raw, &signed)
		_ = json.Unmarshal(signed.Payload, &o)
		result, e := r.IngestAuthorized(ctx, tenant, source, raw, authorize)
		if e != nil {
			if !errors.Is(e, domain.Invalid) && !errors.Is(e, domain.Conflict) && !errors.Is(e, domain.Unauthorized) {
				return report, e // инфраструктурный сбой: повторная загрузка продолжит с того же места (применённое не дублируется)
			}
			reason := "SCHEMA_INVALID"
			if errors.Is(e, domain.Conflict) {
				reason = "SEQUENCE_CONFLICT"
			}
			if errors.Is(e, domain.Unauthorized) {
				reason = "SOURCE_NOT_AUTHORIZED"
			}
			report.Records = append(report.Records, PortableRecord{ObservationID: o.ID, Disposition: "rejected", Reason: reason})
			continue
		}
		rec := PortableRecord{ObservationID: o.ID, Disposition: result.Disposition, Reason: result.Reason}
		if result.AssetID != nil {
			rec.AssetID = *result.AssetID
		}
		if result.Duplicate {
			rec.Disposition = "duplicate"
		}
		report.Records = append(report.Records, rec)
	}
	return report, nil
}
