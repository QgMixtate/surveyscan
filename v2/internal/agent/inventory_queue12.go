package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// batchIdentity12 — всё, что нужно подписать наблюдение 1.2 от имени агента.
type batchIdentity12 struct {
	Tenant string
	Origin contracts.Origin
	Site   string
	Scope  string
	KeyID  string
	Key    ed25519.PrivateKey
}

var errBatch12 = errors.New("inventory 1.2 batch rejected")

// buildBatch12 превращает секции изолированных воркеров в подписанный batch 1.2.
// Секции — данные, а не полномочия: источник, ключ и tenant берутся из удостоверения агента.
// Подписывается каноническая форма (JCS) тем же доменом, что и C03, но под версией 1.2;
// результат проходит ту же схему и границы, которые согласованы между тремя участниками.
// Побочных эффектов нет: ни последовательности, ни записи на диск.
func buildBatch12(id batchIdentity12, t *wire.InventoryTransport12, sequence string, candidates []contracts.Candidate, sections []contracts.Section, collected time.Time) (string, []byte, error) {
	if t == nil || len(id.Key) != ed25519.PrivateKeySize {
		return "", nil, errBatch12
	}
	// Политика 1.2 частичная: принимающая сторона отвергает ok/complete секции, поэтому
	// такой пакет нельзя ставить в очередь: он навсегда остался бы неотправляемым.
	for _, section := range sections {
		if section.Complete || section.Status == "ok" {
			return "", nil, errBatch12
		}
	}
	o := contracts.Observation{Version: contracts.Version{Major: 1, Minor: 2}, ID: identifier.New(), TenantID: id.Tenant, Origin: id.Origin,
		Record: contracts.SourceRecord{Namespace: "host", LocalID: "host"}, Scope: contracts.Scope{SiteID: id.Site, ScopeID: id.Scope},
		Sequence: sequence, CollectedAt: collected, Clock: "trusted", Candidates: candidates, Sections: sections}
	payload, e := wire.RecordJSON(o)
	if e != nil {
		return "", nil, errBatch12
	}
	canonical, e := wire.Canonical(payload)
	if e != nil {
		return "", nil, errBatch12
	}
	sum := sha256.Sum256(canonical)
	signature := ed25519.Sign(id.Key, append([]byte("SURVEYSCAN-OBSERVATION-V1\n"), canonical...))
	signed, e := wire.RecordJSON(contracts.SignedObservation{Payload: canonical, Digest: hex.EncodeToString(sum[:]), KeyID: id.KeyID, Signature: base64.RawURLEncoding.EncodeToString(signature)})
	if e != nil {
		return "", nil, errBatch12
	}
	if _, _, _, e = t.Observation(signed); e != nil {
		return "", nil, errBatch12
	}
	batch := contracts.Batch{Version: contracts.Version{Major: 1, Minor: 2}, TenantID: id.Tenant, DeliveryID: identifier.New(), Records: []json.RawMessage{signed}}
	raw, e := wire.RecordJSON(batch)
	if e != nil {
		return "", nil, errBatch12
	}
	if _, _, e = t.Batch(raw); e != nil {
		return "", nil, errBatch12
	}
	return batch.DeliveryID, raw, nil
}

// queueSections12 вызывается только актором: он один присваивает последовательность,
// подписывает и меняет durable-состояние. Ставит в очередь уже подписанные байты; ранее
// поставленные пакеты не переписываются и не пересобираются под новые лимиты.
func (c *Client) queueSections12(ctx context.Context, t *wire.InventoryTransport12, candidates []contracts.Candidate, sections []contracts.Section, collected time.Time) error {
	if e := c.inventoryPreflight(ctx); e != nil {
		return e
	}
	sequence, e := c.next(false)
	if e != nil {
		return e
	}
	id := batchIdentity12{Tenant: c.claims.Tenant, Origin: contracts.Origin{SourceID: c.claims.Source, SourceKind: "agent", GenerationID: c.claims.Generation},
		Site: c.cfg.Site, Scope: c.cfg.Scope, KeyID: c.claims.KeyID, Key: c.key}
	delivery, raw, e := buildBatch12(id, t, sequence, candidates, sections, collected)
	if e != nil {
		return e
	}
	return writeAtomic(filepath.Join(c.cfg.State, "spool", delivery+".pending"), raw)
}
