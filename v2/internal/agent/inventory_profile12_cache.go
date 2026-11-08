package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"crypto/ed25519"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

const profileCacheFile12 = "inventory-profile12.json"

var errProfileCache12 = errors.New("inventory profile cache rejected")

// cachedProfile12 хранит исходные подписанные байты ответа центра, а не пересказ:
// при каждой загрузке подпись и область проверяются заново.
type cachedProfile12 struct {
	Version  int       `json:"version"`
	Accepted time.Time `json:"accepted_at"`
	Raw      []byte    `json:"signed_response"`
}

type profileScope12 struct {
	Tenant    string
	Origin    contracts.Origin
	Collector string
	KeyID     string
	Public    ed25519.PublicKey
}

// loadInventoryProfile12 читает и заново проверяет кэш. Отсутствие файла — (_, false, nil);
// любая порча, чужая область, смена поколения или ключа — ошибка, а не «нет кэша».
func loadInventoryProfile12(dir string, s profileScope12) (contracts.InventoryProfile12, []byte, bool, error) {
	var none contracts.InventoryProfile12
	path := filepath.Join(dir, profileCacheFile12)
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return none, nil, false, nil
	}
	data, e := privatefile.Read(path, wire.InventoryProfileMaxBytes12+4096)
	if e != nil {
		return none, nil, false, errProfileCache12
	}
	var saved cachedProfile12
	if json.Unmarshal(data, &saved) != nil || saved.Version != 1 {
		return none, nil, false, errProfileCache12
	}
	p, e := wire.VerifyCachedInventoryProfile12(saved.Raw, s.Tenant, s.Origin, s.Collector, s.KeyID, s.Public)
	if e != nil {
		return none, nil, false, errProfileCache12
	}
	return p, saved.Raw, true, nil
}

// commitInventoryProfile12 сохраняет профиль, только что принятый FetchInventoryProfile12.
// Вызывать под блокировкой состояния. Эффективная ревизия не убывает; та же ревизия с
// иной конфигурацией отвергается, чтобы смысл политики не менялся под прежним номером.
func commitInventoryProfile12(dir string, sel InventoryProfileSelection12, s profileScope12) error {
	p, e := wire.VerifyCachedInventoryProfile12(sel.Raw, s.Tenant, s.Origin, s.Collector, s.KeyID, s.Public)
	if e != nil {
		return errProfileCache12
	}
	newRev, e := wire.ProfileRevision12(p.Config.Revision)
	if e != nil {
		return errProfileCache12
	}
	old, _, present, e := loadInventoryProfile12(dir, s)
	if e != nil {
		return e
	}
	if present {
		oldRev, e := wire.ProfileRevision12(old.Config.Revision)
		if e != nil || newRev < oldRev || newRev == oldRev && !reflect.DeepEqual(old.Config, p.Config) {
			return errProfileCache12
		}
	}
	raw, e := json.Marshal(cachedProfile12{Version: 1, Accepted: time.Now().UTC(), Raw: sel.Raw})
	if e != nil {
		return errProfileCache12
	}
	return diskspool.Atomic(filepath.Join(dir, profileCacheFile12), raw)
}

var errNoCachedProfile12 = errors.New("no cached inventory profile")

func (c *Client) profileScope12() profileScope12 {
	return profileScope12{Tenant: c.claims.Tenant, Origin: contracts.Origin{SourceID: c.claims.Source, SourceKind: "agent", GenerationID: c.claims.Generation},
		Collector: c.claims.Collector, KeyID: c.claims.CenterKeyID, Public: c.claims.CenterPublic}
}

// appliedFromCache — ревизия, уже сохранённая durable; именно её можно сообщать центру.
func appliedFromCache(dir string, s profileScope12) (*contracts.InventoryRevision12, error) {
	p, _, present, e := loadInventoryProfile12(dir, s)
	if e != nil || !present {
		return nil, e
	}
	return &contracts.InventoryRevision12{Common: p.Config.Revision, Policy: p.Config.Policy}, nil
}

// cachedInventoryProfile12 возвращает последний принятый профиль для работы без сети.
// Лимиты — пересечение своих возможностей, лимитов профиля и максимумов; расширить
// согласованные потолки профиль не может. Свежего подтверждения трёх участков он не даёт.
func cachedInventoryProfile12(dir string, s profileScope12, own wire.InventoryOffer12) (InventoryProfileSelection12, error) {
	var empty InventoryProfileSelection12
	p, raw, present, e := loadInventoryProfile12(dir, s)
	if e != nil {
		return empty, e
	}
	if !present {
		return empty, errNoCachedProfile12
	}
	l := p.Config.Limits
	limits, e := wire.NegotiateInventory12(own, wire.InventoryOffer12{Observation12: true, Batch12: true, CanonicalBytes: l.CanonicalBytes, SignedBytes: l.SignedBytes, BatchBytes: l.BatchBytes, Records: l.Records}, wire.InventoryMaximum12())
	if e != nil {
		return empty, errProfileCache12
	}
	return InventoryProfileSelection12{Profile: p, Raw: raw, Limits: limits}, nil
}

// SyncInventoryProfile12 — один сетевой обмен: сообщает центру ревизию из durable-кэша,
// проверяет свежий ответ и только затем заменяет кэш. Вызывать под блокировкой состояния.
// Это не включает Windows runtime и не меняет уже поставленные в очередь наблюдения.
func (c *Client) SyncInventoryProfile12(ctx context.Context, negotiated InventoryNegotiation12) (InventoryProfileSelection12, error) {
	var empty InventoryProfileSelection12
	scope, dir := c.profileScope12(), c.cfg.State
	applied, e := appliedFromCache(dir, scope)
	if e != nil {
		return empty, e
	}
	selection, e := c.fetchInventoryProfile12(ctx, negotiated, applied)
	if e != nil {
		return empty, e
	}
	if e = commitInventoryProfile12(dir, selection, scope); e != nil {
		return empty, e
	}
	return selection, nil
}

// CachedInventoryProfile12 — офлайн-доступ к последнему принятому профилю.
func (c *Client) CachedInventoryProfile12(own wire.InventoryOffer12) (InventoryProfileSelection12, error) {
	return cachedInventoryProfile12(c.cfg.State, c.profileScope12(), own)
}
