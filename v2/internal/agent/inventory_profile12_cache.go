package agent

import (
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
