// Package portable — формат и импорт offline-пакета portable-аудита (C23.01/C23.03).
// Контейнер — ZIP (stdlib) с плоскими файлами: manifest.json, manifest.sig, obs/<observation_id>.json.
// Подпись — Ed25519 (stdlib) по JCS-канонизированному manifest.json; manifest содержит SHA-256 каждого наблюдения.
// Самодельных примитивов нет. Шифрование пакета НЕ реализовано (пакет содержит инвентарь, не секреты; перенос — по
// доверенному каналу/носителю). Пакет не содержит паролей и bundle; импорт отвергает пути вне плоской схемы, zip-бомбы
// (лимиты числа файлов/размера/степени сжатия), неверную подпись/ключ, несовпадение digest, одинаковый ID с другим digest.
package portable

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

const FormatVersion = 1

var (
	ErrFormat    = errors.New("portable: invalid package")
	ErrSignature = errors.New("portable: signature or key is not trusted")
	ErrLimits    = errors.New("portable: package exceeds import limits")
)

type Limits struct {
	MaxFiles        int
	MaxFileBytes    int64
	MaxTotalBytes   int64
	MaxRatio        int64 // допустимое отношение распакованного к сжатому
	MaxPackageBytes int64
}

func DefaultLimits() Limits {
	return Limits{MaxFiles: 10001, MaxFileBytes: 4 << 20, MaxTotalBytes: 256 << 20, MaxRatio: 100, MaxPackageBytes: 128 << 20}
}

type Item struct {
	ID     string `json:"observation_id"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	Format    int       `json:"format_version"`
	Tenant    string    `json:"tenant_id"`
	SourceID  string    `json:"source_id"`
	KeyID     string    `json:"key_id"`
	CreatedAt time.Time `json:"created_at"`
	Items     []Item    `json:"observations"`
}

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// KeyID — идентификатор открытого ключа: первые 16 байт SHA-256 в форме UUID (как key_id привязки ключа в центре).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	h := hex.EncodeToString(sum[:16])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// observationDomain — доменный префикс подписи наблюдения (тот же, что у агента и проверки в центре).
const observationDomain = "SURVEYSCAN-OBSERVATION-V1\n"

// SignObservation подписывает JSON наблюдения так же, как агент: JCS-канонизация, SHA-256, Ed25519 по домену.
func SignObservation(priv ed25519.PrivateKey, payload []byte) ([]byte, error) {
	canonical, err := wire.Canonical(payload)
	if err != nil {
		return nil, ErrFormat
	}
	sum := sha256.Sum256(canonical)
	sig := ed25519.Sign(priv, append([]byte(observationDomain), canonical...))
	return wire.RecordJSON(contracts.SignedObservation{Payload: canonical, Digest: hex.EncodeToString(sum[:]),
		KeyID: KeyID(priv.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(sig)})
}

// openSigned проверяет подписанную запись ключом pub и возвращает её полезную нагрузку.
func openSigned(raw []byte, pub ed25519.PublicKey, keyID string) ([]byte, bool) {
	var so contracts.SignedObservation
	if json.Unmarshal(raw, &so) != nil || so.KeyID != keyID || len(so.Payload) == 0 {
		return nil, false
	}
	canonical, err := wire.Canonical(so.Payload)
	if err != nil || !bytes.Equal(canonical, so.Payload) {
		return nil, false
	}
	sum := sha256.Sum256(canonical)
	sig, err := base64.RawURLEncoding.Strict().DecodeString(so.Signature)
	if err != nil || so.Digest != hex.EncodeToString(sum[:]) || !ed25519.Verify(pub, append([]byte(observationDomain), canonical...), sig) {
		return nil, false
	}
	return canonical, true
}

func signedID(raw []byte) string {
	var so contracts.SignedObservation
	if json.Unmarshal(raw, &so) != nil {
		return ""
	}
	var head struct {
		ID string `json:"observation_id"`
	}
	if json.Unmarshal(so.Payload, &head) != nil {
		return ""
	}
	return head.ID
}

// Write собирает подписанный пакет. observations — подписанные наблюдения (SignObservation тем же ключом).
func Write(w io.Writer, priv ed25519.PrivateKey, tenant, source string, created time.Time, observations [][]byte) error {
	pub := priv.Public().(ed25519.PublicKey)
	m := Manifest{Format: FormatVersion, Tenant: tenant, SourceID: source, KeyID: KeyID(pub), CreatedAt: created.UTC()}
	files := map[string][]byte{}
	for _, raw := range observations {
		id := signedID(raw)
		if !idPattern.MatchString(id) {
			return ErrFormat
		}
		if _, ok := openSigned(raw, pub, m.KeyID); !ok {
			return ErrFormat // в пакет не попадают записи, подписанные не ключом пакета
		}
		if _, dup := files["obs/"+id+".json"]; dup {
			return ErrFormat
		}
		sum := sha256.Sum256(raw)
		m.Items = append(m.Items, Item{ID: id, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(raw))})
		files["obs/"+id+".json"] = raw
	}
	sort.Slice(m.Items, func(i, j int) bool { return m.Items[i].ID < m.Items[j].ID })
	mb, err := json.Marshal(m)
	if err != nil {
		return err
	}
	canon, err := wire.Canonical(mb)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, signedBytes(canon))
	zw := zip.NewWriter(w)
	put := func(name string, b []byte) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = f.Write(b)
		return err
	}
	if err = put("manifest.json", canon); err != nil {
		return err
	}
	if err = put("manifest.sig", []byte(base64.StdEncoding.EncodeToString(sig))); err != nil {
		return err
	}
	for _, it := range m.Items {
		if err = put("obs/"+it.ID+".json", files["obs/"+it.ID+".json"]); err != nil {
			return err
		}
	}
	return zw.Close()
}

// signedBytes — подписываемые байты: доменный префикс + канонический manifest (чтобы подпись не переиспользовалась в другом контексте).
func signedBytes(canonical []byte) []byte {
	return append([]byte("SURVEYSCAN-PORTABLE-MANIFEST-V1\n"), canonical...)
}

// Known — состояние уже импортированных наблюдений (ID → digest) для дедупликации между пакетами.
type Known map[string]string

type Rejected struct {
	ID     string
	Reason string
}

type Result struct {
	Manifest    Manifest
	Accepted    [][]byte // подписанные наблюдения (SignedObservation), прошедшие все проверки (по порядку manifest)
	Duplicates  []string // тот же ID и тот же digest — пропущены
	Quarantined []Rejected
}

func readLimited(f *zip.File, max int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, ErrFormat
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, ErrLimits
	}
	return b, nil
}

// Import проверяет пакет целиком и возвращает принятые наблюдения. trust — доверенные ключи (KeyID → публичный ключ).
// Нарушение пакета целиком (структура, лимиты, подпись) → ошибка без приёма чего-либо; плохое отдельное наблюдение
// (digest, схема, ID с другим digest) → карантин, остальное принимается. Late-наблюдения (старый collected_at) принимаются.
func Import(data []byte, trust map[string]ed25519.PublicKey, known Known, lim Limits, v *wire.Inventory12Validator) (Result, error) {
	var res Result
	if int64(len(data)) > lim.MaxPackageBytes {
		return res, ErrLimits
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return res, ErrFormat
	}
	if len(zr.File) > lim.MaxFiles {
		return res, ErrLimits
	}
	entries := map[string]*zip.File{}
	var total int64
	for _, f := range zr.File {
		name := f.Name
		// только плоская схема: manifest.json, manifest.sig, obs/<uuid>.json; никаких .., абсолютных путей, обратных слэшей
		ok := name == "manifest.json" || name == "manifest.sig" ||
			(strings.HasPrefix(name, "obs/") && strings.HasSuffix(name, ".json") && idPattern.MatchString(strings.TrimSuffix(strings.TrimPrefix(name, "obs/"), ".json")))
		if !ok || f.FileInfo().IsDir() || f.Mode()&0o170000 != 0 && !f.Mode().IsRegular() {
			return res, ErrFormat
		}
		if _, dup := entries[name]; dup {
			return res, ErrFormat
		}
		if int64(f.UncompressedSize64) > lim.MaxFileBytes {
			return res, ErrLimits
		}
		if f.CompressedSize64 > 0 && int64(f.UncompressedSize64) > int64(f.CompressedSize64)*lim.MaxRatio && f.UncompressedSize64 > 1<<20 {
			return res, ErrLimits
		}
		total += int64(f.UncompressedSize64)
		if total > lim.MaxTotalBytes {
			return res, ErrLimits
		}
		entries[name] = f
	}
	mf, sf := entries["manifest.json"], entries["manifest.sig"]
	if mf == nil || sf == nil {
		return res, ErrFormat
	}
	canon, err := readLimited(mf, lim.MaxFileBytes)
	if err != nil {
		return res, err
	}
	sigB64, err := readLimited(sf, 4096)
	if err != nil {
		return res, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return res, ErrSignature
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(canon))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&m); err != nil || m.Format != FormatVersion {
		return res, ErrFormat
	}
	pub, trusted := trust[m.KeyID]
	if !trusted || KeyID(pub) != m.KeyID || !ed25519.Verify(pub, signedBytes(canon), sig) {
		return res, ErrSignature
	}
	// подписанный manifest должен быть в канонической форме (иначе подпись покрывает не те байты, что разобрал импорт)
	if again, e := wire.Canonical(canon); e != nil || !bytes.Equal(again, canon) {
		return res, ErrFormat
	}
	res.Manifest = m
	if len(m.Items) != len(entries)-2 {
		return res, ErrFormat // лишние файлы вне manifest
	}
	seen := map[string]bool{}
	for _, it := range m.Items {
		if seen[it.ID] || !idPattern.MatchString(it.ID) {
			return res, ErrFormat
		}
		seen[it.ID] = true
		f := entries["obs/"+it.ID+".json"]
		if f == nil {
			return res, ErrFormat
		}
		raw, err := readLimited(f, lim.MaxFileBytes)
		if err != nil {
			return res, err
		}
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		if digest != it.SHA256 || int64(len(raw)) != it.Size {
			res.Quarantined = append(res.Quarantined, Rejected{it.ID, "DIGEST_MISMATCH"})
			continue
		}
		if prev, ok := known[it.ID]; ok {
			if prev == digest {
				res.Duplicates = append(res.Duplicates, it.ID)
			} else {
				res.Quarantined = append(res.Quarantined, Rejected{it.ID, "SAME_ID_DIFFERENT_DIGEST"})
			}
			continue
		}
		payload, ok := openSigned(raw, pub, m.KeyID)
		if !ok {
			res.Quarantined = append(res.Quarantined, Rejected{it.ID, "RECORD_SIGNATURE_INVALID"})
			continue
		}
		var head struct {
			ID     string `json:"observation_id"`
			Tenant string `json:"tenant_id"`
			Origin struct {
				SourceID string `json:"source_id"`
				Kind     string `json:"source_kind"`
			} `json:"origin"`
		}
		if json.Unmarshal(payload, &head) != nil || head.ID != it.ID || head.Tenant != m.Tenant || head.Origin.SourceID != m.SourceID || head.Origin.Kind != "portable" {
			res.Quarantined = append(res.Quarantined, Rejected{it.ID, "IDENTITY_MISMATCH"})
			continue
		}
		if v != nil {
			if _, err := v.Payload(payload); err != nil {
				res.Quarantined = append(res.Quarantined, Rejected{it.ID, fmt.Sprint("SCHEMA_INVALID")})
				continue
			}
		}
		known[it.ID] = digest
		res.Accepted = append(res.Accepted, raw)
	}
	return res, nil
}
