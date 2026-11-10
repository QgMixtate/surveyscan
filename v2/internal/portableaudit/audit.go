// Package portableaudit — разовый portable-аудит (C23.02): без службы, без центра, без PG/Bao. Собирает этот хост
// и/или удалённые цели (SSH/WinRM), строит наблюдения профиля 1.2 с source_kind=portable, проверяет каждое схемой
// и экспортирует подписанный пакет формата internal/portable. Прерывание не оставляет частичного файла.
package portableaudit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/agent"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/QgMixtate/surveyscan/v2/internal/portable"
)

// Identity — личность portable-источника. Ключ подписи хранится отдельно (signing.key, 0600) и в пакет не попадает.
type Identity struct {
	Tenant     string `json:"tenant_id"`
	Site       string `json:"site_id"`
	Scope      string `json:"network_scope_id"`
	SourceID   string `json:"source_id"`
	Generation string `json:"generation_id"`
	KeyID      string `json:"key_id"`
}

var ErrExists = errors.New("portable: state directory already initialised")

func writePrivate(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Init создаёт личность и ключ в пустом/новом каталоге (0700). Существующая личность не перезаписывается.
func Init(dir, tenant, site, scope string) (Identity, ed25519.PublicKey, error) {
	var id Identity
	if !identifier.Valid(tenant) || !identifier.Valid(site) || !identifier.Valid(scope) {
		return id, nil, errors.New("portable: tenant, site and scope must be UUIDs issued by the centre")
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.json")); err == nil {
		return id, nil, ErrExists
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return id, nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return id, nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return id, nil, err
	}
	id = Identity{Tenant: tenant, Site: site, Scope: scope, SourceID: identifier.New(), Generation: identifier.New(), KeyID: portable.KeyID(pub)}
	if err = writePrivate(filepath.Join(dir, "signing.key"), []byte(base64.StdEncoding.EncodeToString(priv.Seed()))); err != nil {
		return Identity{}, nil, err
	}
	raw, _ := json.MarshalIndent(id, "", "  ")
	if err = writePrivate(filepath.Join(dir, "identity.json"), raw); err != nil {
		return Identity{}, nil, err
	}
	return id, pub, nil
}

// Load читает личность и ключ (оба файла обязаны быть приватными).
func Load(dir string) (Identity, ed25519.PrivateKey, error) {
	var id Identity
	raw, err := privatefile.Read(filepath.Join(dir, "identity.json"), 65536)
	if err != nil {
		return id, nil, errors.New("portable: identity unavailable or not private (run init)")
	}
	if err = json.Unmarshal(raw, &id); err != nil || !identifier.Valid(id.SourceID) || !identifier.Valid(id.Generation) {
		return id, nil, errors.New("portable: identity invalid")
	}
	seedB64, err := privatefile.Read(filepath.Join(dir, "signing.key"), 4096)
	if err != nil {
		return id, nil, errors.New("portable: signing key unavailable or not private")
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedB64)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return id, nil, errors.New("portable: signing key invalid")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if portable.KeyID(priv.Public().(ed25519.PublicKey)) != id.KeyID {
		return id, nil, errors.New("portable: signing key does not match identity")
	}
	return id, priv, nil
}

// nextSequence выдаёт монотонный номер наблюдения и сохраняет его ДО экспорта: номер никогда не переиспользуется,
// даже если экспорт прервётся (пропуски допустимы, повторы — нет).
func nextSequence(dir string) (uint64, error) {
	path := filepath.Join(dir, "sequence")
	var n uint64
	if raw, err := os.ReadFile(path); err == nil {
		if n, err = strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); err != nil {
			return 0, errors.New("portable: sequence file corrupt")
		}
	}
	n++
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := writePrivate(tmp, []byte(strconv.FormatUint(n, 10))); err != nil {
		return 0, err
	}
	return n, os.Rename(tmp, path)
}

// Target — одна цель аудита: этот хост или удалённая (SSH/WinRM).
type Target struct {
	Kind    string // host | ssh | winrm
	Name    string // адрес/имя для source_record и отчёта
	Collect func(context.Context) (agent.Snapshot, error)
}

// Result — итог по цели для предпросмотра.
type Result struct {
	Target   string
	Kind     string
	Err      string
	Sections map[string]string // секция -> status/reason
	Rows     int
}

type Report struct {
	Results     []Result
	Exported    int
	Package     string
	SourceID    string
	KeyID       string
	Observation []string // ID экспортированных наблюдений
}

// Run собирает цели по очереди, строит и проверяет наблюдения и (если out != "") экспортирует пакет.
// Ошибка одной цели не прерывает остальные; отмена ctx прерывает всё без записи пакета.
func Run(ctx context.Context, dir string, targets []Target, out string, progress func(string)) (Report, error) {
	var rep Report
	if progress == nil {
		progress = func(string) {}
	}
	id, key, err := Load(dir)
	if err != nil {
		return rep, err
	}
	rep.SourceID, rep.KeyID = id.SourceID, id.KeyID
	if out != "" {
		if _, err := os.Stat(out); err == nil {
			return rep, fmt.Errorf("portable: %s already exists (packages are never overwritten)", out)
		}
	}
	v, err := wire.NewInventory12()
	if err != nil {
		return rep, err
	}
	var observations [][]byte
	for i, t := range targets {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		progress(fmt.Sprintf("[%d/%d] %s %s: collecting", i+1, len(targets), t.Kind, t.Name))
		res := Result{Target: t.Name, Kind: t.Kind, Sections: map[string]string{}}
		snap, err := t.Collect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return rep, ctx.Err()
			}
			res.Err = err.Error()
			rep.Results = append(rep.Results, res)
			progress(fmt.Sprintf("[%d/%d] %s %s: failed (%s)", i+1, len(targets), t.Kind, t.Name, res.Err))
			continue
		}
		for _, s := range snap.Sections {
			res.Sections[s.Name] = s.Status + "/" + s.Reason
			res.Rows += len(s.Records)
		}
		seq, err := nextSequence(dir)
		if err != nil {
			return rep, err
		}
		collected := time.Now().UTC()
		for i := range snap.Sections { // секции не новее наблюдения
			if snap.Sections[i].CollectedAt.After(collected) {
				snap.Sections[i].CollectedAt = collected
			}
		}
		o := contracts.Observation{Version: contracts.Version{Major: 1, Minor: 2}, ID: identifier.New(), TenantID: id.Tenant,
			Origin: contracts.Origin{SourceID: id.SourceID, SourceKind: "portable", GenerationID: id.Generation},
			Record: contracts.SourceRecord{Namespace: "host", LocalID: t.Kind + ":" + t.Name}, Scope: contracts.Scope{SiteID: id.Site, ScopeID: id.Scope},
			Sequence: strconv.FormatUint(seq, 10), CollectedAt: collected, Clock: "estimated", Candidates: snap.Candidates, Sections: snap.Sections}
		raw, err := wire.RecordJSON(o)
		if err == nil {
			_, err = v.Payload(raw)
		}
		if err == nil {
			raw, err = portable.SignObservation(key, raw) // запись подписана так же, как у агента: центр проверяет её привязкой ключа
		}
		if err != nil {
			res.Err = "observation rejected by the 1.2 schema"
			rep.Results = append(rep.Results, res)
			progress(fmt.Sprintf("[%d/%d] %s %s: %s", i+1, len(targets), t.Kind, t.Name, res.Err))
			continue
		}
		observations = append(observations, raw)
		rep.Observation = append(rep.Observation, o.ID)
		rep.Results = append(rep.Results, res)
		progress(fmt.Sprintf("[%d/%d] %s %s: ok, %d rows", i+1, len(targets), t.Kind, t.Name, res.Rows))
	}
	if out == "" || len(observations) == 0 {
		return rep, nil // предпросмотр или нечего экспортировать
	}
	if err := ctx.Err(); err != nil {
		return rep, err
	}
	tmp := out + ".partial"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return rep, err
	}
	err = portable.Write(f, key, id.Tenant, id.SourceID, time.Now(), observations)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = publish(tmp, out)
	}
	_ = os.Remove(tmp)
	if err != nil {
		return rep, err
	}
	rep.Exported, rep.Package = len(observations), out
	progress(fmt.Sprintf("exported %d observation(s) to %s", len(observations), out))
	return rep, nil
}

// publish делает готовый пакет видимым под именем out, не перезаписывая существующий файл: жёсткая ссылка (атомарно,
// без перезаписи); если ФС её не поддерживает (FAT/exFAT на флешке) — переименование после проверки отсутствия out.
func publish(tmp, out string) error {
	err := os.Link(tmp, out)
	if err == nil || errors.Is(err, os.ErrExist) {
		return err
	}
	if _, statErr := os.Stat(out); statErr == nil {
		return os.ErrExist
	}
	return os.Rename(tmp, out)
}
