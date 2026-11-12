package app

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/bao"
)

// C31.05 (решение пользователя 2026-11-12: интеграции включаются из Web без ручной правки конфигурации центра):
// хранилище секретов интеграций. В эксплуатации — OpenBao KV (раздел integrations_path, центр сам пишет и читает);
// без OpenBao (стенд разработки) — приватные файлы 0600 в каталоге 0700 рядом с конфигурацией центра.
// Секреты не возвращаются через API и не пишутся в журнал.

type SecretStore interface {
	Get(ctx context.Context, scope, key string) ([]byte, bool, error)
	Put(ctx context.Context, scope, key string, value []byte) error
	Kind() string
}

var ErrSecretsUnavailable = errors.New("integration secret store not configured")

var secretName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}$`)

type baoSecrets struct{ c *bao.Client }

func (s baoSecrets) Get(ctx context.Context, scope, key string) ([]byte, bool, error) {
	return s.c.ReadIntegration(ctx, scope, key)
}
func (s baoSecrets) Put(ctx context.Context, scope, key string, value []byte) error {
	return s.c.WriteIntegration(ctx, scope, key, value)
}
func (baoSecrets) Kind() string { return "openbao" }

// FileSecrets — приватные файлы (только без OpenBao).
type FileSecrets struct{ Dir string }

func (s FileSecrets) path(scope, key string) (string, error) {
	if !secretName.MatchString(scope) || !secretName.MatchString(key) {
		return "", ErrSecretsUnavailable
	}
	return filepath.Join(s.Dir, scope, key), nil
}

func (s FileSecrets) Get(_ context.Context, scope, key string) ([]byte, bool, error) {
	p, e := s.path(scope, key)
	if e != nil {
		return nil, false, e
	}
	if _, e = os.Lstat(p); errors.Is(e, os.ErrNotExist) {
		return nil, false, nil
	}
	raw, e := ReadPrivate(p, 65536)
	if e != nil {
		return nil, false, e
	}
	return raw, true, nil
}

func (s FileSecrets) Put(_ context.Context, scope, key string, value []byte) error {
	p, e := s.path(scope, key)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(p), 0o700); e != nil {
		return e
	}
	_ = os.Chmod(s.Dir, 0o700)
	_ = os.Chmod(filepath.Dir(p), 0o700)
	tmp, e := os.CreateTemp(filepath.Dir(p), ".tmp-")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	if e = tmp.Chmod(0o600); e == nil {
		if _, e = tmp.Write(value); e == nil {
			e = tmp.Sync()
		}
	}
	if ce := tmp.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(tmp.Name(), p)
}

func (FileSecrets) Kind() string { return "file" }

const centerScope = "center"

// EnableWebhooks — включение уведомлений из Web: центр создаёт мастер-ключ (32 случайных байта) в хранилище
// секретов, если его ещё нет, и начинает доставку. Ключ не показывается.
func (r *Registry) EnableWebhooks(ctx context.Context) (bool, error) {
	r.hooksMu.Lock()
	defer r.hooksMu.Unlock()
	if r.Webhooks != nil {
		return false, nil
	}
	if r.Secrets == nil {
		return false, ErrSecretsUnavailable
	}
	master, ok, e := r.Secrets.Get(ctx, centerScope, "webhook-master")
	if e != nil {
		return false, e
	}
	created := false
	if !ok {
		master = make([]byte, 32)
		if _, e = rand.Read(master); e != nil {
			return false, e
		}
		if e = r.Secrets.Put(ctx, centerScope, "webhook-master", master); e != nil {
			return false, e
		}
		created = true
	}
	sender, e := newWebhookSender(master)
	if e != nil {
		return false, e
	}
	r.Webhooks = sender
	if r.startWebhooks != nil {
		r.startWebhooks()
	}
	return created, nil
}

// LoadIntegrations — при старте центра: ранее включённые из Web уведомления (мастер-ключ в хранилище).
func (r *Registry) LoadIntegrations(ctx context.Context) error {
	if r.Webhooks != nil || r.Secrets == nil {
		return nil
	}
	master, ok, e := r.Secrets.Get(ctx, centerScope, "webhook-master")
	if e != nil || !ok {
		return e
	}
	r.Webhooks, e = newWebhookSender(master)
	return e
}

// OnWebhooksEnabled задаёт запуск фоновой доставки: сразу, если уведомления уже включены, иначе — при включении из Web.
func (r *Registry) OnWebhooksEnabled(start func()) {
	r.hooksMu.Lock()
	defer r.hooksMu.Unlock()
	once := sync.OnceFunc(start)
	r.startWebhooks = once
	if r.Webhooks != nil {
		once()
	}
}

// WatchIntegrations — для worker-процесса: уведомления включают в Web через api-процесс, а доставку ведёт worker;
// раз в 30 с проверяется хранилище секретов, и при появлении мастер-ключа запускается доставка.
func (r *Registry) WatchIntegrations(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for r.sender() == nil {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		r.hooksMu.Lock()
		if r.Webhooks == nil && r.Secrets != nil {
			if master, ok, e := r.Secrets.Get(ctx, centerScope, "webhook-master"); e == nil && ok {
				if sender, e := newWebhookSender(master); e == nil {
					r.Webhooks = sender
					if r.startWebhooks != nil {
						r.startWebhooks()
					}
				}
			}
		}
		r.hooksMu.Unlock()
	}
}
