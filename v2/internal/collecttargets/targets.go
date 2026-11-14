//go:build linux

package collecttargets

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/agent"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/telemetry"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/sshlinux"
)

// Package collecttargets — C51.03 шаг C: цели удалённого сбора, заведённые в Web. Для каждой цели collector держит отдельную личность агента
// (состояние в своём каталоге учётных данных), регистрирует её по grant центра обычным путём агента через себя
// и собирает узел по SSH/WinRM; учётку берёт у центра по mTLS перед каждым сбором и держит только в памяти.

type machineTarget struct {
	ID         string  `json:"target_id"`
	Kind       string  `json:"kind"`
	Address    string  `json:"address"`
	Port       int     `json:"port"`
	Username   string  `json:"username"`
	HostKey    *string `json:"host_key_sha256"`
	CAPEM      *string `json:"tls_ca_pem"`
	ServerName *string `json:"tls_server_name"`
	Interval   int     `json:"interval_seconds"`
	Source     *string `json:"agent_source_id"`
	State      string  `json:"state"`
	Site       string  `json:"site_id"`
	Scope      string  `json:"network_scope_id"`
	Tenant     string  `json:"tenant_id"`
}

func (t machineTarget) key() string {
	s := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return strings.Join([]string{t.Kind, t.Address, strconv.Itoa(t.Port), t.Username, s(t.HostKey), s(t.CAPEM), s(t.ServerName)}, "\x00")
}

// Manager — цели одного collector. Post — запрос к центру по mTLS collector; Listen — слушатель collector для
// встроенных агентов; CollectorSource — личность collector; CA — файл CA; StateDir — каталог учётных данных.
type Manager struct {
	Post            func(ctx context.Context, path string, raw []byte) (int, []byte, error)
	Listen          string
	CollectorSource string
	CA              string
	StateDir        string
	set             targetSet
}

type targetRun struct {
	key    string
	cancel context.CancelFunc
}

type targetSet struct {
	mu   sync.Mutex
	runs map[string]targetRun
}

// selfURL — собственный слушатель collector для встроенных агентов целей (имя сервера проверяется по личности
// collector, а не по адресу).
func (c *Manager) selfURL() string {
	host, port, e := net.SplitHostPort(c.Listen)
	if e != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "https://" + net.JoinHostPort(host, port)
}

func (c *Manager) targetPost(ctx context.Context, path string, body any) (int, []byte, error) {
	raw, _ := json.Marshal(body)
	return c.Post(ctx, path, raw)
}

// targetsTick сверяет запущенные цели с целями центра: новые запускает, изменённые перезапускает, снятые — гасит.
// Tick сверяет запущенные цели с целями центра (запрос — в рамках task, цели живут в рамках ctx).
func (c *Manager) Tick(ctx, task context.Context) error {
	code, raw, e := c.targetPost(task, "/api/v1/machine/collect-targets", struct{}{})
	if e != nil {
		return e
	}
	if code == 404 || code == 501 {
		return nil
	}
	if code != 200 {
		return errors.New("collect targets unavailable")
	}
	var got struct {
		Items []machineTarget `json:"items"`
	}
	if e = json.Unmarshal(raw, &got); e != nil {
		return e
	}
	set := &c.set
	set.mu.Lock()
	if set.runs == nil {
		set.runs = map[string]targetRun{}
	}
	defer set.mu.Unlock()
	seen := map[string]bool{}
	for _, t := range got.Items {
		if !identifier.Valid(t.ID) || (t.Kind != "ssh" && t.Kind != "winrm" && t.Kind != "snmp") {
			continue
		}
		seen[t.ID] = true
		if r, ok := set.runs[t.ID]; ok {
			if r.key == t.key() {
				continue
			}
			r.cancel()
		}
		runCtx, cancel := context.WithCancel(ctx)
		set.runs[t.ID] = targetRun{key: t.key(), cancel: cancel}
		go c.runTarget(runCtx, t)
	}
	for id, r := range set.runs {
		if !seen[id] {
			r.cancel()
			delete(set.runs, id)
		}
	}
	return nil
}

func (c *Manager) report(ctx context.Context, target string, ok bool, problem string) {
	task, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_, _, _ = c.targetPost(task, "/api/v1/machine/collect-targets/"+target+"/report", map[string]any{"ok": ok, "problem": problem})
}

type issuedSecret struct {
	Kind     string `json:"kind"`
	Username string `json:"username"`
	Secret   struct {
		Password     string `json:"password"`
		PrivateKey   string `json:"private_key"`
		Passphrase   string `json:"passphrase"`
		AuthProtocol string `json:"auth_protocol"`
		AuthKey      string `json:"auth_key"`
		PrivProtocol string `json:"priv_protocol"`
		PrivKey      string `json:"priv_key"`
	} `json:"secret"`
}

func (c *Manager) secret(ctx context.Context, target string) (issuedSecret, error) {
	var out issuedSecret
	code, raw, e := c.targetPost(ctx, "/api/v1/machine/collect-targets/"+target+"/secret", struct{}{})
	if e != nil || code != 200 {
		return out, errors.New("credential not issued")
	}
	return out, json.Unmarshal(raw, &out)
}

// enrollTarget — личность агента цели: подготовка (ключи и CSR в каталоге цели), grant центра, регистрация.
func (c *Manager) enrollTarget(ctx context.Context, cfg agent.Config, t machineTarget) error {
	if _, e := os.Stat(filepath.Join(cfg.State, "identity.json")); e == nil {
		return nil
	}
	prep, e := agent.Prepare(cfg)
	if e != nil {
		return e
	}
	code, raw, e := c.targetPost(ctx, "/api/v1/machine/collect-targets/"+t.ID+"/grant", map[string]string{"source_id": prep.Source, "csr_sha256": prep.Hash, "signing_public_key": prep.Public})
	if e != nil || code != 200 {
		return errors.New("target grant not issued")
	}
	var grant contracts.EnrollmentGrant
	if e = json.Unmarshal(raw, &grant); e != nil {
		return e
	}
	return agent.Enroll(ctx, cfg, grant)
}

func (c *Manager) runTarget(ctx context.Context, t machineTarget) {
	platform := contracts.InventoryPlatformLinux12
	if t.Kind == "winrm" {
		platform = contracts.InventoryPlatform12
	} else if t.Kind == "snmp" {
		platform = contracts.InventoryPlatformNetwork12
	}
	state := filepath.Join(c.StateDir, "targets", t.ID)
	if e := os.MkdirAll(state, 0o700); e != nil {
		telemetry.Log(os.Stderr, "collector", "target_state_unavailable")
		return
	}
	cfg := agent.Config{Tenant: t.Tenant, Site: t.Site, Scope: t.Scope, CollectorURL: c.selfURL(), CollectorSource: c.CollectorSource, CA: c.CA,
		State: state, InventorySeconds: max(t.Interval, 300), HeartbeatSeconds: 300, Jitter: 10, Limit: 16 << 20, InventoryPlatform: platform}
	report := func(s string) {
		if !strings.HasPrefix(s, "detail:") {
			telemetry.Log(os.Stderr, "collector", "target_"+t.ID[:8]+"_"+s) // состояние цикла цели (без секретов)
		}
		switch {
		case s == "inventory_queued":
			c.report(ctx, t.ID, true, "")
		case s == "inventory_failed" || s == "inventory_collection_deadline":
			c.report(ctx, t.ID, false, s)
		}
	}
	for ctx.Err() == nil {
		e := c.enrollTarget(ctx, cfg, t)
		if e == nil {
			c.report(ctx, t.ID, false, "") // регистрация завершена: центр переводит цель в active
			addr := net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
			switch t.Kind {
			case "ssh":
				fetch := func(ctx context.Context) (sshlinux.Secret, error) {
					s, err := c.secret(ctx, t.ID)
					out := sshlinux.Secret{Password: s.Secret.Password, Passphrase: s.Secret.Passphrase}
					if s.Secret.PrivateKey != "" {
						out.PrivateKeyPEM = []byte(s.Secret.PrivateKey)
					}
					return out, err
				}
				target := agent.SSHTarget{Addr: addr, User: t.Username, Secret: fetch}
				if t.HostKey != nil {
					target.HostKeySHA256 = *t.HostKey
				} else {
					// отпечаток не задан: читаем ключ хоста без входа и закрепляем его на центре (как known_hosts);
					// при смене ключа центр отвечает Conflict, сбор останавливается до сброса в Web
					task, cancel := context.WithTimeout(ctx, 20*time.Second)
					fp, err := sshlinux.FetchHostKey(task, addr, 15*time.Second)
					if err == nil {
						var code int
						code, _, err = c.targetPost(task, "/api/v1/machine/collect-targets/"+t.ID+"/hostkey", map[string]string{"host_key_sha256": fp})
						if err == nil && code != 204 {
							err = errors.New("host key not accepted")
						}
					}
					cancel()
					if err != nil {
						e = err
						break
					}
					target.HostKeySHA256 = fp
				}
				e = agent.RunSSH12(ctx, cfg, target, report)
			case "winrm":
				fetch := func(ctx context.Context) ([]byte, error) {
					s, err := c.secret(ctx, t.ID)
					return []byte(s.Secret.Password), err
				}
				target := agent.WinRMTarget{Host: t.Address, Port: t.Port, User: t.Username, Password: fetch}
				if t.CAPEM != nil {
					target.CAPEM = []byte(*t.CAPEM)
				}
				if t.ServerName != nil {
					target.ServerName = *t.ServerName
				}
				e = agent.RunWinRM12(ctx, cfg, target, report)
			case "snmp":
				// протоколы известны только вместе с ключами: первая выдача учётки — до запуска цикла
				first, err := c.secret(ctx, t.ID)
				if err != nil {
					e = err
					break
				}
				keys := func(ctx context.Context) ([]byte, []byte, error) {
					s, err := c.secret(ctx, t.ID)
					return []byte(s.Secret.AuthKey), []byte(s.Secret.PrivKey), err
				}
				e = agent.RunSNMP12(ctx, cfg, agent.SNMPTarget{Addr: addr, User: t.Username, AuthProto: first.Secret.AuthProtocol, PrivProto: first.Secret.PrivProtocol, Keys: keys}, report)
			}
		}
		if ctx.Err() != nil {
			return
		}
		if e != nil {
			c.report(ctx, t.ID, false, "collector:"+shortError(e))
			telemetry.Log(os.Stderr, "collector", "target_run_failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

func shortError(e error) string {
	var st *agent.StageError
	if errors.As(e, &st) {
		return "stage" + strconv.Itoa(int(st.Code))
	}
	return "failed"
}
