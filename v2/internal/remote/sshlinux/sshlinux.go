// Package sshlinux — безагентный сбор инвентаризации Linux по SSH (C17.03). Только фиксированный набор
// read-only команд (cat файлов /proc,/etc,/sys и systemctl/rpm list), вывод разбирается теми же чистыми
// парсерами, что у локального агента. Ключ хоста обязателен и проверяется строго (без TOFU), секрет живёт
// только в памяти вызова и никогда не попадает в argv, ошибки, строки и JSON.
package sshlinux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/agent/linuxinventory"
)

var (
	ErrHostKeyRequired = errors.New("ssh: host key fingerprint is required (trust on first use is not allowed)")
	ErrHostKeyMismatch = errors.New("ssh: host key does not match the pinned fingerprint")
	ErrAuth            = errors.New("ssh: authentication failed")
	ErrNoSecret        = errors.New("ssh: exactly one of password or private key is required")
)

// Secret — учётные данные задания. Выводятся только как «[redacted]».
type Secret struct {
	Password      string
	PrivateKeyPEM []byte
	Passphrase    string
}

func (Secret) String() string               { return "[redacted]" }
func (Secret) GoString() string             { return "sshlinux.Secret{[redacted]}" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte("[redacted]"), nil }
func (s Secret) authMethod() (ssh.AuthMethod, error) {
	hasKey, hasPass := len(s.PrivateKeyPEM) > 0, s.Password != ""
	if hasKey == hasPass {
		return nil, ErrNoSecret
	}
	if hasPass {
		return ssh.Password(s.Password), nil
	}
	var signer ssh.Signer
	var err error
	if s.Passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(s.PrivateKeyPEM, []byte(s.Passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(s.PrivateKeyPEM)
	}
	if err != nil {
		return nil, errors.New("ssh: private key cannot be parsed") // текст исходной ошибки не пробрасываем
	}
	return ssh.PublicKeys(signer), nil
}

type Target struct {
	Addr          string // host:port
	User          string
	HostKeySHA256 string // «SHA256:…» как у ssh-keygen -lf; обязателен
}

type Policy struct {
	ConnectTimeout time.Duration // одно TCP+SSH рукопожатие
	CommandTimeout time.Duration // одна команда
	TotalDeadline  time.Duration // весь сбор
	MaxOutput      int           // байт на команду
	ConnectRetries int           // повторы только при сетевых сбоях, не при отказе аутентификации/ключа
}

func (p Policy) withDefaults() Policy {
	if p.ConnectTimeout <= 0 {
		p.ConnectTimeout = 10 * time.Second
	}
	if p.CommandTimeout <= 0 {
		p.CommandTimeout = 20 * time.Second
	}
	if p.TotalDeadline <= 0 {
		p.TotalDeadline = 2 * time.Minute
	}
	if p.MaxOutput <= 0 {
		p.MaxOutput = 16 << 20
	}
	if p.ConnectRetries < 0 || p.ConnectRetries > 3 {
		p.ConnectRetries = 1
	}
	return p
}

// Fingerprint — SHA256-отпечаток открытого ключа в формате ssh-keygen.
func Fingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// FetchHostKey узнаёт отпечаток ключа хоста БЕЗ доверия к нему и без аутентификации: оператор сверяет его
// вне канала и только затем записывает в Target. Сам сбор неизвестный ключ не принимает.
func FetchHostKey(ctx context.Context, addr string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	var got string
	cfg := &ssh.ClientConfig{User: "surveyscan-probe", Timeout: timeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = Fingerprint(key)
			return errors.New("probe only")
		},
	}
	conn, err := dial(ctx, addr, cfg, timeout)
	if conn != nil {
		conn.Close()
	}
	if got != "" {
		return got, nil
	}
	if err == nil {
		err = errors.New("ssh: no host key received")
	}
	return "", err
}

func dial(ctx context.Context, addr string, cfg *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	d := net.Dialer{Timeout: timeout}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = nc.SetDeadline(time.Now().Add(timeout)) // рукопожатие ограничено
	c, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

type limited struct {
	buf  bytes.Buffer
	left int
	over bool
}

func (w *limited) Write(p []byte) (int, error) {
	if len(p) > w.left {
		w.over = true
		return 0, errors.New("output limit exceeded")
	}
	w.left -= len(p)
	return w.buf.Write(p)
}

// session выполняет одну фиксированную команду с лимитами времени и вывода. Команды строятся только из
// констант этого пакета — данные цели и оператора в командную строку не попадают.
type session struct {
	client *ssh.Client
	policy Policy
}

func (s session) run(ctx context.Context, command string) (string, bool) {
	sess, err := s.client.NewSession()
	if err != nil {
		return "", false
	}
	defer sess.Close()
	out := &limited{left: s.policy.MaxOutput}
	sess.Stdout = out
	done := make(chan error, 1)
	go func() { done <- sess.Run(command) }()
	t := time.NewTimer(s.policy.CommandTimeout)
	defer t.Stop()
	select {
	case err := <-done:
		return out.buf.String(), err == nil && !out.over
	case <-t.C:
	case <-ctx.Done():
	}
	_ = sess.Close()
	return "", false
}

// Command — фиксированные команды сбора. Любая ошибка команды → источник недоступен (секция unavailable).
const (
	cmdHostname = "LC_ALL=C hostname"
	cmdMachine  = "LC_ALL=C cat /etc/machine-id"
	cmdOSRel    = "LC_ALL=C cat /etc/os-release || cat /usr/lib/os-release"
	cmdUname    = "LC_ALL=C uname -m"
	cmdIPLink   = "LC_ALL=C ip -o link show"
	cmdIPAddr   = "LC_ALL=C ip -o addr show"
	cmdCPU      = "LC_ALL=C cat /proc/cpuinfo"
	cmdMem      = "LC_ALL=C cat /proc/meminfo"
	cmdDpkg     = "LC_ALL=C cat /var/lib/dpkg/status"
	cmdRPM      = `LC_ALL=C rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'`
	cmdAPK      = "LC_ALL=C cat /lib/apk/db/installed"
	cmdUnits    = "LC_ALL=C systemctl list-units --type=service --all --plain --no-legend --no-pager"
	cmdUnitFile = "LC_ALL=C systemctl list-unit-files --type=service --plain --no-legend --no-pager"
	cmdPasswd   = "LC_ALL=C cat /etc/passwd"
	cmdGroup    = "LC_ALL=C cat /etc/group"
	cmdMounts   = "LC_ALL=C cat /proc/self/mountinfo"
	cmdRoute    = "LC_ALL=C cat /proc/net/route"
)

var dmiNames = []string{"bios_vendor", "bios_version", "sys_vendor", "product_name", "product_serial", "product_uuid"}

func now() time.Time { return time.Now().UTC() }

func section(name string, rows []map[string]any) contracts.Section {
	if len(rows) == 0 {
		return contracts.Section{Name: name, CollectedAt: now(), Status: "unavailable", Reason: "SOURCE_UNAVAILABLE", Records: []map[string]any{}}
	}
	return contracts.Section{Name: name, CollectedAt: now(), Status: "partial", Reason: "REMOTE_SSH_PARTIAL", Count: len(rows), Records: rows}
}

func failed(name, status, reason string) contracts.Section {
	return contracts.Section{Name: name, CollectedAt: now(), Status: status, Reason: reason, Records: []map[string]any{}}
}

// Connect устанавливает соединение со строгой проверкой ключа хоста. Повторы — только на сетевые сбои.
func Connect(ctx context.Context, t Target, secret Secret, p Policy) (*ssh.Client, error) {
	p = p.withDefaults()
	if !strings.HasPrefix(t.HostKeySHA256, "SHA256:") {
		return nil, ErrHostKeyRequired
	}
	auth, err := secret.authMethod()
	if err != nil {
		return nil, err
	}
	var mismatch bool
	cfg := &ssh.ClientConfig{User: t.User, Auth: []ssh.AuthMethod{auth}, Timeout: p.ConnectTimeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if Fingerprint(key) != t.HostKeySHA256 {
				mismatch = true
				return ErrHostKeyMismatch
			}
			return nil
		}}
	var last error
	for attempt := 0; attempt <= p.ConnectRetries; attempt++ {
		c, err := dial(ctx, t.Addr, cfg, p.ConnectTimeout)
		if err == nil {
			return c, nil
		}
		last = err
		if mismatch {
			return nil, ErrHostKeyMismatch
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, ErrAuth // не повторяем: риск блокировки учётной записи
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("ssh: connect failed: %w", sanitize(last))
}

// sanitize оставляет сетевую причину без деталей, которые могли бы содержать данные цели.
func sanitize(err error) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("timeout")
	}
	return errors.New("network error")
}

// Collect собирает секции одним SSH-соединением. Секции независимы; сбой команды не отбрасывает остальные.
// Отмена ctx и TotalDeadline закрывают соединение: выданные к этому моменту секции остаются частичным результатом.
func Collect(ctx context.Context, t Target, secret Secret, p Policy) ([]contracts.Section, error) {
	p = p.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, p.TotalDeadline)
	defer cancel()
	client, err := Connect(ctx, t, secret, p)
	if err != nil {
		return nil, err
	}
	var closeOnce sync.Once
	closeClient := func() { closeOnce.Do(func() { client.Close() }) }
	defer closeClient()
	stop := context.AfterFunc(ctx, closeClient)
	defer stop()
	s := session{client: client, policy: p}
	var out []contracts.Section

	host, okHost := s.run(ctx, cmdHostname)
	machine, _ := s.run(ctx, cmdMachine)
	if okHost {
		out = append(out, section("identity", linuxinventory.Identity(host, machine)))
	} else {
		out = append(out, failed("identity", "unavailable", "SOURCE_UNAVAILABLE"))
	}
	osr, okOS := s.run(ctx, cmdOSRel)
	uname, _ := s.run(ctx, cmdUname)
	if okOS {
		out = append(out, section("os", linuxinventory.OS(osr, uname)))
	} else {
		out = append(out, failed("os", "unavailable", "SOURCE_UNAVAILABLE"))
	}
	ipLink, okLink := s.run(ctx, cmdIPLink)
	ipAddr, _ := s.run(ctx, cmdIPAddr)
	if okLink {
		out = append(out, section("network", linuxinventory.Network(ipLink, ipAddr)))
	} else {
		out = append(out, failed("network", "unavailable", "SOURCE_UNAVAILABLE"))
	}

	cpu, okCPU := s.run(ctx, cmdCPU)
	mem, okMem := s.run(ctx, cmdMem)
	hw := []map[string]any{}
	if okCPU || okMem {
		hw = append(hw, linuxinventory.Hardware(cpu, mem)...)
	}
	dmi := map[string]string{}
	for _, n := range dmiNames {
		if v, ok := s.run(ctx, "cat /sys/class/dmi/id/"+n+" 2>/dev/null"); ok {
			dmi[n] = v
		}
	}
	hw = append(hw, linuxinventory.DMI(dmi)...)
	out = append(out, section("hardware", hw))

	if dpkg, ok := s.run(ctx, cmdDpkg); ok {
		out = append(out, section("software", linuxinventory.Packages(dpkg)))
	} else if rpm, ok := s.run(ctx, cmdRPM); ok {
		out = append(out, section("software", linuxinventory.RPMPackages(rpm)))
	} else if apk, ok := s.run(ctx, cmdAPK); ok {
		out = append(out, section("software", linuxinventory.APKPackages(apk)))
	} else {
		out = append(out, failed("software", "unsupported", "PACKAGE_MANAGER_UNSUPPORTED"))
	}

	if units, ok := s.run(ctx, cmdUnits); ok {
		files, _ := s.run(ctx, cmdUnitFile)
		out = append(out, section("services", linuxinventory.SystemdServices(units, files)))
	} else {
		out = append(out, failed("services", "unavailable", "SOURCE_UNAVAILABLE"))
	}

	if passwd, ok := s.run(ctx, cmdPasswd); ok {
		group, _ := s.run(ctx, cmdGroup)
		out = append(out, section("users_groups", linuxinventory.Accounts(passwd, group)))
	} else {
		out = append(out, failed("users_groups", "unavailable", "SOURCE_UNAVAILABLE"))
	}
	if mi, ok := s.run(ctx, cmdMounts); ok {
		out = append(out, section("resources", linuxinventory.Mounts(mi)))
	} else {
		out = append(out, failed("resources", "unavailable", "SOURCE_UNAVAILABLE"))
	}
	if rt, ok := s.run(ctx, cmdRoute); ok {
		out = append(out, section("routes_ports", linuxinventory.Routes(rt)))
	} else {
		out = append(out, failed("routes_ports", "unavailable", "SOURCE_UNAVAILABLE"))
	}
	if err := ctx.Err(); err != nil {
		return out, err // частичный результат + причина (отмена/срок)
	}
	return out, nil
}

// SectionOrder — порядок 12 секций профиля 1.2.
var SectionOrder = []string{"identity", "os", "network", "hardware", "software", "updates", "services", "users_groups", "routes_ports", "resources", "protection", "neighbors"}

// Complete12 приводит результат Collect к ровно 12 секциям профиля 1.2: недостающие явно unsupported
// (updates/protection/neighbors не собираются по SSH) или unavailable — значения не выдумываются.
func Complete12(sections []contracts.Section) []contracts.Section {
	have := map[string]contracts.Section{}
	for _, s := range sections {
		have[s.Name] = s
	}
	out := make([]contracts.Section, 0, len(SectionOrder))
	for _, name := range SectionOrder {
		if s, ok := have[name]; ok {
			out = append(out, s)
			continue
		}
		switch name {
		case "updates", "protection", "neighbors":
			out = append(out, failed(name, "unsupported", "SECTION_UNSUPPORTED"))
		default:
			out = append(out, failed(name, "unavailable", "SOURCE_UNAVAILABLE"))
		}
	}
	return out
}

// Candidates извлекает признаки идентификации из секции identity (hostname, machine-id). machine-id — признак,
// а не asset_uid; namespace тот же, что у локального Linux-агента.
func Candidates(sections []contracts.Section) []contracts.Candidate {
	out := []contracts.Candidate{}
	for _, s := range sections {
		if s.Name != "identity" {
			continue
		}
		for _, r := range s.Records {
			if h, ok := r["hostname"].(string); ok && h != "" {
				out = append(out, contracts.Candidate{Kind: "hostname", Namespace: "dns", Value: h})
			}
			if m, ok := r["machine_uuid"].(string); ok && m != "" {
				out = append(out, contracts.Candidate{Kind: "machine_uuid", Namespace: "linux-machine-id", Value: m})
			}
		}
	}
	return out
}
