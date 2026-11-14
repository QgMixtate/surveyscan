package winrminv

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/masterzen/winrm"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/winrmkrb"
)

var (
	ErrPolicy = errors.New("winrm: HTTPS with a trusted CA certificate and NTLM credentials are required")
	ErrRun    = errors.New("winrm: remote command failed")
	ErrAuth   = errors.New("winrm: authentication rejected by the target (HTTP 401)")
	ErrTLS    = errors.New("winrm: TLS verification of the target certificate failed")
	ErrNet    = errors.New("winrm: target unreachable")
	ErrExit   = errors.New("winrm: remote PowerShell exited with a non-zero code")
)

// classify сводит ошибку транспорта к безопасной категории без текста ответа цели.
func classify(err error) error {
	if winrmkrb.Code(err) != "" {
		return err // фиксированный код Kerberos (без текста цели) — показывается в Web
	}
	out := classifyKind(err)
	if os.Getenv("SURVEYSCAN_AGENT_DEBUG") == "1" { // отладка: очищенный и обрезанный текст транспортной ошибки (пароль в нём не передаётся)
		text := strings.Join(strings.Fields(err.Error()), " ")
		if len(text) > 240 {
			text = text[:240]
		}
		return fmt.Errorf("%w: %s", out, text)
	}
	return out
}

func classifyKind(err error) error {
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "401") || strings.Contains(text, "unauthorized") || strings.Contains(text, "ntlm"):
		return ErrAuth
	case strings.Contains(text, "x509") || strings.Contains(text, "certificate") || strings.Contains(text, "tls"):
		return ErrTLS
	case strings.Contains(text, "refused") || strings.Contains(text, "timeout") || strings.Contains(text, "no route") || strings.Contains(text, "deadline"):
		return ErrNet
	}
	return ErrRun
}

// SecretReader — алиас из конфигурации оператора (как у SSH/SNMP).
type SecretReader interface {
	Read(ctx context.Context, alias string) ([]byte, error)
}

// Target — цель WinRM. Только HTTPS (5986) с проверкой сервера: по CA (PEM, с проверкой имени) или по закреплённому
// отпечатку сертификата (CertSHA256, hex); HTTP/Basic и отключение проверки не поддерживаются. Аутентификация NTLM.
type Target struct {
	Host          string
	Port          int // 5986 по умолчанию
	User          string
	PasswordAlias string
	CAPEM         []byte
	TLSServerName string // имя в сертификате цели, если отличается от Host
	CertSHA256    string // закреплённый отпечаток сертификата сервера (если CAPEM не задан)
	// Kerberos: HTTP (5985) с Kerberos и шифрованием сообщений; TLSServerName — полное имя ПК (SPN HTTP/<имя>),
	// Host — адрес для соединения. Сертификаты не используются; NTLM не применяется.
	Kerberos bool
}

type Policy struct {
	ConnectTimeout time.Duration
	TotalDeadline  time.Duration
	MaxOutput      int
}

// Runner выполняет PowerShell-сценарий на цели и возвращает stdout. Реализация WinRM — runWinRM; в тестах — фейк.
type Runner interface {
	RunPowerShell(ctx context.Context, script string, maxOut int) (string, error)
}

type limitedBuf struct {
	b    bytes.Buffer
	left int
}

func (w *limitedBuf) Write(p []byte) (int, error) {
	if len(p) > w.left {
		return 0, errors.New("output limit exceeded")
	}
	w.left -= len(p)
	return w.b.Write(p)
}

type winrmRunner struct {
	client *winrm.Client
	close  func()
}

// Close освобождает соединения транспорта (Kerberos: пул соединений и билет).
func (r winrmRunner) Close() {
	if r.close != nil {
		r.close()
	}
}

func (r winrmRunner) RunPowerShell(ctx context.Context, script string, maxOut int) (string, error) {
	out, errOut := &limitedBuf{left: maxOut}, &limitedBuf{left: 64 << 10}
	code, err := r.client.RunWithContextWithInput(ctx, StdinLoader, out, errOut, strings.NewReader(script))
	if err != nil {
		return "", classify(err) // текст ошибки цели наружу не отдаём
	}
	if code != 0 {
		if os.Getenv("SURVEYSCAN_AGENT_DEBUG") == "1" { // отладка: короткий очищенный хвост stderr цели
			tail := strings.Join(strings.Fields(errOut.b.String()), " ")
			if len(tail) > 160 {
				tail = tail[:160]
			}
			return "", fmt.Errorf("%w (code %d): %s", ErrExit, code, tail)
		}
		return "", fmt.Errorf("%w (code %d)", ErrExit, code)
	}
	if out.b.Len() == 0 && os.Getenv("SURVEYSCAN_AGENT_DEBUG") == "1" { // отладка: пустой stdout — показать хвост stderr цели
		tail := strings.Join(strings.Fields(errOut.b.String()), " ")
		if len(tail) > 600 {
			tail = tail[:600]
		}
		return "", fmt.Errorf("%w: empty stdout, exit 0, stderr=%q", ErrRun, tail)
	}
	return out.b.String(), nil
}

// Таймауты long-poll: WinRM держит запрос «получить вывод» до OperationTimeout. HTTP-таймаут клиента обязан быть
// БОЛЬШЕ: иначе клиент бросает запрос, сервер отдаёт вывод в брошенный ответ, и вывод теряется (команда «успешна»,
// но stdout пуст). Обнаружено на живой цели: сценарий ~36 с при HTTP-таймауте 30 с возвращал пустой вывод с кодом 0.
const (
	OperationTimeout    = "PT20S"
	HTTPResponseTimeout = 60 * time.Second
)

// NewParameters — параметры клиента WinRM: NTLM поверх HTTPS и согласованные таймауты (не общий DefaultParameters).
func NewParameters() *winrm.Parameters {
	params := winrm.NewParameters(OperationTimeout, "en-US", 153600)
	params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	return params
}

// StdinLoader — короткая командная строка: PowerShell читает сценарий из stdin целиком и выполняет его. Длина сценария
// не ограничена лимитом командной строки WinRS/cmd.exe; на диск цели ничего не пишется. Сценарий обязан быть ASCII.
var StdinLoader = winrm.Powershell("$s = [Console]::In.ReadToEnd(); Invoke-Expression $s")

// EncodedLength — длина командной строки powershell -EncodedCommand для сценария (WinRM/cmd.exe ограничен ≈8191).
func EncodedLength(script string) int {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return len("powershell.exe -NoProfile -NonInteractive -EncodedCommand ") + len(base64.StdEncoding.EncodeToString(b))
}

// Connect создаёт клиента NTLM поверх HTTPS с проверкой сертификата.
func Connect(ctx context.Context, r SecretReader, t Target, p Policy) (Runner, error) {
	if t.Host == "" || t.User == "" || t.PasswordAlias == "" {
		return nil, ErrPolicy
	}
	if t.Kerberos {
		return connectKerberos(r, t)
	}
	cfg, err := tlsConfig(t)
	if err != nil {
		return nil, err
	}
	if t.Port == 0 {
		t.Port = 5986
	}
	if p.ConnectTimeout <= 0 {
		p.ConnectTimeout = 15 * time.Second
	}
	pw, err := r.Read(ctx, t.PasswordAlias)
	if err != nil {
		return nil, errors.New("winrm: credential store unavailable")
	}
	defer func() {
		for i := range pw {
			pw[i] = 0
		}
	}()
	// TLS устанавливаем сами (tlsDial): клиенту WinRM отдаётся уже проверенное соединение, поверх него — HTTP+NTLM
	ep := winrm.NewEndpoint(t.Host, t.Port, false, false, nil, nil, nil, HTTPResponseTimeout)
	params := NewParameters()
	dial := tlsDial(cfg, p.ConnectTimeout)
	params.TransportDecorator = func() winrm.Transporter { return winrm.NewClientNTLMWithDial(dial) }
	client, err := winrm.NewClientWithParameters(ep, t.User, string(pw), params)
	if err != nil {
		return nil, errors.New("winrm: client setup failed")
	}
	return winrmRunner{client: client}, nil
}

// CollectWith выполняет сценарий через Runner и приводит результат к 12 секциям. Таймаут/отмена/ошибка → ошибка без частичных данных.
func CollectWith(ctx context.Context, run Runner, p Policy) ([]contracts.Section, []contracts.Candidate, error) {
	if p.TotalDeadline <= 0 {
		p.TotalDeadline = 2 * time.Minute
	}
	if p.MaxOutput <= 0 {
		p.MaxOutput = 16 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, p.TotalDeadline)
	defer cancel()
	out, err := run.RunPowerShell(ctx, Script, p.MaxOutput)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, err
	}
	sections, cands, err := Parse([]byte(out), time.Now())
	if err != nil {
		if os.Getenv("SURVEYSCAN_AGENT_DEBUG") == "1" { // отладка: начало вывода цели (очищено, обрезано)
			head := strings.Join(strings.Fields(out), " ")
			if len(head) > 200 {
				head = head[:200]
			}
			return nil, nil, fmt.Errorf("winrm: unexpected output from target (%v), len=%d, head=%q", err, len(out), head)
		}
		return nil, nil, errors.New("winrm: unexpected output from target")
	}
	return Complete12(sections), cands, nil
}

var order = []string{"identity", "os", "network", "hardware", "software", "updates", "services", "users_groups", "routes_ports", "resources", "protection", "neighbors"}

// Complete12 — ровно 12 секций; не собираемые по WinRM явно unsupported/unavailable.
func Complete12(sections []contracts.Section) []contracts.Section {
	have := map[string]contracts.Section{}
	for _, s := range sections {
		have[s.Name] = s
	}
	out := make([]contracts.Section, 0, 12)
	now := time.Now().UTC()
	for _, n := range order {
		if s, ok := have[n]; ok {
			out = append(out, s)
			continue
		}
		status, reason := "unavailable", "SOURCE_UNAVAILABLE"
		switch n {
		case "updates", "protection", "neighbors", "users_groups", "routes_ports", "resources":
			status, reason = "unsupported", "SECTION_UNSUPPORTED"
		}
		out = append(out, contracts.Section{Name: n, CollectedAt: now, Status: status, Reason: reason, Records: []map[string]any{}})
	}
	return out
}

func connectKerberos(r SecretReader, t Target) (Runner, error) {
	if t.Port == 0 {
		t.Port = 5985
	}
	tr, err := winrmkrb.New(winrmkrb.Target{Host: t.TLSServerName, Addr: net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), User: t.User,
		Password: func(ctx context.Context) ([]byte, error) { return r.Read(ctx, t.PasswordAlias) }})
	if err != nil {
		return nil, err
	}
	ep := winrm.NewEndpoint(t.TLSServerName, t.Port, false, false, nil, nil, nil, HTTPResponseTimeout)
	params := NewParameters()
	params.TransportDecorator = func() winrm.Transporter { return tr }
	client, err := winrm.NewClientWithParameters(ep, t.User, "", params)
	if err != nil {
		return nil, errors.New("winrm: client setup failed")
	}
	return winrmRunner{client: client, close: tr.Close}, nil
}
