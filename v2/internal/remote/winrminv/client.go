package winrminv

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/masterzen/winrm"

	"github.com/QgMixtate/surveyscan/v2/contracts"
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

// Target — цель WinRM. Только HTTPS (5986) и проверка сертификата по переданному CA (PEM); HTTP/Basic и
// отключение проверки не поддерживаются. Аутентификация NTLM; пароль берётся по алиасу.
type Target struct {
	Host          string
	Port          int // 5986 по умолчанию
	User          string
	PasswordAlias string
	CAPEM         []byte
	TLSServerName string // имя в сертификате цели, если отличается от Host
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

type winrmRunner struct{ client *winrm.Client }

func (r winrmRunner) RunPowerShell(ctx context.Context, script string, maxOut int) (string, error) {
	out, errOut := &limitedBuf{left: maxOut}, &limitedBuf{left: 64 << 10}
	code, err := r.client.RunWithContext(ctx, winrm.Powershell(script), out, errOut)
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
	return out.b.String(), nil
}

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
	if t.Host == "" || t.User == "" || t.PasswordAlias == "" || len(t.CAPEM) == 0 {
		return nil, ErrPolicy
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
	ep := winrm.NewEndpoint(t.Host, t.Port, true, false, t.CAPEM, nil, nil, p.ConnectTimeout)
	if t.TLSServerName != "" {
		ep.TLSServerName = t.TLSServerName
	}
	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	client, err := winrm.NewClientWithParameters(ep, t.User, string(pw), params)
	if err != nil {
		return nil, errors.New("winrm: client setup failed")
	}
	return winrmRunner{client}, nil
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
