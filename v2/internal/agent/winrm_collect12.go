package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/winrminv"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/winrmkrb"
)

// WinRMTarget — безагентная Windows-цель (только HTTPS, CA обязателен, NTLM). Файлы приватные.
type WinRMTarget struct {
	Host         string `json:"host"`
	Port         int    `json:"port,omitempty"`
	User         string `json:"user"`
	PasswordFile string `json:"password_file"`
	CAFile       string `json:"ca_file"`
	ServerName   string `json:"tls_server_name,omitempty"`
	// Kerberos: HTTP 5985 с Kerberos и шифрованием сообщений; ServerName — полное имя ПК (SPN), CA не нужен
	Kerberos bool `json:"kerberos,omitempty"`
	// Problem — код отказа подключения (например kerberos_refused) для показа в Web; не сериализуется
	Problem func(code string) `json:"-"`
	// C51.03: пароль и CA из памяти (collector получает их у центра); файлы тогда не используются. Не сериализуются.
	Password func(context.Context) ([]byte, error) `json:"-"`
	CAPEM    []byte                                `json:"-"`
	// закреплённый отпечаток сертификата сервера (hex SHA-256), если CA не задан — запомнен при первом подключении
	CertSHA256 string `json:"-"`
}

type funcSecret func(context.Context) ([]byte, error)

func (f funcSecret) Read(ctx context.Context, _ string) ([]byte, error) {
	b, err := f(ctx)
	if err != nil {
		return nil, errors.New("winrm credential unavailable from the center")
	}
	return b, nil
}

func LoadWinRMTarget(path string) (WinRMTarget, error) {
	var t WinRMTarget
	raw, err := privatefile.Read(path, 65536)
	if err != nil {
		return t, errors.New("winrm target config unavailable or not private")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&t); err != nil {
		return t, errors.New("winrm target config invalid")
	}
	if t.Host == "" || t.User == "" || t.PasswordFile == "" || (t.CAFile == "" && !t.Kerberos) || (t.Kerberos && t.ServerName == "") {
		return t, errors.New("winrm target requires host, user, password_file and ca_file (kerberos: tls_server_name = PC name instead of ca_file)")
	}
	return t, nil
}

type fileSecret struct{ path string }

func (f fileSecret) Read(_ context.Context, _ string) ([]byte, error) {
	b, err := privatefile.Read(f.path, 65536)
	if err != nil {
		return nil, errors.New("secret file unavailable or not private")
	}
	return []byte(strings.TrimRight(string(b), "\r\n")), nil
}

// NewWinRMCollect12 — функция сбора для runLoop12: каждый цикл читает пароль и CA из приватных файлов.
func NewWinRMCollect12(t WinRMTarget) func(context.Context) (Snapshot, error) {
	return func(ctx context.Context) (Snapshot, error) {
		var secret interface {
			Read(context.Context, string) ([]byte, error)
		} = fileSecret{t.PasswordFile}
		ca := t.CAPEM
		if t.Password != nil {
			secret = funcSecret(t.Password)
		} else if !t.Kerberos {
			var err error
			if ca, err = privatefile.Read(t.CAFile, 1<<20); err != nil {
				return Snapshot{}, errors.New("winrm CA file unavailable or not private")
			}
		}
		run, err := winrminv.Connect(ctx, secret, winrminv.Target{Host: t.Host, Port: t.Port, User: t.User, PasswordAlias: "file", CAPEM: ca, TLSServerName: t.ServerName, CertSHA256: t.CertSHA256, Kerberos: t.Kerberos}, winrminv.Policy{})
		if err != nil {
			t.problem(err)
			return Snapshot{}, err
		}
		if c, ok := run.(interface{ Close() }); ok {
			defer c.Close()
		}
		sections, cands, err := winrminv.CollectWith(ctx, run, winrminv.Policy{})
		if err != nil {
			t.problem(err)
			return Snapshot{}, err
		}
		t.problem(nil)
		return Snapshot{Candidates: cands, Sections: sections}, nil
	}
}

func (t WinRMTarget) problem(err error) {
	if t.Problem == nil {
		return
	}
	t.Problem(WinRMProblem(err))
}

// WinRMProblem — фиксированный код отказа WinRM-цели для Web (без текста цели): host_unreachable, auth_failed,
// access_denied, tls_failed или код Kerberos (kerberos_login:…, kerberos_ticket:…, kerberos_refused …).
func WinRMProblem(err error) string {
	switch {
	case err == nil:
		return ""
	case winrmkrb.Code(err) != "":
		return winrmkrb.Code(err)
	case errors.Is(err, winrminv.ErrNet):
		return "host_unreachable"
	case errors.Is(err, winrminv.ErrAuth):
		return "auth_failed"
	case errors.Is(err, winrminv.ErrAccess):
		return "access_denied"
	case errors.Is(err, winrminv.ErrTLS):
		return "tls_failed"
	}
	return ""
}
