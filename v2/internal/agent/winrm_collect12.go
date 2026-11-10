package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/winrminv"
)

// WinRMTarget — безагентная Windows-цель (только HTTPS, CA обязателен, NTLM). Файлы приватные.
type WinRMTarget struct {
	Host         string `json:"host"`
	Port         int    `json:"port,omitempty"`
	User         string `json:"user"`
	PasswordFile string `json:"password_file"`
	CAFile       string `json:"ca_file"`
	ServerName   string `json:"tls_server_name,omitempty"`
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
	if t.Host == "" || t.User == "" || t.PasswordFile == "" || t.CAFile == "" {
		return t, errors.New("winrm target requires host, user, password_file and ca_file")
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
		ca, err := privatefile.Read(t.CAFile, 1<<20)
		if err != nil {
			return Snapshot{}, errors.New("winrm CA file unavailable or not private")
		}
		run, err := winrminv.Connect(ctx, fileSecret{t.PasswordFile}, winrminv.Target{Host: t.Host, Port: t.Port, User: t.User, PasswordAlias: "file", CAPEM: ca, TLSServerName: t.ServerName}, winrminv.Policy{})
		if err != nil {
			return Snapshot{}, err
		}
		sections, cands, err := winrminv.CollectWith(ctx, run, winrminv.Policy{})
		if err != nil {
			return Snapshot{}, err
		}
		return Snapshot{Candidates: cands, Sections: sections}, nil
	}
}
