package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/sshlinux"
)

// SSHTarget — безагентная цель, которую обслуживает эта «виртуальная» агентская личность (collector-host).
// Файлы секретов приватные (проверяет privatefile); сам конфиг цели секретов не содержит.
type SSHTarget struct {
	Addr           string `json:"addr"`
	User           string `json:"user"`
	HostKeySHA256  string `json:"host_key_sha256"`
	PasswordFile   string `json:"password_file,omitempty"`
	PrivateKeyFile string `json:"private_key_file,omitempty"`
	PassphraseFile string `json:"passphrase_file,omitempty"`
	// Secret — секрет из памяти (C51.03: collector получает учётку у центра по mTLS перед каждым сбором); файлы
	// тогда не используются. Не сериализуется.
	Secret func(context.Context) (sshlinux.Secret, error) `json:"-"`
}

// LoadSSHTarget читает приватный JSON цели и проверяет обязательные поля (ключ хоста обязателен).
func LoadSSHTarget(path string) (SSHTarget, error) {
	var t SSHTarget
	raw, err := privatefile.Read(path, 65536)
	if err != nil {
		return t, errors.New("ssh target config unavailable or not private")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&t); err != nil {
		return t, errors.New("ssh target config invalid")
	}
	if t.Addr == "" || t.User == "" || !strings.HasPrefix(t.HostKeySHA256, "SHA256:") {
		return t, errors.New("ssh target requires addr, user and host_key_sha256")
	}
	if (t.PasswordFile == "") == (t.PrivateKeyFile == "") || (t.PasswordFile != "" && t.PassphraseFile != "") {
		return t, errors.New("ssh target requires exactly one of password_file or private_key_file")
	}
	return t, nil
}

func readSecretFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := privatefile.Read(path, 65536)
	if err != nil {
		return nil, errors.New("ssh secret file unavailable or not private")
	}
	return b, nil
}

// NewSSHCollect12 возвращает функцию сбора для runLoop12: каждый цикл читает секрет из приватного файла,
// собирает цель по SSH и приводит результат к 12 секциям. Ошибки не содержат секретов.
func NewSSHCollect12(t SSHTarget, policy sshlinux.Policy) func(context.Context) (Snapshot, error) {
	return func(ctx context.Context) (Snapshot, error) {
		if t.Secret != nil {
			secret, err := t.Secret(ctx)
			if err != nil {
				return Snapshot{}, errors.New("ssh credential unavailable from the center")
			}
			sections, err := sshlinux.Collect(ctx, sshlinux.Target{Addr: t.Addr, User: t.User, HostKeySHA256: t.HostKeySHA256}, secret, policy)
			if err != nil {
				return Snapshot{}, err
			}
			full := sshlinux.Complete12(sections)
			return Snapshot{Candidates: sshlinux.Candidates(full), Sections: full}, nil
		}
		pw, err := readSecretFile(t.PasswordFile)
		if err != nil {
			return Snapshot{}, err
		}
		key, err := readSecretFile(t.PrivateKeyFile)
		if err != nil {
			return Snapshot{}, err
		}
		pp, err := readSecretFile(t.PassphraseFile)
		if err != nil {
			return Snapshot{}, err
		}
		secret := sshlinux.Secret{Password: strings.TrimRight(string(pw), "\r\n"), PrivateKeyPEM: key, Passphrase: strings.TrimRight(string(pp), "\r\n")}
		sections, err := sshlinux.Collect(ctx, sshlinux.Target{Addr: t.Addr, User: t.User, HostKeySHA256: t.HostKeySHA256}, secret, policy)
		if err != nil {
			return Snapshot{}, err // отмена/срок/сбой подключения: частичный результат не публикуем как свежий
		}
		full := sshlinux.Complete12(sections)
		return Snapshot{Candidates: sshlinux.Candidates(full), Sections: full}, nil
	}
}
