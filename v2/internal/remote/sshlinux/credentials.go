package sshlinux

import (
	"context"
	"errors"

	"github.com/QgMixtate/surveyscan/v2/contracts"
)

// SecretReader — источник секретов по алиасу из конфигурации оператора (реализует *bao.Client: Read).
// Алиас — не путь: произвольные пути хранилища клиентский вызов указать не может.
type SecretReader interface {
	Read(ctx context.Context, alias string) ([]byte, error)
}

var ErrCredentialDenied = errors.New("ssh: credential reference is not allowed for this target")

// Binding — решение оператора: ссылка на учётные данные → какие секреты и к каким хостам они применимы.
// Задание несёт только ссылку (CredentialRef) и адрес; пользователь, отпечаток ключа хоста и алиасы секретов
// берутся отсюда, поэтому задание не может ни подставить чужой секрет, ни направить его на посторонний хост.
type Binding struct {
	User            string
	Hosts           map[string]string // addr (host:port) → закреплённый отпечаток ключа хоста
	PasswordAlias   string            // ровно один из PasswordAlias / PrivateKeyAlias
	PrivateKeyAlias string
	PassphraseAlias string // опционально, только для ключа
}

// CollectWithCredentials читает секрет из хранилища непосредственно перед соединением, использует его и
// обнуляет буферы. Любая ошибка хранилища сворачивается в одну обобщённую ошибку без текста ответа Bao.
func CollectWithCredentials(ctx context.Context, r SecretReader, bindings map[string]Binding, credentialRef, addr string, p Policy) ([]contracts.Section, error) {
	b, ok := bindings[credentialRef]
	if !ok {
		return nil, ErrCredentialDenied
	}
	fp, ok := b.Hosts[addr]
	if !ok || fp == "" {
		return nil, ErrCredentialDenied // адрес вне разрешённых для этой ссылки
	}
	if (b.PasswordAlias == "") == (b.PrivateKeyAlias == "") || (b.PasswordAlias != "" && b.PassphraseAlias != "") {
		return nil, ErrNoSecret
	}
	var secret Secret
	var buffers [][]byte
	defer func() {
		for _, buf := range buffers {
			for i := range buf {
				buf[i] = 0
			}
		}
	}()
	read := func(alias string) ([]byte, error) {
		v, err := r.Read(ctx, alias)
		if err != nil {
			return nil, errors.New("ssh: credential store unavailable")
		}
		buffers = append(buffers, v)
		return v, nil
	}
	if b.PasswordAlias != "" {
		v, err := read(b.PasswordAlias)
		if err != nil {
			return nil, err
		}
		secret.Password = string(v)
	} else {
		v, err := read(b.PrivateKeyAlias)
		if err != nil {
			return nil, err
		}
		secret.PrivateKeyPEM = v
		if b.PassphraseAlias != "" {
			pp, err := read(b.PassphraseAlias)
			if err != nil {
				return nil, err
			}
			secret.Passphrase = string(pp)
		}
	}
	return Collect(ctx, Target{Addr: addr, User: b.User, HostKeySHA256: fp}, secret, p)
}
