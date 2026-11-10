package sshlinux

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/bao"
)

var _ SecretReader = (*bao.Client)(nil) // реальный клиент OpenBao реализует интерфейс

type fakeStore struct {
	data  map[string][]byte
	reads []string
}

func (f *fakeStore) Read(_ context.Context, alias string) ([]byte, error) {
	f.reads = append(f.reads, alias)
	v, ok := f.data[alias]
	if !ok {
		return nil, errors.New("bao said: permission denied on secret/data/TOPSECRET-PATH")
	}
	return append([]byte(nil), v...), nil
}

func TestCredentialsScopedToBinding(t *testing.T) {
	s := startServer(t, "pw", baseOutputs())
	store := &fakeStore{data: map[string][]byte{"ssh/pw": []byte("pw"), "ssh/other": []byte("other")}}
	ctx := context.Background()
	b := map[string]Binding{"lab": {User: "scan", Hosts: map[string]string{s.addr: s.hostFP}, PasswordAlias: "ssh/pw"}}

	secs, err := CollectWithCredentials(ctx, store, b, "lab", s.addr, Policy{})
	if err != nil || len(secs) == 0 {
		t.Fatal(err)
	}
	// неизвестная ссылка и адрес вне разрешённых: секрет НЕ читается вообще
	store.reads = nil
	if _, err = CollectWithCredentials(ctx, store, b, "other-ref", s.addr, Policy{}); !errors.Is(err, ErrCredentialDenied) {
		t.Fatal(err)
	}
	if _, err = CollectWithCredentials(ctx, store, b, "lab", "10.9.9.9:22", Policy{}); !errors.Is(err, ErrCredentialDenied) {
		t.Fatal(err)
	}
	if len(store.reads) != 0 {
		t.Fatal("secret must not be read for a denied target:", store.reads)
	}
}

func TestStoreErrorDoesNotLeakDetails(t *testing.T) {
	s := startServer(t, "pw", baseOutputs())
	store := &fakeStore{data: map[string][]byte{}}
	b := map[string]Binding{"lab": {User: "scan", Hosts: map[string]string{s.addr: s.hostFP}, PasswordAlias: "ssh/missing"}}
	_, err := CollectWithCredentials(context.Background(), store, b, "lab", s.addr, Policy{})
	if err == nil || strings.Contains(err.Error(), "TOPSECRET") || strings.Contains(err.Error(), "permission") {
		t.Fatal("store error text must not propagate:", err)
	}
	if s.conns.Load() != 0 {
		t.Fatal("no connection without a credential")
	}
}

func TestBindingMustChooseOneSecret(t *testing.T) {
	store := &fakeStore{}
	for _, bad := range []Binding{
		{User: "u", Hosts: map[string]string{"h:22": "SHA256:x"}},
		{User: "u", Hosts: map[string]string{"h:22": "SHA256:x"}, PasswordAlias: "a", PrivateKeyAlias: "b"},
		{User: "u", Hosts: map[string]string{"h:22": "SHA256:x"}, PasswordAlias: "a", PassphraseAlias: "c"},
	} {
		if _, err := CollectWithCredentials(context.Background(), store, map[string]Binding{"r": bad}, "r", "h:22", Policy{}); !errors.Is(err, ErrNoSecret) {
			t.Fatal(err)
		}
	}
}
