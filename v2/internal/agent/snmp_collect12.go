package agent

import (
	"context"
	"errors"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/remote/snmpnet"
)

// SNMPTarget — сетевое устройство по SNMPv3 authPriv (C51.03, собирает collector). Ключи — из памяти (collector
// получает их у центра по mTLS перед каждым сбором), не из файлов.
type SNMPTarget struct {
	Addr      string // host:port
	User      string
	AuthProto string // SHA | SHA256 | SHA512
	PrivProto string // AES | AES256
	Keys      func(context.Context) (auth, priv []byte, err error)
}

type snmpKeys struct {
	auth, priv []byte
}

func (k snmpKeys) Read(_ context.Context, alias string) ([]byte, error) {
	switch alias {
	case "auth":
		return k.auth, nil
	case "priv":
		return k.priv, nil
	}
	return nil, errors.New("unknown alias")
}

// NewSNMPCollect12 — функция сбора для цикла профиля 1.2 (платформа network/snmp).
func NewSNMPCollect12(t SNMPTarget) func(context.Context) (Snapshot, error) {
	return func(ctx context.Context) (Snapshot, error) {
		if t.Keys == nil {
			return Snapshot{}, errors.New("snmp keys provider required")
		}
		auth, priv, err := t.Keys(ctx)
		if err != nil {
			return Snapshot{}, errors.New("snmp credential unavailable from the center")
		}
		r, err := snmpnet.Collect(ctx, snmpKeys{auth, priv}, t.Addr, snmpnet.Profile{User: t.User, AuthProto: t.AuthProto, PrivProto: t.PrivProto, AuthAlias: "auth", PrivAlias: "priv", MinInterval: 20 * time.Millisecond})
		if err != nil {
			return Snapshot{}, err
		}
		sections := snmpnet.Sections12(r, time.Now())
		return Snapshot{Candidates: snmpnet.Candidates12(sections), Sections: sections}, nil
	}
}
