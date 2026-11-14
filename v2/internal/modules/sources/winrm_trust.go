package sources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/jackc/pgx/v5"
)

// C51.03 шаг 2: корневой (и при необходимости промежуточные) сертификат CA домена для проверки WinRM-целей
// с режимом «CA домена». Хранится открытым текстом: это публичные сертификаты, не секрет.

type TrustCert struct {
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	SHA256   string    `json:"sha256"`
}

type WinRMTrust struct {
	Configured   bool        `json:"configured"`
	Revision     string      `json:"revision"`
	UpdatedAt    *time.Time  `json:"updated_at"`
	Certificates []TrustCert `json:"certificates"`
	Targets      int         `json:"targets"` // целей с проверкой «CA домена»
}

// ParseDomainCA — 1..10 сертификатов CA (basicConstraints CA:TRUE), иначе Invalid.
func ParseDomainCA(pemText string) ([]TrustCert, error) {
	if len(pemText) == 0 || len(pemText) > 65536 {
		return nil, domain.Invalid
	}
	out := []TrustCert{}
	rest := []byte(pemText)
	for {
		var b *pemBlock
		b, rest = decodePEM(rest)
		if b == nil {
			break
		}
		c, err := parseCert(b.Bytes)
		if b.Type != "CERTIFICATE" || err != nil || !c.IsCA || len(out) == 10 {
			return nil, domain.Invalid
		}
		sum := sha256.Sum256(b.Bytes)
		out = append(out, TrustCert{Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotAfter: c.NotAfter.UTC(), SHA256: hex.EncodeToString(sum[:])})
	}
	if len(out) == 0 {
		return nil, domain.Invalid
	}
	return out, nil
}

func (Store) WinRMTrust(ctx context.Context, tx pgx.Tx, tenant string) (WinRMTrust, error) {
	out := WinRMTrust{Revision: "0", Certificates: []TrustCert{}}
	if e := tx.QueryRow(ctx, "SELECT count(*) FROM sources.remote_targets WHERE tenant_id=$1 AND tls_cert_origin='domain_ca'", tenant).Scan(&out.Targets); e != nil {
		return out, e
	}
	var pemText string
	var at time.Time
	e := tx.QueryRow(ctx, "SELECT ca_pem,revision::text,updated_at FROM sources.winrm_trust WHERE tenant_id=$1", tenant).Scan(&pemText, &out.Revision, &at)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, nil
	}
	if e != nil {
		return out, e
	}
	if out.Certificates, e = ParseDomainCA(pemText); e != nil {
		return out, e
	}
	out.Configured, out.UpdatedAt = true, &at
	return out, nil
}

// SetWinRMTrust — задать/заменить (pemText) или удалить (nil) CA домена при совпадении ревизии ("0" — ещё не задан).
// Удаление при наличии целей «CA домена» — Conflict: иначе они остались бы без проверки сертификата.
func (s Store) SetWinRMTrust(ctx context.Context, tx pgx.Tx, tenant, actor, revision string, pemText *string) (WinRMTrust, error) {
	if pemText != nil {
		if _, e := ParseDomainCA(*pemText); e != nil {
			return WinRMTrust{}, e
		}
	}
	var current string
	e := tx.QueryRow(ctx, "SELECT revision::text FROM sources.winrm_trust WHERE tenant_id=$1 FOR UPDATE", tenant).Scan(&current)
	if errors.Is(e, pgx.ErrNoRows) {
		current, e = "0", nil
	}
	if e != nil {
		return WinRMTrust{}, e
	}
	if current != revision {
		return WinRMTrust{}, domain.Revision
	}
	switch {
	case pemText == nil:
		var used bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sources.remote_targets WHERE tenant_id=$1 AND tls_cert_origin='domain_ca')", tenant).Scan(&used); e != nil {
			return WinRMTrust{}, e
		}
		if used {
			return WinRMTrust{}, domain.Conflict
		}
		_, e = tx.Exec(ctx, "DELETE FROM sources.winrm_trust WHERE tenant_id=$1", tenant)
	case current == "0":
		_, e = tx.Exec(ctx, "INSERT INTO sources.winrm_trust(tenant_id,ca_pem,updated_by) VALUES($1,$2,$3)", tenant, *pemText, actor)
	default:
		_, e = tx.Exec(ctx, "UPDATE sources.winrm_trust SET ca_pem=$2,revision=revision+1,updated_at=now(),updated_by=$3 WHERE tenant_id=$1", tenant, *pemText, actor)
	}
	if e != nil {
		return WinRMTrust{}, e
	}
	return s.WinRMTrust(ctx, tx, tenant)
}
