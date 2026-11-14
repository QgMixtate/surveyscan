package winrminv

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"regexp"
	"strconv"
	"time"
)

// Проверка сервера WinRM (C51.03): по CA (сертификат, заданный администратором, или корневой CA домена) с проверкой
// имени — либо по закреплённому отпечатку SHA-256 сертификата сервера (запомнен при первом подключении). TLS-сеанс
// устанавливаем сами и отдаём клиенту WinRM готовое соединение, поэтому проверка не зависит от библиотеки; её
// отключение не поддерживается. Если в окружении collector задан HTTP-прокси, соединение с прокси не пройдёт проверку
// сертификата и сбор откажет — данные в прокси не уходят.

var CertPinRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrCertChanged — сертификат сервера не совпал с закреплённым отпечатком.
var ErrCertChanged = errors.New("winrm: server certificate changed (cert_changed)")

func CertSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func tlsConfig(t Target) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: t.TLSServerName}
	switch {
	case len(t.CAPEM) > 0:
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(t.CAPEM) {
			return nil, ErrPolicy
		}
		cfg.RootCAs = pool
		if cfg.ServerName == "" {
			cfg.ServerName = t.Host
		}
	case CertPinRe.MatchString(t.CertSHA256):
		pin := t.CertSHA256
		// цепочка не строится: доверие — ровно этому сертификату (как known_hosts у SSH)
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || CertSHA256(cs.PeerCertificates[0].Raw) != pin {
				return ErrCertChanged
			}
			return nil
		}
	default:
		return nil, ErrPolicy
	}
	return cfg, nil
}

func tlsDial(cfg *tls.Config, timeout time.Duration) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		raw, err := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).Dial(network, addr)
		if err != nil {
			return nil, err
		}
		c := tls.Client(raw, cfg)
		_ = c.SetDeadline(time.Now().Add(timeout))
		if err = c.Handshake(); err != nil {
			raw.Close()
			if errors.Is(err, ErrCertChanged) {
				return nil, ErrCertChanged
			}
			return nil, err
		}
		_ = c.SetDeadline(time.Time{})
		return c, nil
	}
}

// FetchCert — сертификат сервера WinRM без входа (для закрепления при первом подключении): отпечаток SHA-256 DER.
func FetchCert(host string, port int, serverName string, timeout time.Duration) (string, error) {
	if port == 0 {
		port = 5986
	}
	//nolint:gosec // только чтение сертификата для закрепления; учётные данные по этому соединению не передаются
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, ServerName: serverName}
	raw, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer raw.Close()
	c := tls.Client(raw, cfg)
	_ = c.SetDeadline(time.Now().Add(timeout))
	if err = c.Handshake(); err != nil {
		return "", err
	}
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("winrm: no server certificate")
	}
	return CertSHA256(certs[0].Raw), nil
}
