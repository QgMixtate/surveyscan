package winrminv

import (
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTLSPinAndCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	host, portText, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portText)
	pin, err := FetchCert(host, port, "", 5*time.Second)
	if err != nil || pin != CertSHA256(srv.Certificate().Raw) {
		t.Fatal("fetch", pin, err)
	}
	dialWith := func(tg Target) error {
		cfg, err := tlsConfig(tg)
		if err != nil {
			return err
		}
		c, err := tlsDial(cfg, 5*time.Second)("tcp", net.JoinHostPort(host, portText))
		if err == nil {
			c.Close()
		}
		return err
	}
	if err = dialWith(Target{Host: host, CertSHA256: pin}); err != nil {
		t.Fatal("pinned certificate must connect", err)
	}
	if err = dialWith(Target{Host: host, CertSHA256: strings.Repeat("0", 64)}); !errors.Is(err, ErrCertChanged) {
		t.Fatal("other certificate must be refused as changed", err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err = dialWith(Target{Host: host, CAPEM: ca}); err != nil {
		t.Fatal("CA-verified connection by IP SAN", err)
	}
	if err = dialWith(Target{Host: host, CAPEM: ca, TLSServerName: "other.example"}); err == nil {
		t.Fatal("wrong server name must be refused")
	}
	if err = dialWith(Target{Host: host}); !errors.Is(err, ErrPolicy) {
		t.Fatal("no CA and no pin must be refused", err)
	}
}
