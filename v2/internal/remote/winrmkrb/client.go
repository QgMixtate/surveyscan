package winrmkrb

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

const (
	protocol = "application/HTTP-SPNEGO-session-encrypted" // MS-WSMV 2.2.9.1.1 (как pywinrm для Kerberos)
	boundary = "--Encrypted Boundary"
)

// Target — ПК по имени (FQDN: из него — SPN HTTP/<имя> и область Kerberos) и доменная учётка.
type Target struct {
	Host     string // полное имя ПК, например win-ar.awm.local
	Addr     string // IP:порт для соединения (по умолчанию Host:5985)
	User     string // AWM\scan, scan@awm.local или scan
	Password func(context.Context) ([]byte, error)
	KDC      string // необязательно: host:88; иначе DNS SRV _kerberos._tcp.<область>, затем <область>:88
	Timeout  time.Duration
}

// Principal возвращает имя и область Kerberos: UPN — как есть; DOMAIN\user и user — область из имени ПК.
func Principal(user, host string) (name, realm string, err error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return "", "", errors.New("winrm kerberos: target must be a fully qualified PC name, not an address")
	}
	realm = strings.ToUpper(host[strings.Index(host, ".")+1:])
	switch {
	case strings.Contains(user, "@"):
		i := strings.LastIndex(user, "@")
		name, realm = user[:i], strings.ToUpper(user[i+1:])
	case strings.Contains(user, `\`):
		name = user[strings.Index(user, `\`)+1:]
	default:
		name = user
	}
	if name == "" || realm == "" {
		return "", "", errors.New("winrm kerberos: invalid user")
	}
	return name, realm, nil
}

func krbConfig(realm, kdc string) *config.Config {
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DNSLookupKDC = false
	cfg.LibDefaults.UDPPreferenceLimit = 1 // только TCP
	aes := []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96}
	cfg.LibDefaults.DefaultTktEnctypeIDs, cfg.LibDefaults.DefaultTGSEnctypeIDs, cfg.LibDefaults.PermittedEnctypeIDs = aes, aes, aes
	cfg.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}
	cfg.LibDefaults.DefaultTGSEnctypes, cfg.LibDefaults.PermittedEnctypes = cfg.LibDefaults.DefaultTktEnctypes, cfg.LibDefaults.DefaultTktEnctypes
	kdcs := []string{}
	if kdc != "" {
		kdcs = append(kdcs, kdc)
	} else if _, srv, err := net.LookupSRV("kerberos", "tcp", realm); err == nil && len(srv) > 0 {
		for _, s := range srv {
			kdcs = append(kdcs, net.JoinHostPort(strings.TrimSuffix(s.Target, "."), strconv.Itoa(int(s.Port))))
		}
	} else {
		kdcs = append(kdcs, strings.ToLower(realm)+":88")
	}
	cfg.Realms = []config.Realm{{Realm: realm, KDC: kdcs, DefaultDomain: strings.ToLower(realm)}}
	return cfg
}

// Transport — транспорт masterzen/winrm: одно TCP-соединение, Kerberos-контекст и шифрование каждого сообщения.
type Transport struct {
	t    Target
	conn net.Conn
	br   *bufio.Reader
	sess *Session
}

func New(t Target) (*Transport, error) {
	if _, _, err := Principal(t.User, t.Host); err != nil {
		return nil, err
	}
	if t.Addr == "" {
		t.Addr = net.JoinHostPort(t.Host, "5985")
	}
	if t.Timeout <= 0 {
		t.Timeout = 30 * time.Second
	}
	if t.Password == nil {
		return nil, errors.New("winrm kerberos: no credential")
	}
	return &Transport{t: t}, nil
}

func (k *Transport) Transport(*winrm.Endpoint) error { return nil }

func (k *Transport) Close() {
	if k.conn != nil {
		k.conn.Close()
	}
	k.conn, k.sess = nil, nil
}

func (k *Transport) authenticate(ctx context.Context) error {
	name, realm, _ := Principal(k.t.User, k.t.Host)
	pw, err := k.t.Password(ctx)
	if err != nil {
		return errors.New("winrm kerberos: credential unavailable")
	}
	cl := client.NewWithPassword(name, realm, string(pw), krbConfig(realm, k.t.KDC), client.DisablePAFXFAST(true))
	for i := range pw {
		pw[i] = 0
	}
	defer cl.Destroy()
	if err = cl.Login(); err != nil {
		return fmt.Errorf("winrm kerberos: domain login failed: %s", krbReason(err))
	}
	spn := "HTTP/" + strings.ToLower(k.t.Host)
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		return fmt.Errorf("winrm kerberos: no service ticket for %s: %s", spn, krbReason(err))
	}
	if err = aesOnly(key); err != nil {
		return err
	}
	auth, err := types.NewAuthenticator(cl.Credentials.Domain(), cl.Credentials.CName())
	if err != nil {
		return err
	}
	chk := make([]byte, 24)
	binary.LittleEndian.PutUint32(chk[:4], 16)
	binary.LittleEndian.PutUint32(chk[20:], gssapi.ContextFlagMutual|gssapi.ContextFlagInteg|gssapi.ContextFlagConf|gssapi.ContextFlagSequence|gssapi.ContextFlagReplay)
	auth.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: chk}
	if err = auth.GenerateSeqNumberAndSubKey(key.KeyType, len(key.KeyValue)); err != nil {
		return err
	}
	req, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		return err
	}
	types.SetFlag(&req.APOptions, flags.APOptionMutualRequired)
	raw, err := req.Marshal()
	if err != nil {
		return err
	}
	conn, err := (&net.Dialer{Timeout: k.t.Timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", k.t.Addr)
	if err != nil {
		return err
	}
	k.conn, k.br = conn, bufio.NewReader(conn)
	resp, body, err := k.roundTrip(ctx, nil, "Negotiate "+base64.StdEncoding.EncodeToString(gssFrame([]byte{0x01, 0x00}, raw)), "")
	if err != nil {
		k.Close()
		return err
	}
	_ = body
	if resp.StatusCode != 200 {
		k.Close()
		if resp.StatusCode == 401 {
			return errors.New("winrm kerberos: PC refused Kerberos (check the account rights, the PC name and the HTTP/<name> SPN)")
		}
		return fmt.Errorf("winrm kerberos: authentication answered HTTP %d", resp.StatusCode)
	}
	tok, err := serverToken(resp.Header.Values("WWW-Authenticate"))
	if err != nil {
		k.Close()
		return err
	}
	if k.sess, err = AcceptAPRep(tok, key, auth); err != nil {
		k.Close()
		return err
	}
	return nil
}

// serverToken — маркер AP-REP из WWW-Authenticate (сырой Kerberos или SPNEGO NegTokenResp).
func serverToken(values []string) ([]byte, error) {
	for _, v := range values {
		f := strings.Fields(v)
		if len(f) != 2 || !strings.EqualFold(f[0], "Negotiate") && !strings.EqualFold(f[0], "Kerberos") {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil || len(b) == 0 {
			return nil, ErrToken
		}
		if b[0] == 0xa1 {
			var resp spnego.NegTokenResp
			if resp.Unmarshal(b) != nil || len(resp.ResponseToken) == 0 {
				return nil, ErrToken
			}
			return resp.ResponseToken, nil
		}
		return b, nil
	}
	return nil, errors.New("winrm kerberos: PC did not confirm its identity (no mutual authentication)")
}

func krbReason(err error) string {
	s := err.Error()
	for _, k := range []string{"KDC_ERR_PREAUTH_FAILED", "KDC_ERR_C_PRINCIPAL_UNKNOWN", "KDC_ERR_S_PRINCIPAL_UNKNOWN", "KRB_AP_ERR_SKEW", "KDC_ERR_ETYPE_NOSUPP", "KDC_ERR_CLIENT_REVOKED", "KDC_ERR_KEY_EXPIRED", "networking"} {
		if strings.Contains(s, k) {
			return k
		}
	}
	return "error"
}

func (k *Transport) roundTrip(ctx context.Context, body []byte, authorization, contentType string) (*http.Response, []byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://"+k.t.Host+":"+portOf(k.t.Addr)+"/wsman", bytes.NewReader(body))
	req.Header.Set("Host", k.t.Host)
	req.Header.Set("User-Agent", "SurveyScan WinRM")
	req.Header.Set("Connection", "Keep-Alive")
	req.ContentLength = int64(len(body))
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	deadline := time.Now().Add(winrmResponseTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = k.conn.SetDeadline(deadline)
	if err := req.Write(k.conn); err != nil {
		return nil, nil, err
	}
	resp, err := http.ReadResponse(k.br, req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp, data, err
}

var winrmResponseTimeout = 3 * time.Minute

func portOf(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "5985"
	}
	return p
}

// Post — отправка SOAP-сообщения (интерфейс winrm.Transporter): контекст устанавливается при первом вызове и
// заново после разрыва соединения.
func (k *Transport) Post(_ *winrm.Client, request *soap.SoapMessage) (string, error) {
	ctx := context.Background()
	msg := []byte(request.String())
	for attempt := 0; attempt < 2; attempt++ {
		if k.sess == nil {
			if err := k.authenticate(ctx); err != nil {
				return "", err
			}
		}
		body, err := k.seal(msg)
		if err != nil {
			return "", err
		}
		resp, data, err := k.roundTrip(ctx, body, "", `multipart/encrypted;protocol="`+protocol+`";boundary="Encrypted Boundary"`)
		if err != nil || resp.StatusCode == 401 {
			k.Close() // соединение или контекст потеряны — один повтор с новым контекстом
			if attempt == 0 {
				continue
			}
			if err == nil {
				err = errors.New("winrm kerberos: PC rejected the session")
			}
			return "", err
		}
		plain, err := k.open(resp.Header.Get("Content-Type"), data)
		if err != nil {
			k.Close()
			return "", err
		}
		if resp.StatusCode != 200 {
			return string(plain), fmt.Errorf("winrm: http error %d: %s", resp.StatusCode, string(plain))
		}
		return string(plain), nil
	}
	return "", errors.New("winrm kerberos: no session")
}

func (k *Transport) seal(msg []byte) ([]byte, error) {
	header, data, err := k.sess.Wrap(msg)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s\r\n\tContent-Type: %s\r\n\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n%s\r\n\tContent-Type: application/octet-stream\r\n", boundary, protocol, len(msg), boundary)
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(header)))
	b.Write(header)
	b.Write(data)
	b.WriteString(boundary + "--\r\n")
	return b.Bytes(), nil
}

// open расшифровывает ответ; незашифрованный ответ не принимается (кроме пустого тела).
func (k *Transport) open(contentType string, body []byte) ([]byte, error) {
	if len(body) == 0 {
		return nil, nil
	}
	if !strings.Contains(contentType, `protocol="`+protocol+`"`) {
		return nil, errors.New("winrm kerberos: PC answered without encryption")
	}
	parts := [][]byte{}
	for _, p := range bytes.Split(body, []byte(boundary+"\r\n")) {
		if len(bytes.TrimSpace(p)) > 0 {
			parts = append(parts, p)
		}
	}
	var out []byte
	for i := 0; i+1 < len(parts); i += 2 {
		meta, payload := parts[i], parts[i+1]
		j := bytes.Index(meta, []byte("Length="))
		if j < 0 {
			return nil, ErrToken
		}
		want, err := strconv.Atoi(string(bytes.TrimSpace(meta[j+len("Length="):])))
		if err != nil {
			return nil, ErrToken
		}
		payload = bytes.TrimSuffix(payload, []byte(boundary+"--\r\n"))
		payload = bytes.TrimPrefix(payload, []byte("\tContent-Type: application/octet-stream\r\n"))
		if len(payload) < 4 {
			return nil, ErrToken
		}
		n := int(binary.LittleEndian.Uint32(payload[:4]))
		if n <= 0 || 4+n > len(payload) {
			return nil, ErrToken
		}
		plain, err := k.sess.Unwrap(payload[4:4+n], payload[4+n:])
		if err != nil {
			return nil, err
		}
		if len(plain) != want {
			return nil, errors.New("winrm kerberos: message length mismatch")
		}
		out = append(out, plain...)
	}
	if out == nil {
		return nil, ErrToken
	}
	return out, nil
}
