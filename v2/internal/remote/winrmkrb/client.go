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
	"sync"
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

// CodedError — отказ с фиксированным кодом для Web (без текста цели, адресов и секретов).
type CodedError struct{ Code, Msg string }

func (e *CodedError) Error() string { return e.Msg }

// Code — код отказа Kerberos/WinRM или "".
func Code(err error) string {
	var c *CodedError
	if errors.As(err, &c) {
		return c.Code
	}
	return ""
}

func coded(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

// Transport — транспорт masterzen/winrm. Контекст Kerberos в WinRM привязан к TCP-соединению, а библиотека шлёт
// запросы параллельно (чтение вывода команды идёт в своей горутине, пока отправляется ввод), поэтому у каждого
// запроса своё соединение со своим контекстом: соединение берётся из пула простаивающих или устанавливается заново
// (билет службы кэшируется). Общего изменяемого соединения нет; пул защищён мьютексом.
type Transport struct {
	t Target

	mu     sync.Mutex
	dialer func(ctx context.Context, fresh bool) (*conn, error) // для тестов; по умолчанию dial
	idle   []*conn
	ticket *serviceTicket
	closed bool
}

type conn struct {
	c    net.Conn
	br   *bufio.Reader
	sess *Session
}

type serviceTicket struct {
	cl  *client.Client
	tkt messages.Ticket
	key types.EncryptionKey
	at  time.Time
}

const (
	maxIdle      = 4
	ticketMaxAge = 8 * time.Hour // билеты домена по умолчанию живут 10 ч
)

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

// Close закрывает простаивающие соединения и забывает билет (соединения, занятые запросами, закроются после них).
func (k *Transport) Close() {
	k.mu.Lock()
	idle, t := k.idle, k.ticket
	k.idle, k.ticket, k.closed = nil, nil, true
	k.mu.Unlock()
	for _, c := range idle {
		c.c.Close()
	}
	if t != nil {
		t.cl.Destroy()
	}
}

// serviceTicketFor — кэшированный билет HTTP/<имя ПК> или новый (вход в домен паролем учётки).
func (k *Transport) serviceTicketFor(ctx context.Context, fresh bool) (*serviceTicket, error) {
	k.mu.Lock()
	if t := k.ticket; t != nil && !fresh && time.Since(t.at) < ticketMaxAge {
		k.mu.Unlock()
		return t, nil
	}
	k.mu.Unlock()
	name, realm, _ := Principal(k.t.User, k.t.Host)
	pw, err := k.t.Password(ctx)
	if err != nil {
		return nil, errors.New("winrm kerberos: credential unavailable")
	}
	cl := client.NewWithPassword(name, realm, string(pw), krbConfig(realm, k.t.KDC), client.DisablePAFXFAST(true))
	for i := range pw {
		pw[i] = 0
	}
	if err = cl.Login(); err != nil {
		cl.Destroy()
		return nil, coded("kerberos_login:"+krbReason(err), "winrm kerberos: domain login failed: "+krbReason(err))
	}
	spn := "HTTP/" + strings.ToLower(k.t.Host)
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		cl.Destroy()
		return nil, coded("kerberos_ticket:"+krbReason(err), fmt.Sprintf("winrm kerberos: no service ticket for %s: %s", spn, krbReason(err)))
	}
	if err = aesOnly(key); err != nil {
		cl.Destroy()
		return nil, err
	}
	t := &serviceTicket{cl: cl, tkt: tkt, key: key, at: time.Now()}
	k.mu.Lock()
	old := k.ticket
	k.ticket = t
	k.mu.Unlock()
	if old != nil && old != t {
		old.cl.Destroy()
	}
	return t, nil
}

// dial устанавливает новое соединение с контекстом Kerberos (AP-REQ с взаимной проверкой AP-REP).
func (k *Transport) dial(ctx context.Context, fresh bool) (*conn, error) {
	st, err := k.serviceTicketFor(ctx, fresh)
	if err != nil {
		return nil, err
	}
	auth, err := types.NewAuthenticator(st.cl.Credentials.Domain(), st.cl.Credentials.CName())
	if err != nil {
		return nil, err
	}
	chk := make([]byte, 24)
	binary.LittleEndian.PutUint32(chk[:4], 16)
	binary.LittleEndian.PutUint32(chk[20:], gssapi.ContextFlagMutual|gssapi.ContextFlagInteg|gssapi.ContextFlagConf|gssapi.ContextFlagSequence|gssapi.ContextFlagReplay)
	auth.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: chk}
	if err = auth.GenerateSeqNumberAndSubKey(st.key.KeyType, len(st.key.KeyValue)); err != nil {
		return nil, err
	}
	req, err := messages.NewAPReq(st.tkt, st.key, auth)
	if err != nil {
		return nil, err
	}
	types.SetFlag(&req.APOptions, flags.APOptionMutualRequired)
	raw, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	nc, err := (&net.Dialer{Timeout: k.t.Timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", k.t.Addr)
	if err != nil {
		return nil, coded("network", "winrm kerberos: cannot connect to the PC on port "+portOf(k.t.Addr))
	}
	c := &conn{c: nc, br: bufio.NewReader(nc)}
	resp, _, err := k.roundTrip(ctx, c, nil, "Negotiate "+base64.StdEncoding.EncodeToString(gssFrame([]byte{0x01, 0x00}, raw)), "")
	if err != nil {
		nc.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		nc.Close()
		if resp.StatusCode == 401 {
			return nil, coded("kerberos_refused", "winrm kerberos: PC refused Kerberos (check the account rights, the PC name and the HTTP/<name> SPN)")
		}
		return nil, coded("kerberos_http_"+strconv.Itoa(resp.StatusCode), fmt.Sprintf("winrm kerberos: authentication answered HTTP %d", resp.StatusCode))
	}
	tok, err := serverToken(resp.Header.Values("WWW-Authenticate"))
	if err == nil {
		c.sess, err = AcceptAPRep(tok, st.key, auth)
	}
	if err != nil {
		nc.Close()
		if Code(err) == "" {
			err = coded("kerberos_mutual", err.Error())
		}
		return nil, err
	}
	return c, nil
}

// get — простаивающее соединение (reused=true) или новое.
func (k *Transport) get(ctx context.Context, fresh bool) (*conn, bool, error) {
	k.mu.Lock()
	if k.closed {
		k.mu.Unlock()
		return nil, false, errors.New("winrm kerberos: transport closed")
	}
	if n := len(k.idle); n > 0 && !fresh {
		c := k.idle[n-1]
		k.idle = k.idle[:n-1]
		k.mu.Unlock()
		return c, true, nil
	}
	dial := k.dial
	if k.dialer != nil {
		dial = k.dialer
	}
	k.mu.Unlock()
	c, err := dial(ctx, fresh)
	return c, false, err
}

func (k *Transport) put(c *conn) {
	k.mu.Lock()
	if !k.closed && len(k.idle) < maxIdle {
		k.idle = append(k.idle, c)
		c = nil
	}
	k.mu.Unlock()
	if c != nil {
		c.c.Close()
	}
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

func (k *Transport) roundTrip(ctx context.Context, c *conn, body []byte, authorization, contentType string) (*http.Response, []byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://"+k.t.Host+":"+portOf(k.t.Addr)+"/wsman", bytes.NewReader(body))
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
	_ = c.c.SetDeadline(deadline)
	if err := req.Write(c.c); err != nil {
		return nil, nil, err
	}
	resp, err := http.ReadResponse(c.br, req)
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

// Post — отправка SOAP-сообщения (интерфейс winrm.Transporter). Безопасна для параллельных вызовов: каждый вызов
// работает на своём соединении. Простаивающее соединение могло быть закрыто ПК — тогда один повтор на новом;
// отказ контекста (401) — новый билет. Паника внутри транспорта превращается в ошибку и не роняет collector.
func (k *Transport) Post(_ *winrm.Client, request *soap.SoapMessage) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = "", errors.New("winrm kerberos: internal error")
		}
	}()
	return k.post([]byte(request.String()))
}

func (k *Transport) post(msg []byte) (string, error) {
	ctx := context.Background()
	fresh := false
	for attempt := 0; attempt < 3; attempt++ {
		c, reused, err := k.get(ctx, fresh)
		if err != nil {
			return "", err
		}
		body, err := c.sess.seal(msg)
		if err != nil {
			c.c.Close()
			return "", err
		}
		resp, data, err := k.roundTrip(ctx, c, body, "", `multipart/encrypted;protocol="`+protocol+`";boundary="Encrypted Boundary"`)
		if err != nil || resp.StatusCode == 401 {
			c.c.Close()
			if err == nil {
				fresh = true // контекст отвергнут: новый билет и новое соединение
			}
			if attempt < 2 && (reused || fresh) {
				continue
			}
			if err == nil {
				err = errors.New("winrm kerberos: PC rejected the session")
			}
			return "", err
		}
		plain, err := c.sess.open(resp.Header.Get("Content-Type"), data)
		if err != nil {
			c.c.Close()
			return "", err
		}
		if resp.Close {
			c.c.Close()
		} else {
			k.put(c)
		}
		if resp.StatusCode != 200 {
			return string(plain), fmt.Errorf("winrm: http error %d: %s", resp.StatusCode, string(plain))
		}
		return string(plain), nil
	}
	return "", errors.New("winrm kerberos: no session")
}

func (s *Session) seal(msg []byte) ([]byte, error) {
	header, data, err := s.Wrap(msg)
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
func (s *Session) open(contentType string, body []byte) ([]byte, error) {
	if len(body) == 0 {
		return nil, nil
	}
	if !strings.Contains(contentType, `protocol="`+protocol+`"`) {
		return nil, coded("kerberos_unencrypted", "winrm kerberos: PC answered without encryption")
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
		plain, err := s.Unwrap(payload[4:4+n], payload[4+n:])
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
