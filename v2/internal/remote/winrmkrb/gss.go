// Package winrmkrb — WinRM по HTTP (5985) с Kerberos и шифрованием сообщений (C51.03 шаг 3, запрос пользователя:
// «только по имени ПК и доменной учётке, NTLM по HTTP запрещён»). Аутентификация — Kerberos AP-REQ с взаимной
// проверкой (AP-REP); каждое SOAP-сообщение шифруется маркером GSS Wrap (RFC 4121, AES, RRC=28 как у Windows)
// и передаётся в multipart/encrypted (MS-WSMV 2.2.9.1). Без Kerberos соединение не устанавливается: NTLM
// и незашифрованный обмен не поддерживаются.
package winrmkrb

import (
	"bytes"
	"crypto/hmac"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// OID механизма Kerberos v5 (1.2.840.113554.1.2.2).
var oidKRB5 = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

const (
	flagSentByAcceptor = 0x01
	flagSealed         = 0x02
	flagAcceptorSubkey = 0x04
	wrapHeaderLen      = 16
	rrcWindows         = 28 // 16 (копия заголовка) + 12 (HMAC-SHA1-96): так поворачивает Windows для AES
)

var (
	ErrUnsupportedEtype = errors.New("winrm kerberos: only AES session keys are supported (aes128/aes256-cts-hmac-sha1-96)")
	ErrToken            = errors.New("winrm kerberos: malformed GSS token")
)

// gssFrame — начальный маркер контекста GSS (RFC 2743 3.1): [APPLICATION 0] { OID, tokID, сообщение }.
func gssFrame(tokID []byte, inner []byte) []byte {
	oid, _ := asn1.Marshal(oidKRB5)
	body := append(append(append([]byte{}, oid...), tokID...), inner...)
	return append(append([]byte{0x60}, asn1Length(len(body))...), body...)
}

func asn1Length(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

// gssUnframe возвращает tokID и вложенное сообщение маркера Kerberos.
func gssUnframe(tok []byte) ([]byte, []byte, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(tok, &raw)
	if err != nil || len(rest) != 0 || raw.Class != asn1.ClassApplication || raw.Tag != 0 {
		return nil, nil, ErrToken
	}
	var oid asn1.ObjectIdentifier
	inner, err := asn1.Unmarshal(raw.Bytes, &oid)
	if err != nil || !oid.Equal(oidKRB5) || len(inner) < 2 {
		return nil, nil, ErrToken
	}
	return inner[:2], inner[2:], nil
}

// Session — установленный контекст: ключ защиты сообщений и счётчики последовательности.
type Session struct {
	key            types.EncryptionKey
	acceptorSubkey bool
	sendSeq        uint64
}

func aesOnly(k types.EncryptionKey) error {
	if k.KeyType != etypeID.AES128_CTS_HMAC_SHA1_96 && k.KeyType != etypeID.AES256_CTS_HMAC_SHA1_96 {
		return ErrUnsupportedEtype
	}
	return nil
}

// AcceptAPRep проверяет ответ сервера (взаимная аутентификация) и выбирает ключ защиты (RFC 4121 2): подключ
// сервера, если он есть, иначе подключ клиента из аутентификатора.
func AcceptAPRep(token []byte, sessionKey types.EncryptionKey, auth types.Authenticator) (*Session, error) {
	tokID, inner, err := gssUnframe(token)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(tokID, []byte{0x02, 0x00}) {
		if bytes.Equal(tokID, []byte{0x03, 0x00}) {
			var kerr messages.KRBError
			if kerr.Unmarshal(inner) == nil {
				return nil, fmt.Errorf("winrm kerberos: server refused authentication (KRB error %d)", kerr.ErrorCode)
			}
		}
		return nil, ErrToken
	}
	var rep messages.APRep
	if err = rep.Unmarshal(inner); err != nil {
		return nil, ErrToken
	}
	plain, err := crypto.DecryptEncPart(rep.EncPart, sessionKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, errors.New("winrm kerberos: server proof failed (mutual authentication)")
	}
	var part messages.EncAPRepPart
	if err = part.Unmarshal(plain); err != nil {
		return nil, ErrToken
	}
	// RFC 4120 3.2.5: сервер подтверждает время нашего аутентификатора
	if part.CTime.Unix() != auth.CTime.Unix() || part.Cusec != auth.Cusec {
		return nil, errors.New("winrm kerberos: server proof does not match the request")
	}
	s := &Session{key: auth.SubKey, sendSeq: uint64(auth.SeqNumber)}
	if len(part.Subkey.KeyValue) > 0 {
		s.key, s.acceptorSubkey = part.Subkey, true
	}
	if len(s.key.KeyValue) == 0 {
		s.key = sessionKey
	}
	if err = aesOnly(s.key); err != nil {
		return nil, err
	}
	return s, nil
}

// Wrap шифрует сообщение (маркер Wrap RFC 4121 4.2.6.2, EC=0, RRC=28) и возвращает части для WinRM: заголовок
// (16 байт заголовка маркера + повёрнутые 28 байт хвоста + 16 байт зашифрованного «соля») и данные.
func (s *Session) Wrap(msg []byte) (header, data []byte, err error) {
	et, err := crypto.GetEtype(s.key.KeyType)
	if err != nil {
		return nil, nil, ErrUnsupportedEtype
	}
	hdr := make([]byte, wrapHeaderLen)
	hdr[0], hdr[1] = 0x05, 0x04
	hdr[2] = flagSealed
	if s.acceptorSubkey {
		hdr[2] |= flagAcceptorSubkey
	}
	hdr[3] = 0xFF
	binary.BigEndian.PutUint64(hdr[8:], s.sendSeq)
	s.sendSeq++
	// шифруется: сообщение | копия заголовка (EC=0, RRC=0)
	_, enc, err := et.EncryptMessage(s.key.KeyValue, append(append([]byte{}, msg...), hdr...), keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		return nil, nil, err
	}
	binary.BigEndian.PutUint16(hdr[6:], rrcWindows)
	rot := rotateRight(enc, rrcWindows)
	token := append(hdr, rot...)
	// граница: заголовок маркера + повёрнутый хвост (28) + зашифрованный «соль» (16 байт конфундера AES)
	split := wrapHeaderLen + rrcWindows + et.GetConfounderByteSize()
	return token[:split], token[split:], nil
}

// Unwrap расшифровывает сообщение сервера из частей WinRM (заголовок и данные).
func (s *Session) Unwrap(header, data []byte) ([]byte, error) {
	token := append(append([]byte{}, header...), data...)
	if len(token) < wrapHeaderLen || token[0] != 0x05 || token[1] != 0x04 || token[3] != 0xFF {
		return nil, ErrToken
	}
	flags := token[2]
	if flags&flagSentByAcceptor == 0 || flags&flagSealed == 0 || (flags&flagAcceptorSubkey != 0) != s.acceptorSubkey {
		return nil, errors.New("winrm kerberos: unexpected wrap token flags")
	}
	ec := int(binary.BigEndian.Uint16(token[4:6]))
	rrc := int(binary.BigEndian.Uint16(token[6:8]))
	et, err := crypto.GetEtype(s.key.KeyType)
	if err != nil {
		return nil, ErrUnsupportedEtype
	}
	// RFC 4121: поворот на RRC; Windows для части маркеров поворачивает на RRC+EC — пробуем оба
	plain, err := et.DecryptMessage(s.key.KeyValue, rotateLeft(token[wrapHeaderLen:], rrc), keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil && ec > 0 {
		plain, err = et.DecryptMessage(s.key.KeyValue, rotateLeft(token[wrapHeaderLen:], rrc+ec), keyusage.GSSAPI_ACCEPTOR_SEAL)
	}
	if err != nil {
		return nil, errors.New("winrm kerberos: message integrity check failed")
	}
	if len(plain) < ec+wrapHeaderLen {
		return nil, ErrToken
	}
	inner := plain[len(plain)-wrapHeaderLen:]
	want := append([]byte{}, token[:wrapHeaderLen]...)
	want[6], want[7] = 0, 0 // в зашифрованной копии RRC = 0
	if !hmac.Equal(inner, want) {
		return nil, errors.New("winrm kerberos: wrap token header mismatch")
	}
	return plain[:len(plain)-wrapHeaderLen-ec], nil
}

func rotateRight(b []byte, n int) []byte {
	if len(b) == 0 {
		return b
	}
	n %= len(b)
	return append(append([]byte{}, b[len(b)-n:]...), b[:len(b)-n]...)
}

func rotateLeft(b []byte, n int) []byte {
	if len(b) == 0 {
		return b
	}
	n %= len(b)
	return append(append([]byte{}, b[n:]...), b[:n]...)
}
