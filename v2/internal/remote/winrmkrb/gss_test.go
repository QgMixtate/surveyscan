package winrmkrb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

var testKey = types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x42}, 32)}

// acceptorWrap — маркер сервера (как Windows: отправлен сервером, зашифрован, подключ сервера, EC=0, RRC=28).
func acceptorWrap(t *testing.T, key types.EncryptionKey, seq uint64, msg []byte) []byte {
	et, _ := crypto.GetEtype(key.KeyType)
	hdr := []byte{0x05, 0x04, flagSentByAcceptor | flagSealed | flagAcceptorSubkey, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(hdr[8:], seq)
	_, enc, err := et.EncryptMessage(key.KeyValue, append(append([]byte{}, msg...), hdr...), keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(hdr[6:], 28)
	return append(hdr, rotateRight(enc, 28)...)
}

func TestWrapLayoutAndRoundTrip(t *testing.T) {
	s := &Session{key: testKey, acceptorSubkey: true, sendSeq: 7}
	msg := []byte("<s:Envelope>surveyscan</s:Envelope>")
	header, data, err := s.Wrap(msg)
	if err != nil || len(header) != 60 || len(data) != len(msg) {
		t.Fatal("WinRM split must be 60-byte header + ciphertext of the message length", len(header), len(data), err)
	}
	if header[2] != flagSealed|flagAcceptorSubkey || binary.BigEndian.Uint16(header[6:8]) != 28 || binary.BigEndian.Uint64(header[8:16]) != 7 {
		t.Fatalf("token header %x", header[:16])
	}
	// наш маркер расшифровывается по RFC 4121 ключом инициатора (usage 24) и содержит копию заголовка с RRC=0
	et, _ := crypto.GetEtype(testKey.KeyType)
	tok := append(append([]byte{}, header...), data...)
	plain, err := et.DecryptMessage(testKey.KeyValue, rotateLeft(tok[16:], 28), keyusage.GSSAPI_INITIATOR_SEAL)
	want := append([]byte{}, tok[:16]...)
	want[6], want[7] = 0, 0
	if err != nil || !bytes.Equal(plain, append(append([]byte{}, msg...), want...)) {
		t.Fatal("initiator token does not decrypt to message+header", err)
	}
	// ответ сервера расшифровывается; подмена байта — отказ; свой маркер (без флага сервера) не принимается
	reply := acceptorWrap(t, testKey, 99, []byte("<reply/>"))
	got, err := s.Unwrap(reply[:60], reply[60:])
	if err != nil || string(got) != "<reply/>" {
		t.Fatal("unwrap", err, got)
	}
	bad := append([]byte{}, reply...)
	bad[len(bad)-1] ^= 1
	if _, err = s.Unwrap(bad[:60], bad[60:]); err == nil {
		t.Fatal("tampered message must be refused")
	}
	if _, err = s.Unwrap(header, data); err == nil {
		t.Fatal("own (initiator) token must not be accepted as a reply")
	}
}

func TestPrincipal(t *testing.T) {
	for _, c := range []struct{ user, host, name, realm string }{
		{`AWM\scan`, "win-ar.awm.local", "scan", "AWM.LOCAL"},
		{"scan@awm.local", "win-ar.awm.local", "scan", "AWM.LOCAL"},
		{"scan", "PC1.Corp.Example.", "scan", "CORP.EXAMPLE"},
	} {
		n, r, err := Principal(c.user, c.host)
		if err != nil || n != c.name || r != c.realm {
			t.Fatal(c, n, r, err)
		}
	}
	for _, host := range []string{"10.170.108.10", "win-ar"} {
		if _, _, err := Principal("scan", host); err == nil {
			t.Fatal("kerberos target must be a fully qualified name", host)
		}
	}
}

// Сверка с независимой реализацией (impacket): SURVEYSCAN_KRB_XCHECK=<каталог> — пишем наш маркер, читаем маркер
// сервера, построенный impacket (scripts в песочнице; в CI не запускается).
func TestCrossCheckFiles(t *testing.T) {
	dir := os.Getenv("SURVEYSCAN_KRB_XCHECK")
	if dir == "" {
		t.Skip("cross-check directory not set")
	}
	s := &Session{key: testKey, acceptorSubkey: true, sendSeq: 5}
	header, data, err := s.Wrap([]byte("hello from go"))
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "go.hex"), []byte(hex.EncodeToString(append(header, data...))), 0o600)
	raw, err := os.ReadFile(filepath.Join(dir, "py.hex"))
	if err != nil {
		t.Skip("no py.hex yet")
	}
	tok, _ := hex.DecodeString(string(bytes.TrimSpace(raw)))
	got, err := s.Unwrap(tok[:60], tok[60:])
	if err != nil || string(got) != "hello from python" {
		t.Fatal("impacket token", err, string(got))
	}
}
