package winrmkrb

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
)

// fakeWinRM — сервер WinRM с шифрованием Kerberos (ключ известен заранее): расшифровывает запрос, отвечает
// зашифрованным эхо; каждое третье соединение закрывает после ответа (проверка повтора на простаивающем соединении).
func fakeWinRM(t *testing.T) (string, *int64) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var conns int64
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			n := atomic.AddInt64(&conns, 1)
			go func(nc net.Conn, n int64) {
				defer nc.Close()
				br := bufio.NewReader(nc)
				et, _ := crypto.GetEtype(testKey.KeyType)
				var seq uint64 = 1000
				for {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					body, _ := io.ReadAll(req.Body)
					parts := bytes.SplitN(body, []byte("\tContent-Type: application/octet-stream\r\n"), 2)
					payload := bytes.TrimSuffix(parts[1], []byte(boundary+"--\r\n"))
					hl := int(binary.LittleEndian.Uint32(payload[:4]))
					tok := payload[4:]
					plain, err := et.DecryptMessage(testKey.KeyValue, rotateLeft(tok[16:], int(binary.BigEndian.Uint16(tok[6:8]))), keyusage.GSSAPI_INITIATOR_SEAL)
					if err != nil || hl != 60 {
						fmt.Fprintf(nc, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
						return
					}
					msg := plain[:len(plain)-16]
					reply := append([]byte("echo:"), msg...)
					w := acceptorWrap(t, testKey, seq, reply)
					seq++
					var b bytes.Buffer
					fmt.Fprintf(&b, "%s\r\n\tContent-Type: %s\r\n\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n%s\r\n\tContent-Type: application/octet-stream\r\n", boundary, protocol, len(reply), boundary)
					_ = binary.Write(&b, binary.LittleEndian, uint32(60))
					b.Write(w)
					b.WriteString(boundary + "--\r\n")
					closeAfter := n%3 == 0
					hdr := "HTTP/1.1 200 OK\r\nContent-Type: multipart/encrypted;protocol=\"" + protocol + "\";boundary=\"Encrypted Boundary\"\r\nContent-Length: " + strconv.Itoa(b.Len()) + "\r\n"
					if closeAfter {
						hdr += "Connection: close\r\n"
					}
					nc.Write(append([]byte(hdr+"\r\n"), b.Bytes()...))
					if closeAfter {
						return
					}
				}
			}(nc, n)
		}
	}()
	return ln.Addr().String(), &conns
}

// Параллельные запросы (как у masterzen/winrm: чтение вывода в своей горутине) — без гонок и паник, каждый ответ
// приходит своему запросу; запускать с -race.
func TestConcurrentPosts(t *testing.T) {
	addr, conns := fakeWinRM(t)
	k, err := New(Target{Host: "pc.test.local", Addr: addr, User: "scan", Password: func(context.Context) ([]byte, error) { return []byte("x"), nil }})
	if err != nil {
		t.Fatal(err)
	}
	k.dialer = func(ctx context.Context, _ bool) (*conn, error) {
		nc, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return &conn{c: nc, br: bufio.NewReader(nc), sess: &Session{key: testKey, acceptorSubkey: true, sendSeq: 1}}, nil
	}
	defer k.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 400)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				msg := fmt.Sprintf("<m g=%d i=%d/>", g, i)
				out, err := k.post([]byte(msg))
				if err != nil || out != "echo:"+msg {
					errs <- fmt.Errorf("g%d i%d: %v %q", g, i, err, out)
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if atomic.LoadInt64(conns) < 2 || len(k.idle) > maxIdle {
		t.Fatal("connections", *conns, len(k.idle))
	}
	// после Close транспорт не паникует, а возвращает ошибку
	k.Close()
	if _, err = k.post([]byte("<late/>")); err == nil || strings.Contains(err.Error(), "internal") {
		t.Fatal("closed transport must refuse cleanly", err)
	}
}
