// testsshd — тестовый SSH-сервер для смока C51.03 (не входит в поставку): слушает только 127.0.0.1, пускает одного
// пользователя по паролю из приватного файла и выполняет команды сбора по-настоящему через /bin/sh (только exec,
// без оболочки и пересылок). Печатает адрес и отпечаток ключа хоста.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh"
)

func main() {
	user := flag.String("user", "scanprobe", "")
	passwordFile := flag.String("password-file", "", "")
	flag.Parse()
	raw, err := os.ReadFile(*passwordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "password file required")
		os.Exit(2)
	}
	password := strings.TrimRight(string(raw), "\r\n")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if c.User() == *user && string(p) == password {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(1)
	}
	fmt.Printf("addr=%s fingerprint=%s\n", l.Addr(), ssh.FingerprintSHA256(signer.PublicKey()))
	for {
		nc, err := l.Accept()
		if err != nil {
			return
		}
		go serve(nc, cfg)
	}
}

func serve(nc net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		c, creqs, err := ch.Accept()
		if err != nil {
			continue
		}
		go func() {
			for r := range creqs {
				if r.Type != "exec" {
					_ = r.Reply(false, nil)
					continue
				}
				var p struct{ Command string }
				_ = ssh.Unmarshal(r.Payload, &p)
				_ = r.Reply(true, nil)
				cmd := exec.Command("/bin/sh", "-c", p.Command)
				cmd.Stdout, cmd.Stderr = c, c.Stderr()
				code := uint32(0)
				if err := cmd.Run(); err != nil {
					code = 1
					var ee *exec.ExitError
					if errors.As(err, &ee) {
						code = uint32(ee.ExitCode())
					}
				}
				_, _ = c.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
				c.Close()
			}
		}()
	}
}
