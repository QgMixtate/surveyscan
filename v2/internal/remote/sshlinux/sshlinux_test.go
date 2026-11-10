package sshlinux

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeServer — настоящий SSH-сервер в процессе теста (реальный протокол и рукопожатие, не мок клиента).
type fakeServer struct {
	addr     string
	hostFP   string
	conns    atomic.Int32
	commands atomic.Int32
	outputs  map[string]string // команда → вывод; нет в карте → exit 1
	hang     string            // команда, которая не отвечает
}

func startServer(t *testing.T, password string, outputs map[string]string) *fakeServer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if c.User() == "scan" && string(p) == password {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{addr: l.Addr().String(), hostFP: Fingerprint(signer.PublicKey()), outputs: outputs}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			go s.serve(nc, cfg)
		}
	}()
	return s
}

func (s *fakeServer) serve(nc net.Conn, cfg *ssh.ServerConfig) {
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
		c, creqs, _ := ch.Accept()
		go func() {
			for r := range creqs {
				if r.Type != "exec" {
					_ = r.Reply(false, nil)
					continue
				}
				var p struct{ Command string }
				_ = ssh.Unmarshal(r.Payload, &p)
				_ = r.Reply(true, nil)
				s.commands.Add(1)
				if s.hang != "" && p.Command == s.hang {
					time.Sleep(10 * time.Second)
					return
				}
				code := uint32(1)
				if out, ok := s.outputs[p.Command]; ok {
					_, _ = c.Write([]byte(out))
					code = 0
				}
				_, _ = c.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
				c.Close()
			}
		}()
	}
}

func baseOutputs() map[string]string {
	return map[string]string{
		cmdHostname: "web01\n",
		cmdMachine:  "0123456789abcdef0123456789abcdef\n",
		cmdOSRel:    "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n",
		cmdUname:    "x86_64\n",
		cmdIPLink:   "2: eth0: <UP> mtu 1500 qdisc fq state UP\\    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n",
		cmdIPAddr:   "2: eth0    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth0\n",
		cmdCPU:      "processor\t: 0\nmodel name\t: Test CPU\n",
		cmdMem:      "MemTotal: 2048 kB\n",
		cmdDpkg:     "Package: bash\nStatus: install ok installed\nArchitecture: all\nVersion: 5.2-1\n",
		cmdUnits:    "ssh.service loaded active running SSH\n",
		cmdUnitFile: "ssh.service enabled enabled\n",
		cmdPasswd:   "root:x:0:0:root:/root:/bin/bash\n",
		cmdGroup:    "root:x:0:\n",
		cmdMounts:   "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
		cmdRoute:    "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\n",
		"cat /sys/class/dmi/id/sys_vendor 2>/dev/null": "QEMU\n",
	}
}

func TestCollectOverRealSSH(t *testing.T) {
	s := startServer(t, "pw", baseOutputs())
	secs, err := Collect(context.Background(), Target{Addr: s.addr, User: "scan", HostKeySHA256: s.hostFP}, Secret{Password: "pw"}, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]string{}
	for _, x := range secs {
		by[x.Name] = x.Status
		if x.Complete || x.Status == "ok" {
			t.Fatal("remote profile must be partial", x.Name)
		}
	}
	if len(Candidates(secs)) != 2 || len(Complete12(secs)) != 12 {
		t.Fatal("candidates / 12 sections", Candidates(secs), len(Complete12(secs)))
	}
	for _, n := range []string{"identity", "os", "network", "hardware", "software", "services", "users_groups", "resources", "routes_ports"} {
		if by[n] != "partial" {
			t.Errorf("%s: %s", n, by[n])
		}
	}
}

func TestHostKeyIsMandatoryAndStrict(t *testing.T) {
	s := startServer(t, "pw", baseOutputs())
	if _, err := Collect(context.Background(), Target{Addr: s.addr, User: "scan"}, Secret{Password: "pw"}, Policy{}); !errors.Is(err, ErrHostKeyRequired) {
		t.Fatal("empty fingerprint must be refused:", err)
	}
	if s.conns.Load() != 0 {
		t.Fatal("no connection may be attempted without a pinned key")
	}
	_, err := Collect(context.Background(), Target{Addr: s.addr, User: "scan", HostKeySHA256: "SHA256:AAAA"}, Secret{Password: "pw"}, Policy{})
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatal("wrong key must be refused:", err)
	}
	if s.conns.Load() != 1 {
		t.Fatal("key mismatch must not be retried, conns =", s.conns.Load())
	}
}

func TestFetchHostKeyDoesNotAuthenticate(t *testing.T) {
	s := startServer(t, "pw", baseOutputs())
	fp, err := FetchHostKey(context.Background(), s.addr, time.Second)
	if err != nil || fp != s.hostFP {
		t.Fatal(fp, err)
	}
	if s.commands.Load() != 0 {
		t.Fatal("probe must not run commands")
	}
}

func TestWrongPasswordIsNotRetried(t *testing.T) {
	s := startServer(t, "pw", baseOutputs())
	_, err := Collect(context.Background(), Target{Addr: s.addr, User: "scan", HostKeySHA256: s.hostFP}, Secret{Password: "bad"}, Policy{ConnectRetries: 3})
	if !errors.Is(err, ErrAuth) {
		t.Fatal(err)
	}
	if s.conns.Load() != 1 {
		t.Fatal("auth failure must not be retried (lockout risk), conns =", s.conns.Load())
	}
	if strings.Contains(err.Error(), "bad") {
		t.Fatal("secret in error")
	}
}

func TestCommandTimeoutGivesPartialResult(t *testing.T) {
	s := startServer(t, "pw", baseOutputs())
	s.hang = cmdUnits
	start := time.Now()
	secs, err := Collect(context.Background(), Target{Addr: s.addr, User: "scan", HostKeySHA256: s.hostFP}, Secret{Password: "pw"}, Policy{CommandTimeout: 300 * time.Millisecond})
	if err != nil || time.Since(start) > 5*time.Second {
		t.Fatal(err, time.Since(start))
	}
	by := map[string]string{}
	for _, x := range secs {
		by[x.Name] = x.Status
	}
	if by["services"] != "unavailable" || by["software"] != "partial" {
		t.Fatal("timeout must only affect the hanging source:", by)
	}
}

func TestCancelStopsCollection(t *testing.T) {
	s := startServer(t, "pw", baseOutputs())
	s.hang = cmdDpkg
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	secs, err := Collect(ctx, Target{Addr: s.addr, User: "scan", HostKeySHA256: s.hostFP}, Secret{Password: "pw"}, Policy{CommandTimeout: 8 * time.Second})
	if !errors.Is(err, context.Canceled) || time.Since(start) > 4*time.Second {
		t.Fatal(err, time.Since(start))
	}
	if len(secs) == 0 || secs[0].Name != "identity" {
		t.Fatal("sections gathered before cancel must be kept")
	}
}

func TestOutputLimit(t *testing.T) {
	o := baseOutputs()
	o[cmdPasswd] = strings.Repeat("u:x:1:1::/:/bin/sh\n", 1000)
	s := startServer(t, "pw", o)
	secs, _ := Collect(context.Background(), Target{Addr: s.addr, User: "scan", HostKeySHA256: s.hostFP}, Secret{Password: "pw"}, Policy{MaxOutput: 1024})
	for _, x := range secs {
		if x.Name == "users_groups" && x.Status != "unavailable" {
			t.Fatal("oversized output must make the source unavailable, got", x.Status)
		}
	}
}

func TestSecretIsRedacted(t *testing.T) {
	sec := Secret{Password: "TOPSECRET", PrivateKeyPEM: []byte("KEYDATA"), Passphrase: "PASS"}
	b, _ := json.Marshal(struct{ S Secret }{sec})
	for _, text := range []string{fmt.Sprint(sec), fmt.Sprintf("%+v", sec), fmt.Sprintf("%#v", sec), string(b)} {
		for _, bad := range []string{"TOPSECRET", "KEYDATA", "PASS\""} {
			if strings.Contains(text, bad) {
				t.Fatalf("secret leaked in %q", text)
			}
		}
	}
	if _, err := (Secret{}).authMethod(); !errors.Is(err, ErrNoSecret) {
		t.Fatal(err)
	}
	if _, err := (Secret{Password: "a", PrivateKeyPEM: []byte("b")}).authMethod(); !errors.Is(err, ErrNoSecret) {
		t.Fatal("both secrets must be refused")
	}
	if _, err := (Secret{PrivateKeyPEM: []byte("not a key")}).authMethod(); err == nil || strings.Contains(err.Error(), "not a key") {
		t.Fatal(err)
	}
}
