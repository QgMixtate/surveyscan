// ssh-probe — ручная проверка безагентного SSH-сбора на живой цели (стенд, не production-инструмент).
//
//	ssh-probe fingerprint --addr host:22
//	ssh-probe collect --addr host:22 --user U --fingerprint SHA256:… (--password-file F | --key-file F [--passphrase-file F])
//
// Секреты читаются только из файлов (не из argv). Вывод — статусы и счётчики секций, без содержимого записей.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/remote/sshlinux"
)

func readSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secret file unreadable")
	}
	return b, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ssh-probe fingerprint|collect [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	addr := fs.String("addr", "", "host:port")
	user := fs.String("user", "", "SSH user")
	fp := fs.String("fingerprint", "", "pinned host key SHA256:…")
	pwFile := fs.String("password-file", "", "file with password")
	keyFile := fs.String("key-file", "", "file with PEM private key")
	ppFile := fs.String("passphrase-file", "", "file with key passphrase")
	_ = fs.Parse(os.Args[2:])
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch os.Args[1] {
	case "fingerprint":
		got, err := sshlinux.FetchHostKey(ctx, *addr, 10*time.Second)
		if err != nil {
			fmt.Println("FAIL:", err)
			os.Exit(1)
		}
		fmt.Println(got)
	case "collect":
		pw, e1 := readSecret(*pwFile)
		key, e2 := readSecret(*keyFile)
		pp, e3 := readSecret(*ppFile)
		if e1 != nil || e2 != nil || e3 != nil {
			fmt.Println("FAIL: secret file unreadable")
			os.Exit(1)
		}
		secret := sshlinux.Secret{Password: strings.TrimRight(string(pw), "\r\n"), PrivateKeyPEM: key, Passphrase: strings.TrimRight(string(pp), "\r\n")}
		secs, err := sshlinux.Collect(ctx, sshlinux.Target{Addr: *addr, User: *user, HostKeySHA256: *fp}, secret, sshlinux.Policy{})
		for _, s := range secs {
			fmt.Printf("%-13s status=%-11s reason=%-22s rows=%d\n", s.Name, s.Status, s.Reason, len(s.Records))
		}
		if err != nil {
			fmt.Println("RESULT: FAIL:", err)
			os.Exit(1)
		}
		fmt.Println("RESULT: OK (sections collected; check statuses above)")
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}
