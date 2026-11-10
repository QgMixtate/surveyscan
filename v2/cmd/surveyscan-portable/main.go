// surveyscan-portable — разовый аудит без службы и без центра (C23.02).
//
//	surveyscan-portable init    --state DIR --tenant UUID --site UUID --scope UUID
//	surveyscan-portable collect --state DIR (--out FILE | --dry-run) [--no-host] [--ssh-target F]... [--winrm-target F]...
//	surveyscan-portable verify  --package FILE --public-key BASE64URL
//
// Личность и ключ подписи хранятся в --state (0700/0600) и в пакет не попадают. Секреты целей — только в своих
// приватных файлах, читаются в момент сбора. Ctrl-C прерывает сбор без частичного пакета.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/QgMixtate/surveyscan/v2/internal/agent"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/QgMixtate/surveyscan/v2/internal/portable"
	"github.com/QgMixtate/surveyscan/v2/internal/portableaudit"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/sshlinux"
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: surveyscan-portable init|collect|verify [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	state := fs.String("state", "", "каталог личности portable-источника")
	tenant := fs.String("tenant", "", "tenant UUID (выдаёт центр)")
	site := fs.String("site", "", "site UUID")
	scope := fs.String("scope", "", "network scope UUID")
	out := fs.String("out", "", "файл пакета (не перезаписывается)")
	dry := fs.Bool("dry-run", false, "только собрать и проверить, без пакета")
	noHost := fs.Bool("no-host", false, "не собирать этот хост")
	pkg := fs.String("package", "", "файл пакета для проверки")
	pubKey := fs.String("public-key", "", "открытый ключ portable-источника (base64url, из init)")
	var sshTargets, winrmTargets list
	fs.Var(&sshTargets, "ssh-target", "приватный JSON SSH-цели (можно несколько)")
	fs.Var(&winrmTargets, "winrm-target", "приватный JSON WinRM-цели (можно несколько)")
	_ = fs.Parse(os.Args[2:])
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch os.Args[1] {
	case "init":
		id, pub, err := portableaudit.Init(*state, *tenant, *site, *scope)
		if err != nil {
			fail("%v", err)
		}
		fmt.Printf("source_id=%s\nkey_id=%s\npublic_key=%s\n", id.SourceID, id.KeyID, base64.RawURLEncoding.EncodeToString(pub))
		fmt.Println("Передайте public_key в центр для доверия при импорте. Ключ подписи остаётся в", *state)
	case "collect":
		if (*out == "") == !*dry {
			fail("укажите ровно одно из --out FILE или --dry-run")
		}
		targets := []portableaudit.Target{}
		if !*noHost {
			host, _ := os.Hostname()
			targets = append(targets, portableaudit.Target{Kind: "host", Name: host, Collect: agent.CollectHost12})
		}
		for _, p := range sshTargets {
			t, err := agent.LoadSSHTarget(p)
			if err != nil {
				fail("%s: %v", p, err)
			}
			targets = append(targets, portableaudit.Target{Kind: "ssh", Name: t.Addr, Collect: agent.NewSSHCollect12(t, sshlinux.Policy{})})
		}
		for _, p := range winrmTargets {
			t, err := agent.LoadWinRMTarget(p)
			if err != nil {
				fail("%s: %v", p, err)
			}
			targets = append(targets, portableaudit.Target{Kind: "winrm", Name: t.Host, Collect: agent.NewWinRMCollect12(t)})
		}
		if len(targets) == 0 {
			fail("нет целей")
		}
		rep, err := portableaudit.Run(ctx, *state, targets, *out, func(s string) { fmt.Fprintln(os.Stderr, s) })
		if err != nil {
			fail("%v", err)
		}
		fmt.Printf("source_id=%s key_id=%s\n", rep.SourceID, rep.KeyID)
		failed := 0
		for _, r := range rep.Results {
			if r.Err != "" {
				failed++
				fmt.Printf("%-6s %-24s FAILED: %s\n", r.Kind, r.Target, r.Err)
				continue
			}
			names := make([]string, 0, len(r.Sections))
			for n := range r.Sections {
				names = append(names, n)
			}
			sort.Strings(names)
			fmt.Printf("%-6s %-24s rows=%d\n", r.Kind, r.Target, r.Rows)
			for _, n := range names {
				fmt.Printf("         %-13s %s\n", n, r.Sections[n])
			}
		}
		if *dry {
			fmt.Printf("DRY RUN: %d target(s) ok, %d failed; package not written\n", len(rep.Observation), failed)
		} else {
			fmt.Printf("EXPORTED: %d observation(s) -> %s (%d target(s) failed)\n", rep.Exported, rep.Package, failed)
		}
		if failed > 0 {
			os.Exit(3) // частичный результат: оператор видит, что не все цели собраны
		}
	case "verify":
		pub, err := base64.RawURLEncoding.DecodeString(*pubKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			fail("--public-key: нужен base64url открытого ключа из init")
		}
		data, err := os.ReadFile(*pkg)
		if err != nil {
			fail("%v", err)
		}
		v, err := wire.NewInventory12()
		if err != nil {
			fail("%v", err)
		}
		key := ed25519.PublicKey(pub)
		res, err := portable.Import(data, map[string]ed25519.PublicKey{portable.KeyID(key): key}, portable.Known{}, portable.DefaultLimits(), v)
		if err != nil {
			fail("%v", err)
		}
		fmt.Printf("VERIFIED: source_id=%s observations=%d accepted=%d quarantined=%d\n", res.Manifest.SourceID, len(res.Manifest.Items), len(res.Accepted), len(res.Quarantined))
		for _, q := range res.Quarantined {
			fmt.Printf("  quarantined %s: %s\n", q.ID, q.Reason)
		}
	default:
		fail("неизвестная команда %q", os.Args[1])
	}
}
