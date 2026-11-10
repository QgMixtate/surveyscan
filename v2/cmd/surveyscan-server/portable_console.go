package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/audit"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
)

// portableConsole — операторские команды C23.03 на хосте центра (как bootstrap-admin/create-user):
//
//	portable-register --tenant T --site S --scope SC --source ID --generation G --public-key B64URL
//	portable-import   --tenant T --source ID --package FILE
//
// Доступ — у того, кто запускает сервер с его конфигурацией БД. Итог импорта печатается JSON-отчётом.
func portableConsole(ctx context.Context, pool *pgxpool.Pool, command string, args []string) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	tenant := f.String("tenant", "", "")
	site := f.String("site", "", "")
	scope := f.String("scope", "", "")
	source := f.String("source", "", "")
	generation := f.String("generation", "", "")
	publicKey := f.String("public-key", "", "")
	pkgPath := f.String("package", "", "")
	if e := f.Parse(args); e != nil || f.NArg() != 0 {
		return errors.New("invalid portable console arguments")
	}
	machine := &sources.MachineService{Pool: pool, Audit: audit.Store{}}
	if command == "portable-register" {
		pub, e := base64.RawURLEncoding.DecodeString(*publicKey)
		if e != nil {
			return errors.New("public key must be base64url (from surveyscan-portable init)")
		}
		keyID, e := machine.RegisterPortable(ctx, "console", sources.PortableRegistration{Tenant: *tenant, Site: *site, Scope: *scope, Source: *source, Generation: *generation, PublicKey: pub})
		if e != nil {
			fmt.Fprintln(os.Stderr, "portable-register:", e)
			return e
		}
		fmt.Printf("portable source registered: source_id=%s key_id=%s\n", *source, keyID)
		return nil
	}
	data, e := os.ReadFile(*pkgPath)
	if e != nil {
		return errors.New("package file unreadable")
	}
	registry, e := app.NewRegistry(pool, access.New(pool))
	if e != nil {
		return e
	}
	if _, e = registry.ConfigureInventoryProtocol12(true); e != nil {
		return e
	}
	report, e := registry.ImportPortable(ctx, machine, *tenant, *source, data)
	if e != nil {
		fmt.Fprintln(os.Stderr, "portable-import:", e)
		return e
	}
	out, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(out))
	return nil
}
