package main

import (
	"context"
	"errors"
	"flag"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"os"
	"strings"
)

func console(ctx context.Context, pool *pgxpool.Pool, command string, args []string) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	tenant := f.String("tenant", "", "")
	name := f.String("tenant-name", "", "")
	username := f.String("username", "", "")
	passwordFile := f.String("password-file", "", "")
	role := f.String("role", "viewer", "")
	enabled := f.Bool("enabled", true, "")
	if e := f.Parse(args); e != nil || f.NArg() != 0 {
		return errors.New("invalid console arguments")
	}
	service := access.New(pool)
	if command == "set-user-state" {
		return service.ChangeUser(ctx, *tenant, *username, *role, *enabled)
	}
	file, e := os.Open(*passwordFile)
	if e != nil {
		return errors.New("private password file required")
	}
	defer file.Close()
	info, e := file.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1026 {
		return errors.New("password file must be private regular file")
	}
	b, e := io.ReadAll(io.LimitReader(file, 1027))
	if e != nil || len(b) > 1026 {
		return errors.New("invalid password file")
	}
	password := strings.TrimRight(string(b), "\r\n")
	if command == "reset-password" {
		return service.ResetPassword(ctx, *tenant, *username, password)
	}
	if command == "bootstrap-admin" {
		*role = "admin"
	}
	return service.Provision(ctx, command == "bootstrap-admin", *tenant, *name, *username, password, *role)
}
