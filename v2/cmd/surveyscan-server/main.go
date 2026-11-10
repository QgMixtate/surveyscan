package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/buildinfo"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/config"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/migrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func run(args []string) error {
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}
	if command == "bootstrap-issuer" {
		return bootstrapIssuer(args[1:])
	}
	isConsole := command == "bootstrap-admin" || command == "create-user" || command == "set-user-state" || command == "reset-password" || command == "portable-register" || command == "portable-import"
	if len(args) > 1 && !isConsole {
		return fmt.Errorf("unexpected arguments")
	}
	if command == "version" || command == "--version" {
		return buildinfo.Print(os.Stdout, "server")
	}
	if command == "schema-catalog" {
		ms, err := app.Migrations()
		if err != nil {
			return err
		}
		catalog, err := migrate.Catalog(ms)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"format": "surveyscan-schema-v1", "migrations": catalog})
	}
	if command == "healthcheck" {
		addr, e := config.ListenAddress()
		if e != nil {
			return e
		}
		host, port, _ := net.SplitHostPort(addr)
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		c := http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/health/ready")
		if err != nil {
			return fmt.Errorf("not ready")
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("not ready")
		}
		return nil
	}
	if command != "serve" && command != "migrate" && command != "schema-check" && !isConsole {
		return fmt.Errorf("supported commands: serve, migrate, schema-catalog, schema-check, version, bootstrap-admin, create-user, set-user-state, reset-password, portable-register, portable-import")
	}
	db, err := config.Database()
	if err != nil {
		return err
	}
	catalog, err := app.Migrations()
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if command == "schema-check" {
		conn, err := pgx.ConnectConfig(ctx, db)
		if err != nil {
			return fmt.Errorf("database connection failed")
		}
		defer conn.Close(context.Background())
		if err = migrate.Check(ctx, conn, catalog); err != nil {
			return fmt.Errorf("schema incompatible with this binary")
		}
		fmt.Println("schema_compatible")
		return nil
	}
	if command == "migrate" {
		conn, err := pgx.ConnectConfig(ctx, db)
		if err != nil {
			return fmt.Errorf("database connection failed")
		}
		defer conn.Close(context.Background())
		n, err := migrate.Apply(ctx, conn, catalog)
		if err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
		fmt.Printf("applied_migrations=%d\n", n)
		return nil
	}

	poolConfig, err := pgxpool.ParseConfig("")
	if err != nil {
		return fmt.Errorf("database pool configuration failed")
	}
	poolConfig.ConnConfig = db.Copy()
	poolConfig.ConnConfig.ConnectTimeout = 3 * time.Second
	poolConfig.MaxConns = 8
	poolConfig.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return fmt.Errorf("database pool failed")
	}
	defer pool.Close()
	if isConsole {
		conn, e := pgx.ConnectConfig(ctx, db)
		if e != nil {
			return fmt.Errorf("database connection failed")
		}
		e = migrate.Check(ctx, conn, catalog)
		conn.Close(ctx)
		if e != nil {
			return fmt.Errorf("apply migrations before console administration")
		}
		if err = console(ctx, pool, command, args[1:]); err != nil {
			return fmt.Errorf("console operation failed")
		}
		fmt.Println("console operation completed; no credentials printed")
		return nil
	}
	authService := access.New(pool)
	auth, err := access.NewHTTP(authService, os.Getenv("SURVEYSCAN_V2_PUBLIC_ORIGIN"), os.Getenv("SURVEYSCAN_V2_INSECURE_LOCAL_HTTP") == "1")
	if err != nil {
		return err
	}
	addr, err := config.ListenAddress()
	if err != nil {
		return err
	}
	bao, err := config.BaoURL()
	if err != nil {
		return err
	}
	dbCheck := func(ctx context.Context) error {
		conn, err := pgx.ConnectConfig(ctx, db)
		if err != nil {
			return err
		}
		defer conn.Close(context.Background())
		if err = conn.Ping(ctx); err != nil {
			return err
		}
		return migrate.Check(ctx, conn, catalog)
	}
	registry, err := app.NewRegistry(pool, authService)
	if err != nil {
		return err
	}
	machineListen := ""
	var machineTLS *tls.Config
	if path := os.Getenv("SURVEYSCAN_V2_MACHINE_CONFIG"); path != "" {
		machineListen, machineTLS, err = app.ConfigureMachine(path, registry, authService)
		if err != nil {
			return err
		}
	}
	if registry.Machine != nil && registry.Machine.Maintain != nil {
		go registry.Machine.Maintain(ctx)
	}
	checks := []health.Check{dbCheck, health.Bao(bao)}
	if registry.Machine != nil && registry.Machine.Ready != nil {
		checks[1] = registry.Machine.Ready
	}
	handler, err := app.NewHTTP(auth, health.Handler(checks...), registry)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				task, done := context.WithTimeout(ctx, 5*time.Second)
				tenants, e := messaging.PendingTenants(task, pool)
				if e == nil {
					for _, tenant := range tenants {
						for range 100 {
							worked, e := registry.ConsumeOne(task, tenant)
							if e != nil || !worked {
								break
							}
						}
					}
				}
				done()
			}
		}
	}()
	finished := make(chan error, 2)
	var machineServer *http.Server
	if machineTLS != nil {
		machineServer = &http.Server{Addr: machineListen, Handler: handler, TLSConfig: machineTLS, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
		defer machineServer.Close()
		go func() { finished <- machineServer.ListenAndServeTLS("", "") }()
	}
	defer server.Close()
	go func() { finished <- server.ListenAndServe() }()
	fmt.Println("surveyscan v2 C06 registry server started; machine transport pending C07")
	select {
	case err = <-finished:
		if err != http.ErrServerClosed {
			return fmt.Errorf("HTTP server failed")
		}
		return nil
	case <-ctx.Done():
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if machineServer != nil {
			_ = machineServer.Shutdown(shutdown)
		}
		return server.Shutdown(shutdown)
	}
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
