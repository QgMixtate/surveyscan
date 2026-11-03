package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/app"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/buildinfo"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/config"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/health"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/migrate"
	"github.com/jackc/pgx/v5"
)

func run(args []string) error {
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}
	if len(args) > 1 {
		return fmt.Errorf("unexpected arguments")
	}
	if command == "version" || command == "--version" {
		return buildinfo.Print(os.Stdout, "server")
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
	if command != "serve" && command != "migrate" {
		return fmt.Errorf("supported commands: serve, migrate, version")
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
	server := &http.Server{Addr: addr, Handler: health.Handler(dbCheck, health.Bao(bao)), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServe() }()
	fmt.Println("surveyscan v2 C04 server started; application API pending C05-C07")
	select {
	case err = <-finished:
		if err != http.ErrServerClosed {
			return fmt.Errorf("HTTP server failed")
		}
		return nil
	case <-ctx.Done():
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		return server.Shutdown(shutdown)
	}
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
