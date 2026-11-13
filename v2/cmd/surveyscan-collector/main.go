package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/QgMixtate/surveyscan/v2/internal/collector"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/buildinfo"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func run(args []string) error {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		return buildinfo.Print(os.Stdout, "collector")
	}
	if len(args) == 0 || (args[0] != "run" && args[0] != "renew") {
		return fmt.Errorf("supported commands: run/renew --config PRIVATE_FILE, version")
	}
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *path == "" {
		return fmt.Errorf("private collector configuration required")
	}
	relay, e := collector.Load(*path)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if args[0] == "renew" {
		task, stop := context.WithTimeout(ctx, 30*time.Second)
		defer stop()
		if e = relay.RenewOnce(task); e != nil {
			return e
		}
		fmt.Println("collector_certificate_renewed")
		return nil
	}
	wireTargets(relay)
	fmt.Println("collector HTTPS relay started; pending data retained until verified center result")
	return relay.Run(ctx)
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
