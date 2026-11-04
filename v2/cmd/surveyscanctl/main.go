package main

import (
	"context"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/buildinfo"
	"github.com/QgMixtate/surveyscan/v2/internal/usercli"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		if e := buildinfo.Print(os.Stdout, "cli"); e != nil {
			os.Exit(5)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(usercli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
