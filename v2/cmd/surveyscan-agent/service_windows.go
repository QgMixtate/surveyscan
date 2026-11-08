//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/QgMixtate/surveyscan/v2/internal/agent"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/telemetry"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/winservice"
)

const defaultServiceName = "SurveyscanAgent"

// runServiceCommand обрабатывает install-service/uninstall-service/service до общего разбора
// команд: им нужен свой набор флагов. Возвращает handled=true, если команда распознана.
func runServiceCommand(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "install-service", "uninstall-service", "service":
	default:
		return false, nil
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	name := flags.String("name", defaultServiceName, "service name")
	configPath := flags.String("config", "", "private config (absolute path)")
	errorFile := flags.String("error-file", "", "необязательный файл для текста ошибки завершения службы (диагностика)")
	if e := flags.Parse(args[1:]); e != nil {
		return true, e
	}
	if flags.NArg() != 0 {
		return true, errors.New("лишние аргументы команды службы")
	}
	switch args[0] {
	case "uninstall-service":
		return true, winservice.Uninstall(*name)
	case "install-service":
		if !filepath.IsAbs(*configPath) {
			return true, errors.New("для службы требуется абсолютный --config")
		}
		exe, e := os.Executable()
		if e != nil {
			return true, e
		}
		e = winservice.Install(winservice.Spec{Name: *name, DisplayName: "surveyscan agent",
			Description: "Постоянный агент инвентаризации surveyscan", Exe: exe,
			Args: serviceArgs(*name, *configPath, *errorFile)})
		if e == nil {
			fmt.Println("service_installed")
		}
		return true, e
	default: // service — вход SCM
		c, e := agent.ReadConfig(*configPath)
		if e != nil {
			noteError(*errorFile, "config", e)
			return true, &exitError{code: 1, err: e}
		}
		e = winservice.Run(*name, func(ctx context.Context) error {
			err := agent.RunWindows(ctx, c, func(state string) { telemetry.Log(os.Stdout, "agent", state) })
			if err != nil && !errors.Is(err, context.Canceled) {
				noteError(*errorFile, "run", err)
			}
			var st *agent.StageError
			if errors.As(err, &st) {
				return &winservice.StageError{Code: st.Code, Err: err}
			}
			return err
		})
		if e != nil {
			noteError(*errorFile, "scm", e)
		}
		return true, e
	}
}

func serviceArgs(name, config, errorFile string) []string {
	args := []string{"service", "--name", name, "--config", config}
	if errorFile != "" {
		args = append(args, "--error-file", errorFile)
	}
	return args
}

// noteError дописывает причину завершения в файл диагностики, если он задан.
func noteError(path, stage string, err error) {
	if path == "" {
		return
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if e != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s: %v\n", stage, err)
}
