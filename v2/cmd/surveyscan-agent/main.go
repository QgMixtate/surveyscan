package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/agent"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/buildinfo"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/telemetry"
)

func run() error {
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		return buildinfo.Print(os.Stdout, "agent")
	}
	if handled, err := runNativeWorker(os.Args[1:]); handled {
		return err
	}
	if handled, err := runCollect12(os.Args[1:]); handled {
		return err
	}
	if handled, err := runServiceCommand(os.Args[1:]); handled {
		return err
	}
	if len(os.Args) < 2 {
		return fmt.Errorf("используйте prepare/enroll/bind-host/renew/run/run12/run-ssh12 --config /secure/agent.json")
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	configPath := flags.String("config", "", "private config")
	grantPath := flags.String("grant-file", "", "private enrollment grant")
	sshTarget := flags.String("ssh-target", "", "private SSH target config (run-ssh12)")
	winrmTarget := flags.String("winrm-target", "", "private WinRM target config (run-winrm12)")
	if e := flags.Parse(os.Args[2:]); e != nil {
		return e
	}
	if flags.NArg() != 0 || *configPath == "" {
		return fmt.Errorf("требуется явный --config")
	}
	c, e := agent.ReadConfig(*configPath)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch command {
	case "prepare":
		result, e := agent.Prepare(c)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "enroll":
		raw, e := privatefile.Read(*grantPath, 65536)
		if e != nil {
			return e
		}
		var grant contracts.EnrollmentGrant
		if e = json.Unmarshal(raw, &grant); e != nil {
			return fmt.Errorf("неверный файл grant")
		}
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if e = agent.Enroll(bounded, c, grant); e != nil {
			return e
		}
		fmt.Println("agent_enrolled")
		return nil
	case "bind-host":
		if e = agent.BindHost(ctx, c); e != nil {
			return e
		}
		fmt.Println("agent_host_bound")
		return nil
	case "renew":
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if e = agent.RenewOnce(bounded, c); e != nil {
			return e
		}
		fmt.Println("agent_certificate_renewed")
		return nil
	case "run":
		return runAgent(ctx, c, func(state string) { telemetry.Log(os.Stdout, "agent", state) })
	case "run12":
		// Явное включение цикла по профилю 1.2 на Linux; на Windows run уже использует 1.2.
		return runAgent12(ctx, c, func(state string) { telemetry.Log(os.Stdout, "agent", state) })
	case "run-ssh12":
		// Безагентная Linux-цель по SSH под отдельной личностью (профиль 1.2); только Linux-хост коллектора.
		if *sshTarget == "" {
			return fmt.Errorf("требуется --ssh-target")
		}
		target, e := agent.LoadSSHTarget(*sshTarget)
		if e != nil {
			return e
		}
		return runSSH12(ctx, c, target, func(state string) { telemetry.Log(os.Stdout, "agent", state) })
	case "run-winrm12":
		// Безагентная Windows-цель по WinRM под отдельной личностью (платформа windows/amd64 при выдаче grant).
		if *winrmTarget == "" {
			return fmt.Errorf("требуется --winrm-target")
		}
		target, e := agent.LoadWinRMTarget(*winrmTarget)
		if e != nil {
			return e
		}
		return runWinRM12(ctx, c, target, func(state string) { telemetry.Log(os.Stdout, "agent", state) })
	default:
		return fmt.Errorf("неизвестная команда агента")
	}
}

// exitError задаёт код выхода процесса (этапы службы), не печатая лишнего.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		var ee *exitError
		if errors.As(e, &ee) {
			os.Exit(ee.code)
		}
		// Этап завершения цикла (1 состояние, 2 Open, 3 очередь, 4 клиент 1.2) — код выхода процесса:
		// по нему супервизор и оператор отличают «не зарегистрирован» от отказа ACL/блокировки.
		var st *agent.StageError
		if errors.As(e, &st) && st.Code > 0 && st.Code < 256 {
			os.Exit(int(st.Code))
		}
		os.Exit(1)
	}
}
