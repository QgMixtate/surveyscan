//go:build windows

package winservice

import (
	"context"
	"flag"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// SCM запускает сам тестовый бинарник как службу: позиционные аргументы после "--" включают режим помощника.
func TestServiceHelperProcess(t *testing.T) {
	args := flag.Args()
	if len(args) != 2 || args[0] != "scm-helper" {
		t.Skip("запускается только SCM")
	}
	if err := Run(args[1], func(ctx context.Context) error { <-ctx.Done(); return nil }); err != nil {
		t.Fatal(err)
	}
}

func waitState(t *testing.T, name string, want svc.State, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if state, _, err := Status(name); err == nil && state == want {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	state, code, err := Status(name)
	t.Fatalf("service %s did not reach state %d: state=%d exit=%d err=%v", name, want, state, code, err)
}

func TestServiceLifecycleThroughSCM(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("SCM operations require an elevated administrator")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	name := "SurveyScanTest" + identifier.New()[:8]
	spec := Spec{Name: name, DisplayName: "SurveyScan test " + name, Description: "temporary lifecycle test", Exe: exe,
		Args: []string{"-test.run=^TestServiceHelperProcess$", "--", "scm-helper", name}}
	if err = Install(spec); err != nil {
		t.Fatal("install", err)
	}
	defer func() { _ = Uninstall(name) }()
	if err = Install(spec); err != ErrInstalled {
		t.Fatal("second install must be refused", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		t.Fatal(err)
	}
	config, err := s.Config()
	if err != nil {
		t.Fatal(err)
	}
	if config.StartType != mgr.StartAutomatic || !config.DelayedAutoStart || config.ServiceStartName != "LocalSystem" {
		t.Fatal("service must be delayed-automatic LocalSystem", config.StartType, config.DelayedAutoStart, config.ServiceStartName)
	}
	actions, err := s.RecoveryActions()
	if err != nil || len(actions) != 3 || actions[0].Type != mgr.ServiceRestart || actions[2].Delay != 5*time.Minute {
		t.Fatal("recovery actions", actions, err)
	}
	s.Close()
	if err = Start(name); err != nil {
		t.Fatal("start", err)
	}
	waitState(t, name, svc.Running, 30*time.Second)
	if err = Stop(name, 40*time.Second); err != nil {
		t.Fatal("stop", err)
	}
	waitState(t, name, svc.Stopped, 10*time.Second)
	if state, code, err := Status(name); err != nil || state != svc.Stopped || code != 0 {
		t.Fatal("a requested stop must be a clean exit", state, code, err)
	}
	if err = Uninstall(name); err != nil {
		t.Fatal("uninstall", err)
	}
	if _, _, err = Status(name); err == nil {
		t.Fatal("service still present after uninstall")
	}
	if Install(Spec{Name: "bad name", Exe: exe}) == nil || Install(Spec{Name: name, Exe: "relative.exe"}) == nil {
		t.Fatal("invalid name or relative path accepted")
	}
}
