//go:build windows

// Package winservice управляет Windows-службой агента через SCM: установка с отложенным
// автозапуском и перезапуском при сбое, запуск, остановка, удаление и вход службы (Run).
// Учётная запись — LocalSystem: инвентаризации нужны права администратора, а состояние
// агента доверяет только SYSTEM и Administrators.
package winservice

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type Spec struct {
	Name        string
	DisplayName string
	Description string
	Exe         string
	Args        []string
}

// StageError несёт код, который попадёт в ServiceSpecificExitCode: по нему видно, на каком
// этапе служба завершилась, без записи путей и секретов в журналы.
type StageError struct {
	Code uint32
	Err  error
}

func (e *StageError) Error() string { return e.Err.Error() }
func (e *StageError) Unwrap() error { return e.Err }

var ErrInstalled = errors.New("service already installed")

func validName(name string) bool {
	if name == "" || len(name) > 80 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// Install создаёт службу LocalSystem с отложенным автозапуском и тремя перезапусками при сбое.
func Install(s Spec) error {
	if !validName(s.Name) || !filepath.IsAbs(s.Exe) {
		return errors.New("service name or executable path invalid")
	}
	if info, e := os.Stat(s.Exe); e != nil || info.IsDir() {
		return errors.New("service executable unavailable")
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	if existing, e := m.OpenService(s.Name); e == nil {
		existing.Close()
		return ErrInstalled
	}
	service, e := m.CreateService(s.Name, s.Exe, mgr.Config{DisplayName: s.DisplayName, Description: s.Description,
		StartType: mgr.StartAutomatic, DelayedAutoStart: true, ErrorControl: mgr.ErrorNormal}, s.Args...)
	if e != nil {
		return e
	}
	defer service.Close()
	actions := []mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Minute}, {Type: mgr.ServiceRestart, Delay: time.Minute}, {Type: mgr.ServiceRestart, Delay: 5 * time.Minute}}
	if e = service.SetRecoveryActions(actions, 86400); e != nil {
		_ = service.Delete()
		return e
	}
	if e = service.SetRecoveryActionsOnNonCrashFailures(true); e != nil {
		_ = service.Delete()
		return e
	}
	return nil
}

func open(name string, access uint32) (*mgr.Mgr, *mgr.Service, error) {
	if !validName(name) {
		return nil, nil, errors.New("service name invalid")
	}
	m, e := mgr.Connect()
	if e != nil {
		return nil, nil, e
	}
	service, e := m.OpenService(name)
	if e != nil {
		m.Disconnect()
		return nil, nil, e
	}
	return m, service, nil
}

// Uninstall останавливает службу при необходимости и удаляет её. Данные агента не трогает:
// личность и очередь сохраняются для повторной установки.
func Uninstall(name string) error {
	m, service, e := open(name, 0)
	if e != nil {
		return e
	}
	defer m.Disconnect()
	defer service.Close()
	if status, e := service.Query(); e == nil && status.State != svc.Stopped {
		_, _ = service.Control(svc.Stop)
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if status, e = service.Query(); e == nil && status.State == svc.Stopped {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	return service.Delete()
}

func Start(name string) error {
	m, service, e := open(name, 0)
	if e != nil {
		return e
	}
	defer m.Disconnect()
	defer service.Close()
	return service.Start()
}

func Stop(name string, timeout time.Duration) error {
	m, service, e := open(name, 0)
	if e != nil {
		return e
	}
	defer m.Disconnect()
	defer service.Close()
	if _, e = service.Control(svc.Stop); e != nil {
		return e
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, e := service.Query()
		if e != nil {
			return e
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("service did not stop in time")
}

// Status возвращает состояние и код выхода (специфичный для службы, если задан).
func Status(name string) (state svc.State, exitCode uint32, e error) {
	m, service, e := open(name, 0)
	if e != nil {
		return 0, 0, e
	}
	defer m.Disconnect()
	defer service.Close()
	status, e := service.Query()
	if e != nil {
		return 0, 0, e
	}
	code := status.Win32ExitCode
	if code == uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) {
		code = status.ServiceSpecificExitCode
	}
	return status.State, code, nil
}

type handler struct {
	run func(context.Context) error
}

func (h *handler) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending, WaitHint: 30000}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case err := <-done:
			if err == nil {
				return false, 0
			}
			var stage *StageError
			if errors.As(err, &stage) {
				return true, stage.Code
			}
			return true, 1
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 30000}
				cancel()
				select {
				case <-done:
				case <-time.After(25 * time.Second):
				}
				return false, 0
			}
		}
	}
}

// Run отдаёт управление SCM и блокируется до остановки службы. Вызывается только из
// процесса, который запустил SCM.
func Run(name string, run func(context.Context) error) error {
	return svc.Run(name, &handler{run: run})
}
