//go:build windows

package windowsinventory

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

var ErrWorkerArguments = errors.New("unsupported read-only inventory worker arguments")

// Only our own binary and a closed section vocabulary can execute. Profiles,
// network callers and worker input cannot supply an executable or a command.
var workerCommand = func(ctx context.Context, name string) (*exec.Cmd, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, path, "inventory-worker", name), nil
}

type workerOutput struct {
	bytes.Buffer
	limit  int
	over   bool
	cancel context.CancelFunc
}

func (w *workerOutput) Write(b []byte) (int, error) {
	if len(b) > w.limit-w.Len() {
		w.over = true
		w.cancel()
		return 0, errors.New("worker output limit")
	}
	return w.Buffer.Write(b)
}

func failedSection(name, status, reason string) contracts.Section {
	return contracts.Section{Name: name, CollectedAt: time.Now().UTC(), Status: status, Complete: false, Reason: reason, Records: []map[string]any{}}
}

func workerSection(ctx context.Context, name string, timeout time.Duration) contracts.Section {
	if name != "updates" && name != "protection" {
		return failedSection(name, "unsupported", "SECTION_UNSUPPORTED")
	}
	if timeout <= 0 || timeout > 30*time.Second {
		return failedSection(name, "unavailable", "INVALID_TIMEOUT")
	}
	child, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd, err := workerCommand(child, name)
	if err != nil {
		return failedSection(name, "unavailable", "WORKER_UNAVAILABLE")
	}
	output := &workerOutput{limit: wire.Inventory12MaxPayload, cancel: cancel}
	cmd.Stdout, cmd.Stderr = output, io.Discard
	cmd.WaitDelay = time.Second
	err = cmd.Run()
	if output.over {
		return failedSection(name, "unavailable", "LIMIT_REACHED")
	}
	if child.Err() != nil {
		reason := "TIMEOUT"
		if errors.Is(child.Err(), context.Canceled) {
			reason = "CANCELLED"
		}
		return failedSection(name, "unavailable", reason)
	}
	if err != nil {
		return failedSection(name, "unavailable", "WORKER_FAILED")
	}
	validator, err := wire.NewInventory12()
	if err != nil {
		return failedSection(name, "unavailable", "CONTRACT_UNAVAILABLE")
	}
	section, err := validator.Section(output.Bytes())
	if err != nil || section.Name != name || section.CollectedAt.After(time.Now().UTC().Add(time.Second)) {
		return failedSection(name, "unavailable", "INVALID_WORKER_RESPONSE")
	}
	return section
}
