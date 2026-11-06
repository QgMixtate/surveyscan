//go:build windows

package windowsinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ole "github.com/go-ole/go-ole"
)

func TestMain(m *testing.M) {
	if path := os.Getenv("SURVEYSCAN_C15_TEST_AGENT"); path != "" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			os.Exit(2)
		}
		workerCommand = func(ctx context.Context, name string) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, absolute, "inventory-worker", name), nil
		}
	}
	os.Exit(m.Run())
}

func TestWorkerHelperProcess(t *testing.T) {
	mode := os.Getenv("SURVEYSCAN_TEST_WORKER_MODE")
	if mode == "" {
		return
	}
	fmt.Fprintln(os.Stderr, "canary-private-provider-error")
	switch mode {
	case "wait":
		os.WriteFile(os.Getenv("SURVEYSCAN_TEST_WORKER_MARKER"), []byte("ready"), 0600)
		time.Sleep(time.Minute)
	case "oversized":
		fmt.Print(strings.Repeat("x", 2<<20))
	case "malformed":
		fmt.Print(`{"password":"canary-private-provider-error"}`)
	case "wrong-section":
		json.NewEncoder(os.Stdout).Encode(failedSection("protection", "unsupported", "PROVIDER_UNAVAILABLE"))
	case "crash":
		os.Exit(2)
	case "valid":
		json.NewEncoder(os.Stdout).Encode(failedSection("updates", "partial", "QFE_SUBSET"))
	case "valid-protection":
		json.NewEncoder(os.Stdout).Encode(failedSection("protection", "partial", "BASELINE_COVERAGE_ONLY"))
	}
	os.Exit(0)
}

func TestWorkerFailureDoesNotDiscardOtherSections(t *testing.T) {
	original := workerCommand
	defer func() { workerCommand = original }()
	workerCommand = func(ctx context.Context, name string) (*exec.Cmd, error) {
		path, err := os.Executable()
		if err != nil {
			return nil, err
		}
		mode := "crash"
		if name == "protection" {
			mode = "valid-protection"
		}
		cmd := exec.CommandContext(ctx, path, "-test.run=^TestWorkerHelperProcess$")
		cmd.Env = append(os.Environ(), "SURVEYSCAN_TEST_WORKER_MODE="+mode)
		return cmd, nil
	}
	sections, err := Collect(context.Background())
	if err != nil || len(sections) != 12 {
		t.Fatal("one worker failure discarded the snapshot")
	}
	if sections[0].Count == 0 || sections[1].Count == 0 {
		t.Fatal("successful native identity/OS sections lost")
	}
	for _, section := range sections {
		if section.Name == "updates" && section.Reason != "WORKER_FAILED" {
			t.Fatal("worker failure not represented explicitly")
		}
		if section.Name == "protection" && section.Status != "partial" {
			t.Fatal("later section was not collected")
		}
	}
}

func TestWorkerIsolationLimitsAndReaping(t *testing.T) {
	original := workerCommand
	defer func() { workerCommand = original }()
	for _, item := range []struct{ mode, status, reason string }{
		{"valid", "partial", "QFE_SUBSET"}, {"malformed", "unavailable", "INVALID_WORKER_RESPONSE"},
		{"wrong-section", "unavailable", "INVALID_WORKER_RESPONSE"}, {"oversized", "unavailable", "LIMIT_REACHED"},
		{"crash", "unavailable", "WORKER_FAILED"}, {"wait", "unavailable", "TIMEOUT"},
	} {
		t.Run(item.mode, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "ready")
			var process *exec.Cmd
			workerCommand = func(ctx context.Context, _ string) (*exec.Cmd, error) {
				path, err := os.Executable()
				if err != nil {
					return nil, err
				}
				process = exec.CommandContext(ctx, path, "-test.run=^TestWorkerHelperProcess$")
				process.Env = append(os.Environ(), "SURVEYSCAN_TEST_WORKER_MODE="+item.mode, "SURVEYSCAN_TEST_WORKER_MARKER="+marker)
				return process, nil
			}
			section := workerSection(context.Background(), "updates", 2*time.Second)
			if section.Status != item.status || section.Reason != item.reason {
				t.Fatalf("unexpected safe worker result: %s/%s", section.Status, section.Reason)
			}
			encoded, _ := json.Marshal(section)
			if strings.Contains(string(encoded), "canary") || strings.Contains(string(encoded), "password") {
				t.Fatal("worker text escaped into result")
			}
			if process == nil || process.ProcessState == nil {
				t.Fatal("worker was not reaped")
			}
			if item.mode == "wait" {
				if _, err := os.Stat(marker); err != nil {
					t.Fatal("timeout probe did not reach the intentionally blocked child")
				}
			}
		})
	}
	if result := workerSection(context.Background(), "shell", time.Second); result.Status != "unsupported" {
		t.Fatal("arbitrary worker operation accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := workerSection(ctx, "updates", time.Second); result.Reason != "CANCELLED" {
		t.Fatal("cancelled caller did not terminate worker execution")
	}
}

func TestNativeUpdatesAndProtectionWorkers(t *testing.T) {
	if os.Getenv("SURVEYSCAN_C15_TEST_AGENT") == "" {
		t.Skip("requires built Windows agent executable, configured in Windows CI")
	}
	for _, name := range []string{"updates", "protection"} {
		section := workerSection(context.Background(), name, 30*time.Second)
		if section.Name != name || section.Count != len(section.Records) || section.Complete {
			t.Fatal("native worker section semantics invalid")
		}
		if section.Reason == "WORKER_FAILED" || section.Reason == "INVALID_WORKER_RESPONSE" || section.Reason == "TIMEOUT" {
			t.Fatalf("native worker failed: %s/%s", name, section.Reason)
		}
		if name == "updates" && section.Status != "partial" {
			t.Fatalf("QFE provider unavailable on supported CI stand: %s", section.Reason)
		}
		if name == "protection" {
			firewalls := 0
			for _, row := range section.Records {
				if row["kind"] == "firewall" {
					if _, ok := row["enabled"].(bool); !ok {
						t.Fatal("firewall policy has no native boolean")
					}
					firewalls++
				}
			}
			if firewalls != 3 {
				t.Fatal("three native firewall profile values missing")
			}
		}
		t.Logf("native %s worker: status=%s reason=%s records=%d (no facts/credentials logged)", name, section.Status, section.Reason, section.Count)
	}
}

func TestProviderFailureClassificationsAreSafe(t *testing.T) {
	for _, item := range []struct {
		code           uintptr
		status, reason string
	}{{0x8004100e, "unsupported", "PROVIDER_UNAVAILABLE"}, {0x80070005, "unavailable", "ACCESS_DENIED"}, {0x80004005, "unavailable", "API_DATA_UNAVAILABLE"}} {
		err := ole.NewErrorWithDescription(item.code, "canary-secret-namespace-or-user")
		status, reason := providerFailure(err)
		if status != item.status || reason != item.reason || strings.Contains(reason, "canary") {
			t.Fatal("unsafe or inaccurate provider error")
		}
	}
}
