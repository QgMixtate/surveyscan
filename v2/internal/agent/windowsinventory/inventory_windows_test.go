//go:build windows

package windowsinventory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

func TestNativeWindowsBaseline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sections, err := Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sections) != 12 || sections[0].Count != 1 || sections[1].Count != 1 {
		t.Fatal("native identity/OS baseline missing")
	}
	names := map[string]bool{}
	for i, section := range sections {
		if names[section.Name] || section.Complete || section.Count != len(section.Records) {
			t.Fatal("incorrect section status or count")
		}
		names[section.Name] = true
		if i >= 3 && (section.Status != "unsupported" || section.Count != 0 || section.Reason != "ADAPTER_NOT_IMPLEMENTED") {
			t.Fatal("unimplemented section misrepresented")
		}
	}
	if sections[0].Records[0]["hostname"] == "" || sections[1].Records[0]["build"] == "" {
		t.Fatal("native hostname/build missing")
	}
	// Synthetic origin/scope/sequence from fixtures; only section facts are native.
	b, err := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C15/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID      string         `json:"id"`
		Payload map[string]any `json:"payload"`
	}
	if err = json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	for _, fixture := range fixtures {
		if fixture.ID == "all-sections" {
			payload = fixture.Payload
		}
	}
	if payload == nil {
		t.Fatal("missing envelope fixture")
	}
	payload["sections"], payload["collected_at"] = sections, time.Now().UTC()
	b, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	v, err := wire.NewInventory12()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Payload(b); err != nil {
		t.Fatal("native baseline violates draft payload contract")
	}
	t.Log("native Windows identity/OS/network baseline checked; nine sections unsupported; synthetic envelope; no delivery/service/reboot test")
}

func TestNativeWindowsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled collection started")
	}
}
