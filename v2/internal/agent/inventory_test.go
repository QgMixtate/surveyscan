package agent

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

func TestLinuxReadOnlyInventoryLiveSchema(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux live adapter")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snapshot, err := Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Sections) != 3 || snapshot.Sections[0].Status != "ok" || snapshot.Sections[0].Records[0]["hostname"] != host || snapshot.Sections[1].Status != "ok" {
		t.Fatal("live host identification incomplete")
	}
	o := contracts.Observation{Version: contracts.Version{Major: 1}, ID: identifier.New(), TenantID: identifier.New(), Origin: contracts.Origin{SourceID: identifier.New(), GenerationID: identifier.New(), SourceKind: "agent"}, Scope: contracts.Scope{SiteID: identifier.New(), ScopeID: identifier.New()}, Record: contracts.SourceRecord{Namespace: "host", LocalID: "live-host"}, Sequence: "1", CollectedAt: time.Now().UTC(), Clock: "trusted", Candidates: snapshot.Candidates, Sections: snapshot.Sections}
	raw, _ := json.Marshal(o)
	v, err := wire.New()
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Validate("Observation", raw); err != nil {
		t.Fatal("live inventory violates C03", err)
	}
	// Никакие hostname/IP/MAC/machine-id не попадают в test report.
	t.Logf("live Linux/%s: three C03 sections; identity/os=%s/%s; network rows=%d", runtime.GOARCH, snapshot.Sections[0].Status, snapshot.Sections[1].Status, snapshot.Sections[2].Count)
}
func TestOSReleaseIsDataAndCancellation(t *testing.T) {
	name, version, e := parseOSRelease("NAME=\"$(touch /tmp/ssv2-must-not-run)\"\nVERSION_ID='1.2'\n")
	if e != nil || name != "$(touch /tmp/ssv2-must-not-run)" || version != "1.2" {
		t.Fatal("OS release interpreted as commands")
	}
	if _, _, e = parseOSRelease("NAME=Linux\n"); e == nil {
		t.Fatal("missing version reported successful")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = Collect(ctx); e != context.Canceled {
		t.Fatal("cancellation ignored")
	}
}
