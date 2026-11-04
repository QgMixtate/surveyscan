package app

import (
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"testing"
	"time"
)

func TestDiagnosticsAlertsPreserveUnknownAndSourceState(t *testing.T) {
	now := time.Now()
	source := "source"
	low := int64(1)
	stale := float64(500)
	old := now.Add(-10 * time.Minute)
	d := diagnosticSnapshot{At: now, Sources: []sources.DiagnosticSource{{Source: source, State: "active", Desired: "2", HeartbeatSeconds: 60, HeartbeatAge: &stale, ReportedAge: &stale, Reported: &contracts.RuntimeDiagnostics{OldestPending: &old, DiskAvailable: &low, CertificateExpires: now.Add(-time.Minute)}}}}
	alerts := diagnosticAlerts(d)
	seen := map[string]bool{}
	for _, a := range alerts {
		seen[a.Code] = true
	}
	for _, code := range []string{"BACKUP_AGE_UNKNOWN", "SOURCE_CONTACT_STALE", "PROFILE_NOT_APPLIED", "RUNTIME_DIAGNOSTICS_STALE", "SPOOL_DISK_LOW", "SPOOL_BACKLOG", "CERTIFICATE_EXPIRED"} {
		if !seen[code] {
			t.Fatal("missing operational alert", code)
		}
	}
	d.Sources[0].State = "revoked"
	alerts = diagnosticAlerts(d)
	if len(alerts) != 1 || alerts[0].Code != "BACKUP_AGE_UNKNOWN" {
		t.Fatal("revoked source produced active/presence alerts", alerts)
	}
}
