package app

import (
	"encoding/json"
	"fmt"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/imports"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/machinecred"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
	"net/http"
	"os"
	"time"
)

type diagnosticAlert struct {
	Code     string  `json:"code"`
	Severity string  `json:"severity"`
	Source   *string `json:"source_id"`
}
type diagnosticSnapshot struct {
	Version   string                     `json:"schema_version"`
	At        time.Time                  `json:"generated_at"`
	Tenant    string                     `json:"tenant_id"`
	Sources   []sources.DiagnosticSource `json:"sources"`
	Truncated bool                       `json:"sources_truncated"`
	Imports   imports.Diagnostics        `json:"imports"`
	Outbox    messaging.Diagnostics      `json:"outbox"`
	BackupAge *float64                   `json:"backup_age_seconds"`
	Alerts    []diagnosticAlert          `json:"alerts"`
}

func backupAge() *float64 {
	path := os.Getenv("SURVEYSCAN_V2_BACKUP_MARKER")
	if path == "" {
		return nil
	}
	var marker struct {
		Completed time.Time `json:"completed_at"`
	}
	ok, e := machinecred.ReadOptional(path, &marker)
	if e != nil || !ok || marker.Completed.IsZero() || marker.Completed.After(time.Now()) {
		return nil
	}
	age := time.Since(marker.Completed).Seconds()
	return &age
}
func diagnosticAlerts(d diagnosticSnapshot) []diagnosticAlert {
	out := []diagnosticAlert{}
	add := func(code, severity string, source *string) {
		out = append(out, diagnosticAlert{code, severity, source})
	}
	if d.BackupAge == nil {
		add("BACKUP_AGE_UNKNOWN", "warning", nil)
	} else if *d.BackupAge > 86400 {
		add("BACKUP_TOO_OLD", "warning", nil)
	}
	if d.Imports.DeadLetter > 0 {
		add("IMPORT_DEAD_LETTER", "critical", nil)
	}
	if d.Outbox.DeadLetter > 0 {
		add("OUTBOX_DEAD_LETTER", "critical", nil)
	}
	if d.Imports.OldestAge != nil && *d.Imports.OldestAge > 300 {
		add("IMPORT_BACKLOG", "warning", nil)
	}
	if d.Outbox.OldestAge != nil && *d.Outbox.OldestAge > 300 {
		add("OUTBOX_LAG", "warning", nil)
	}
	if d.Truncated {
		add("SOURCE_DIAGNOSTICS_TRUNCATED", "warning", nil)
	}
	for _, s := range d.Sources {
		if s.State != "active" || s.Kind == "portable" {
			continue
		}
		source := s.Source
		if s.HeartbeatAge == nil {
			add("SOURCE_CONTACT_UNKNOWN", "warning", &source)
		} else if *s.HeartbeatAge > float64(s.HeartbeatSeconds*3) {
			add("SOURCE_CONTACT_STALE", "warning", &source)
		}
		if s.Desired != "1" && (s.Applied == nil || *s.Applied != s.Desired) {
			add("PROFILE_NOT_APPLIED", "warning", &source)
		}
		if s.Reported == nil || s.ReportedAge == nil {
			add("RUNTIME_DIAGNOSTICS_UNKNOWN", "warning", &source)
			continue
		}
		if *s.ReportedAge > 90 {
			add("RUNTIME_DIAGNOSTICS_STALE", "warning", &source)
		}
		if s.Reported.DiskAvailable != nil && *s.Reported.DiskAvailable < 128*1024*1024 {
			add("SPOOL_DISK_LOW", "warning", &source)
		}
		if s.Reported.OldestPending != nil && d.At.Sub(*s.Reported.OldestPending) > 5*time.Minute {
			add("SPOOL_BACKLOG", "warning", &source)
		}
		if s.Reported.CertificateExpires.Before(d.At) {
			add("CERTIFICATE_EXPIRED", "critical", &source)
		} else if s.Reported.CertificateExpires.Before(d.At.Add(time.Hour)) {
			add("CERTIFICATE_EXPIRING", "warning", &source)
		}
	}
	return out
}
func (m *MachineAPI) diagnostics(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query()) > 0 {
		access.APIError(w, 400, "INVALID_QUERY")
		return
	}
	if m.Uploads == nil {
		access.APIError(w, 503, "CAPABILITY_NOT_ENABLED")
		return
	}
	actor, _ := access.Identity(r.Context())
	d := diagnosticSnapshot{Version: "C12/1.1", At: time.Now().UTC(), Tenant: actor.TenantID, BackupAge: backupAge()}
	var e error
	d.Sources, e = m.Sources.Diagnostics(r.Context(), actor)
	if e != nil {
		m.fail(w, e)
		return
	}
	if len(d.Sources) > 1000 {
		d.Sources = d.Sources[:1000]
		d.Truncated = true
	}
	d.Imports, e = m.Uploads.Diagnostics(r.Context(), actor.TenantID)
	if e != nil {
		m.fail(w, e)
		return
	}
	d.Outbox, e = messaging.Statistics(r.Context(), m.Sources.Pool, actor.TenantID)
	if e != nil {
		m.fail(w, e)
		return
	}
	d.Alerts = diagnosticAlerts(d)
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/api/v1/metrics" {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "surveyscan_import_pending_deliveries %d\nsurveyscan_import_pending_bytes %d\nsurveyscan_import_dead_letter %d\nsurveyscan_outbox_pending_events %d\nsurveyscan_outbox_dead_letter %d\n", d.Imports.Pending, d.Imports.PendingBytes, d.Imports.DeadLetter, d.Outbox.Pending, d.Outbox.DeadLetter)
		if d.Imports.OldestAge != nil {
			fmt.Fprintf(w, "surveyscan_import_oldest_pending_age_seconds %g\n", *d.Imports.OldestAge)
		}
		if d.Outbox.OldestAge != nil {
			fmt.Fprintf(w, "surveyscan_outbox_oldest_pending_age_seconds %g\n", *d.Outbox.OldestAge)
		}
		if d.BackupAge != nil {
			fmt.Fprintf(w, "surveyscan_backup_age_known 1\nsurveyscan_backup_age_seconds %g\n", *d.BackupAge)
		} else {
			fmt.Fprintln(w, "surveyscan_backup_age_known 0")
		}
		for _, s := range d.Sources {
			if s.HeartbeatAge != nil {
				fmt.Fprintf(w, "surveyscan_source_heartbeat_age_seconds{source_id=%q} %g\n", s.Source, *s.HeartbeatAge)
			}
			if s.InventoryAge != nil {
				fmt.Fprintf(w, "surveyscan_source_inventory_age_seconds{source_id=%q} %g\n", s.Source, *s.InventoryAge)
			}
			if s.Reported != nil {
				fmt.Fprintf(w, "surveyscan_source_spool_pending_files{source_id=%q} %d\nsurveyscan_source_spool_pending_bytes{source_id=%q} %d\nsurveyscan_source_certificate_seconds_remaining{source_id=%q} %g\n", s.Source, s.Reported.PendingFiles, s.Source, s.Reported.PendingBytes, s.Source, s.Reported.CertificateExpires.Sub(d.At).Seconds())
				if s.Reported.DiskAvailable != nil {
					fmt.Fprintf(w, "surveyscan_source_disk_available_bytes{source_id=%q} %d\n", s.Source, *s.Reported.DiskAvailable)
				}
			}
		}
		for _, alert := range d.Alerts {
			source := ""
			if alert.Source != nil {
				source = *alert.Source
			}
			fmt.Fprintf(w, "surveyscan_alert{code=%q,severity=%q,source_id=%q} 1\n", alert.Code, alert.Severity, source)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(d)
}
