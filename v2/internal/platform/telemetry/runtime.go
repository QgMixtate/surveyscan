package telemetry

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func Snapshot(spool string, expiry time.Time) (contracts.RuntimeDiagnostics, error) {
	out := contracts.RuntimeDiagnostics{Collected: time.Now().UTC(), CertificateExpires: expiry.UTC()}
	f, e := os.Open(spool)
	if e != nil {
		return out, e
	}
	defer f.Close()
	entries, e := f.ReadDir(diskspool.MaxFiles + 1)
	if e != nil && e != io.EOF {
		return out, e
	}
	if len(entries) > diskspool.MaxFiles {
		return out, errors.New("spool diagnostic file bound exceeded")
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".pending") {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			return out, e
		}
		if !info.Mode().IsRegular() {
			return out, errors.New("spool diagnostic requires regular records")
		}
		out.PendingFiles++
		out.PendingBytes += info.Size()
		at := info.ModTime().UTC()
		if out.OldestPending == nil || at.Before(*out.OldestPending) {
			out.OldestPending = &at
		}
	}
	out.DiskAvailable = DiskAvailable(spool)
	return out, nil
}
func CertificateExpiry(raw []byte) (time.Time, error) {
	leaf, e := x509.ParseCertificate(raw)
	if e != nil {
		return time.Time{}, e
	}
	return leaf.NotAfter.UTC(), nil
}
func Write(directory string, value contracts.RuntimeDiagnostics) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	return diskspool.Atomic(filepath.Join(directory, "diagnostics.json"), raw)
}
