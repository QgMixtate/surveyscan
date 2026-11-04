package agent

import (
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOptionalRotationStateFailsClosedAndSchedulesPending(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tls-identity.json")
	var bundle tlsIdentity
	if present, e := loadOptionalJSON(path, &bundle); present || e != nil {
		t.Fatal("absent upgrade bundle failed", e)
	}
	if e := os.WriteFile(path, []byte(`{"result":{}}`), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := loadOptionalJSON(path, &bundle); e == nil {
		t.Fatal("public credentials fell back to initial identity")
	}
	if e := os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(`{"unknown":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := loadOptionalJSON(path, &bundle); e == nil {
		t.Fatal("corrupt bundle fell back")
	}
	now := time.Now()
	bundle = tlsIdentity{Result: contracts.EnrollmentResult{Expires: now.Add(2 * time.Hour)}}
	if e := saveJSON(path, bundle); e != nil {
		t.Fatal(e)
	}
	c := &Client{cfg: Config{State: dir}}
	if c.renewalDue(now) || !c.renewalDue(now.Add(61*time.Minute)) {
		t.Fatal("renewal lead window incorrect")
	}
	if e := os.WriteFile(filepath.Join(dir, "renewal.pending.json"), []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	if !c.renewalDue(now) {
		t.Fatal("pending rotation did not resume")
	}
}
