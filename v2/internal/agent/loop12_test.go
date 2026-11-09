package agent

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Error = timeoutError{}

type fake12 struct {
	mu                          sync.Mutex
	negotiateErr, cachedErr     error
	events                      []string
	heartbeats, queued, flushes atomic.Int32
	negotiations                atomic.Int32
}

func (f *fake12) Heartbeat(context.Context) error           { f.heartbeats.Add(1); return nil }
func (f *fake12) PollProfile(context.Context) (bool, error) { return false, nil }
func (f *fake12) renewalDue(time.Time) bool                 { return false }
func (f *fake12) Renew(context.Context) error               { return nil }
func (f *fake12) inventoryPreflight(context.Context) error  { return nil }
func (f *fake12) intervals() (int, int, int)                { return 1, 1, 0 }
func (f *fake12) flush(context.Context) (bool, error)       { f.flushes.Add(1); return false, nil }
func (f *fake12) selection() InventoryProfileSelection12 {
	var s InventoryProfileSelection12
	s.Limits = wire.InventoryMaximum12()
	s.Profile.Config.CollectionSeconds = 420
	return s
}
func (f *fake12) negotiate(context.Context, wire.InventoryOffer12) (InventoryNegotiation12, error) {
	f.negotiations.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return InventoryNegotiation12{}, f.negotiateErr
}
func (f *fake12) sync(context.Context, InventoryNegotiation12) (InventoryProfileSelection12, error) {
	return f.selection(), nil
}
func (f *fake12) cached(wire.InventoryOffer12) (InventoryProfileSelection12, error) {
	if f.cachedErr != nil {
		return InventoryProfileSelection12{}, f.cachedErr
	}
	return f.selection(), nil
}
func (f *fake12) queue(context.Context, *wire.InventoryTransport12, Snapshot, time.Time) error {
	f.queued.Add(1)
	return nil
}
func (f *fake12) set(negotiate error) { f.mu.Lock(); f.negotiateErr = negotiate; f.mu.Unlock() }

func runFor(t *testing.T, f *fake12, d time.Duration, collects *atomic.Int32, mid func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	collect := func(context.Context) (Snapshot, error) {
		collects.Add(1)
		return Snapshot{Candidates: []contracts.Candidate{}, Sections: []contracts.Section{}}, nil
	}
	if mid != nil {
		go func() { time.Sleep(d / 2); mid() }()
	}
	if err := runLoop12(ctx, f, func(string) {}, collect, wire.InventoryMaximum12(), loop12Timing{Tick: 10 * time.Millisecond, ProfileOK: 200 * time.Millisecond, ProfileRetry: 200 * time.Millisecond, WaitingProfile: 100 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
}

func TestLoop12NeverCollectsWithoutAnAcceptedProfileButKeepsHeartbeatAndDelivery(t *testing.T) {
	f := &fake12{negotiateErr: errors.New("collector offers no inventory 1.2")}
	var collects atomic.Int32
	runFor(t, f, 1500*time.Millisecond, &collects, nil)
	if collects.Load() != 0 || f.queued.Load() != 0 {
		t.Fatal("collection started without a verified profile", collects.Load())
	}
	if f.heartbeats.Load() == 0 || f.flushes.Load() == 0 {
		t.Fatal("heartbeat and delivery must continue", f.heartbeats.Load(), f.flushes.Load())
	}
}

func TestLoop12NetworkOutageUsesTheCachedProfileOnce(t *testing.T) {
	f := &fake12{negotiateErr: timeoutError{}}
	var collects atomic.Int32
	runFor(t, f, 2500*time.Millisecond, &collects, nil)
	if collects.Load() == 0 || f.queued.Load() == 0 {
		t.Fatal("offline start must run on the last durable profile", collects.Load(), f.queued.Load())
	}
	empty := &fake12{negotiateErr: timeoutError{}, cachedErr: errNoCachedProfile12}
	var none atomic.Int32
	runFor(t, empty, 1500*time.Millisecond, &none, nil)
	if none.Load() != 0 {
		t.Fatal("first-ever start offline must not collect: no accepted profile exists")
	}
}

func TestLoop12ProtocolRejectionStopsNewCollectionsAfterAnAcceptedProfile(t *testing.T) {
	f := &fake12{}
	var collects atomic.Int32
	var atRejection, settled atomic.Int32
	runFor(t, f, 5*time.Second, &collects, func() {
		atRejection.Store(collects.Load())
		f.set(errors.New("inventory selection changed"))
		// Достаточно двух периодов синхронизации и одного окна ожидания, чтобы отказ вступил в силу.
		time.Sleep(1500 * time.Millisecond)
		settled.Store(collects.Load())
	})
	if atRejection.Load() == 0 {
		t.Fatal("no collection happened under the accepted profile")
	}
	if collects.Load() != settled.Load() {
		t.Fatal("collections continued after an explicit protocol refusal", settled.Load(), collects.Load())
	}
}

func TestIsNetworkFailureDistinguishesOutageFromRefusal(t *testing.T) {
	if !isNetworkFailure(timeoutError{}) || !isNetworkFailure(context.DeadlineExceeded) {
		t.Fatal("outage must be a network failure")
	}
	if isNetworkFailure(errors.New("inventory selection changed")) || isNetworkFailure(errProfileCache12) {
		t.Fatal("protocol refusal or a corrupt cache must not be treated as an outage")
	}
}

func TestCandidatesFromSectionsUsesIdentityHostname(t *testing.T) {
	got := candidatesFromSections([]contracts.Section{{Name: "identity", Records: []map[string]any{{"hostname": "host-01"}}}, {Name: "os"}})
	found := false
	for _, c := range got {
		if c.Kind == "hostname" && c.Value == "host-01" && c.Namespace != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("hostname candidate missing", got)
	}
	if len(candidatesFromSections(nil)) > 1 {
		t.Fatal("no identity section must not invent hostnames")
	}
}

func TestMachineUUIDCandidateIsCanonicalUUID(t *testing.T) {
	if got := canonicalMachineUUID("15b9bc6bf4234db283a367df09c5db84"); got != "15b9bc6b-f423-4db2-83a3-67df09c5db84" {
		t.Fatal("not canonical:", got)
	}
	if got := canonicalMachineUUID("already-not-32"); got != "already-not-32" {
		t.Fatal("must leave other forms alone:", got)
	}
	// Кандидаты реального сбора проходят ту же проверку формата, что центр применяет к machine_uuid.
	for _, c := range candidatesFromSections(nil) {
		if c.Kind == "machine_uuid" && !identifier.Valid(c.Value) {
			t.Fatalf("machine_uuid candidate rejected by the centre format check: %q", c.Value)
		}
	}
}
