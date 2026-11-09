package agent

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/machineid"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/retry"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// client12 — всё, что нужно циклу от клиента. Узкий интерфейс позволяет проверить логику
// цикла без сети; боевая реализация — windowsClient12 над *Client.
type client12 interface {
	Heartbeat(ctx context.Context) error
	PollProfile(ctx context.Context) (bool, error)
	renewalDue(now time.Time) bool
	Renew(ctx context.Context) error
	inventoryPreflight(ctx context.Context) error
	negotiate(ctx context.Context, own wire.InventoryOffer12) (InventoryNegotiation12, error)
	sync(ctx context.Context, n InventoryNegotiation12) (InventoryProfileSelection12, error)
	cached(own wire.InventoryOffer12) (InventoryProfileSelection12, error)
	queue(ctx context.Context, t *wire.InventoryTransport12, s Snapshot, at time.Time) error
	flush(ctx context.Context) (bool, error)
	intervals() (inventory, heartbeat, jitter int)
}

type windowsClient12 struct {
	*Client
	decoder *wire.InventoryDecoder
}

func newWindowsClient12(c *Client) (*windowsClient12, error) {
	d, e := wire.NewInventoryDecoder(c.wire, true)
	if e != nil {
		return nil, e
	}
	return &windowsClient12{Client: c, decoder: d}, nil
}
func (w *windowsClient12) negotiate(ctx context.Context, own wire.InventoryOffer12) (InventoryNegotiation12, error) {
	return w.NegotiateInventory12(ctx, own)
}
func (w *windowsClient12) sync(ctx context.Context, n InventoryNegotiation12) (InventoryProfileSelection12, error) {
	return w.SyncInventoryProfile12(ctx, n)
}
func (w *windowsClient12) cached(own wire.InventoryOffer12) (InventoryProfileSelection12, error) {
	return w.CachedInventoryProfile12(own)
}
func (w *windowsClient12) queue(ctx context.Context, t *wire.InventoryTransport12, s Snapshot, at time.Time) error {
	return w.queueSections12(ctx, t, s.Candidates, s.Sections, at)
}
func (w *windowsClient12) flush(ctx context.Context) (bool, error) {
	return w.flushProgress12(ctx, w.decoder)
}
func (w *windowsClient12) intervals() (int, int, int) {
	return w.cfg.InventorySeconds, w.cfg.HeartbeatSeconds, w.cfg.Jitter
}

// isNetworkFailure отличает недоступность сети от отказа по протоколу. Только первая
// допускает работу по последнему принятому профилю; явный отказ (нет 1.2, подпись, область)
// останавливает новые сборы, пока свежее согласование не пройдёт.
func isNetworkFailure(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded)
}

// candidatesFromSections строит кандидаты идентичности из секции identity и MachineGuid.
// Это только подсказки сопоставления: актив определяет центр, а не агент.
func candidatesFromSections(sections []contracts.Section) []contracts.Candidate {
	out := []contracts.Candidate{}
	for _, s := range sections {
		if s.Name != "identity" || len(s.Records) == 0 {
			continue
		}
		if host, ok := s.Records[0]["hostname"].(string); ok && host != "" && len(host) <= 512 {
			out = append(out, contracts.Candidate{Kind: "hostname", Namespace: "hostname.raw", Value: host})
		}
	}
	if id, e := machineid.Local(); e == nil {
		out = append(out, contracts.Candidate{Kind: "machine_uuid", Namespace: machineNamespace12(), Value: id})
	}
	return out
}

// loop12Timing — периоды цикла; в бою defaultLoop12Timing, в тестах короткие.
type loop12Timing struct {
	Tick, ProfileOK, ProfileRetry, WaitingProfile time.Duration
}

var defaultLoop12Timing = loop12Timing{Tick: time.Second, ProfileOK: time.Minute, ProfileRetry: 20 * time.Second, WaitingProfile: 20 * time.Second}

// runLoop12 — цикл Windows-агента: те же heartbeat/продление/профиль, что у Linux, но сбор
// разрешён только при проверенном профиле 1.2, а наблюдения идут как подписанные batch 1.2.
// Один сбор за раз вне актора; актор один присваивает последовательность и пишет очередь.
func runLoop12(ctx context.Context, cl client12, report func(string), collect func(context.Context) (Snapshot, error), own wire.InventoryOffer12, timing loop12Timing) error {
	var collection *collectionTask
	defer func() {
		if collection != nil {
			collection.cancel()
		}
	}()
	var transport *wire.InventoryTransport12
	collectionLimit := 30 * time.Second
	adopt := func(s InventoryProfileSelection12, how string) bool {
		t, e := wire.NewInventoryTransport12(s.Limits)
		if e != nil {
			transport = nil
			report("inventory_profile_unusable")
			return false
		}
		transport = t
		if secs := s.Profile.Config.CollectionSeconds; secs > 0 {
			collectionLimit = time.Duration(secs) * time.Second
		}
		report(how)
		return true
	}
	ensure := func() bool {
		task, cancel := context.WithTimeout(ctx, 8*time.Second)
		negotiated, e := cl.negotiate(task, own)
		var selected InventoryProfileSelection12
		if e == nil {
			selected, e = cl.sync(task, negotiated)
		}
		cancel()
		if e == nil {
			return adopt(selected, "inventory_profile_synced")
		}
		if !isNetworkFailure(e) {
			transport = nil
			report("inventory_profile_rejected")
			return false
		}
		if transport != nil {
			report("inventory_profile_offline_using_last")
			return true
		}
		if s, ce := cl.cached(own); ce == nil {
			return adopt(s, "inventory_profile_cached")
		}
		report("inventory_profile_unavailable")
		return false
	}
	if timing.Tick <= 0 {
		timing = defaultLoop12Timing
	}
	ticker := time.NewTicker(timing.Tick)
	defer ticker.Stop()
	inventoryAt, heartbeatAt, renewalAt, profileAt, inventoryProfileAt := time.Time{}, time.Time{}, time.Time{}, time.Time{}, time.Time{}
	var delivery retry.Backoff
	for {
		if ctx.Err() != nil {
			return nil
		}
		inv, hb, jit := cl.intervals()
		if collection != nil {
			select {
			case result := <-collection.done:
				collection.cancel()
				collection = nil
				if result.err != nil {
					report("inventory_failed")
				} else if transport == nil {
					report("inventory_failed")
				} else if err := cl.queue(ctx, transport, result.snapshot, result.at); err != nil {
					report("inventory_failed")
				} else {
					report("inventory_queued")
				}
				inventoryAt = time.Now().Add(jitter(inv, jit))
			default:
				if collection.ctx.Err() != nil && !collection.reported {
					report("inventory_collection_deadline")
					collection.reported = true
				}
			}
		}
		now := time.Now()
		if !now.Before(profileAt) {
			task, cancel := context.WithTimeout(ctx, 3*time.Second)
			changed, err := cl.PollProfile(task)
			cancel()
			if err != nil {
				report("profile_unavailable_cached_or_local")
			} else if changed {
				report("profile_applied")
			}
			profileAt = time.Now().Add(20 * time.Second)
		}
		if !now.Before(inventoryProfileAt) {
			if ensure() {
				inventoryProfileAt = time.Now().Add(timing.ProfileOK)
			} else {
				inventoryProfileAt = time.Now().Add(timing.ProfileRetry)
			}
		}
		if !now.Before(renewalAt) && cl.renewalDue(now) {
			if err := cl.Renew(ctx); err != nil {
				report("renewal_pending")
			} else {
				report("renewal_checked")
			}
			renewalAt = time.Now().Add(time.Minute)
		}
		if !now.Before(heartbeatAt) {
			if err := cl.Heartbeat(ctx); err != nil {
				report("heartbeat_failed")
			} else {
				report("heartbeat_accepted")
			}
			heartbeatAt = time.Now().Add(jitter(hb, jit))
		}
		if collection == nil && !now.Before(inventoryAt) {
			if transport == nil {
				report("inventory_waiting_profile")
				inventoryAt = time.Now().Add(timing.WaitingProfile)
			} else if err := cl.inventoryPreflight(ctx); err != nil {
				report("inventory_failed")
				inventoryAt = time.Now().Add(jitter(inv, jit))
			} else {
				collection = startCollection(ctx, collect, collectionLimit)
			}
		}
		if delivery.Ready(time.Now()) {
			if progress, err := cl.flush(ctx); err != nil {
				if progress {
					delivery.Reset()
				} else {
					delivery.Failed(time.Now())
				}
				report("delivery_pending")
			} else {
				delivery.Reset()
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
