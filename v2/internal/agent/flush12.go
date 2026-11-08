package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// flushProgress12 — доставка для Windows-агента: те же правила, что у flushProgress, но
// пакеты и подтверждения центра проверяет InventoryDecoder (1.0 и согласованный 1.2).
// Копия, а не общий код, чтобы принятый Linux E1 не менялся. Progress означает, что
// проверенное remove-подтверждение durable потреблено, а не что HTTP принял пакет.
func (c *Client) flushProgress12(ctx context.Context, d *wire.InventoryDecoder) (bool, error) {
	progress := false
	entries, e := os.ReadDir(filepath.Join(c.cfg.State, "spool"))
	if e != nil {
		return progress, e
	}
	waiting := false
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".pending") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".pending")
		if !identifier.Valid(id) {
			return progress, errors.New("invalid agent packet path")
		}
		path := filepath.Join(c.cfg.State, "spool", entry.Name())
		raw, e := privatefile.Read(path, 1048576)
		if e != nil {
			return progress, e
		}
		var batch contracts.Batch
		if e = json.Unmarshal(raw, &batch); e != nil || batch.DeliveryID != id || batch.TenantID != c.claims.Tenant {
			return progress, errors.New("invalid agent pending packet")
		}
		if _, stat := os.Stat(filepath.Join(c.cfg.State, "spool", id+".receipt")); stat == nil {
			cached, e := privatefile.Read(filepath.Join(c.cfg.State, "spool", id+".receipt"), 1048576)
			if e != nil {
				return progress, e
			}
			_, remove, e := d.VerifyCenterResult(cached, raw, c.claims.CenterKeyID, c.claims.CenterPublic)
			if e != nil {
				return progress, errors.New("cached source receipt verification failed")
			}
			if remove {
				if e = diskspool.Remove(path); e != nil {
					return progress, e
				}
				progress = true
			}
			continue
		} else if !os.IsNotExist(stat) {
			return progress, stat
		}
		// У transport receipt нет права удалять пакет. Результат центра проверяется независимо.
		code, ack, e := request(ctx, c.http, c.cfg.CollectorURL, "POST", "/api/v1/machine/observations", raw, "")
		if e != nil {
			return progress, e
		}
		if code != 202 {
			return progress, fmt.Errorf("collector batch rejected (HTTP %d)", code)
		}
		_, remove, verify := d.VerifyCenterResult(ack, raw, c.claims.CenterKeyID, c.claims.CenterPublic)
		if verify != nil {
			code, ack, e = request(ctx, c.http, c.cfg.CollectorURL, "GET", "/api/v1/machine/deliveries/"+id, nil, "")
			if e != nil {
				return progress, e
			}
			if code != 200 {
				return progress, fmt.Errorf("collector status rejected (HTTP %d)", code)
			}
			_, remove, verify = d.VerifyCenterResult(ack, raw, c.claims.CenterKeyID, c.claims.CenterPublic)
		}
		if verify != nil {
			waiting = true
			continue
		}
		if e = diskspool.Capacity(filepath.Join(c.cfg.State, "spool"), c.cfg.Limit, int64(len(ack))); e != nil {
			return progress, e
		}
		if e = writeAtomic(filepath.Join(c.cfg.State, "spool", id+".receipt"), ack); e != nil {
			return progress, e
		}
		if remove {
			if e = diskspool.Remove(path); e != nil {
				return progress, e
			}
			progress = true
		}
	}
	if waiting {
		return progress, errors.New("center result pending; source packet retained")
	}
	return progress, nil
}
