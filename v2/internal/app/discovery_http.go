package app

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/sources"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/jackc/pgx/v5"
)

// C51: «Обследования сети» (ADR D13-discovery-policy). Права: подсети — администратор (sources:admin); запуск —
// оператор (jobs:write); просмотр — sources:read. Каждое изменение и запуск — в аудит.

var src51 = sources.Store{}

type route51 struct {
	permission string
	handler    http.Handler
}

// discoveryDo — транзакция с проверкой права, ответ JSON с кодом status.
func (r *Registry) discoveryDo(w http.ResponseWriter, req *http.Request, status int, permission string, fn func(context.Context, pgx.Tx, accessport.Identity) (any, error)) {
	ctx, cancel, id := cmdbContext(req)
	defer cancel()
	tx, e := r.adminTx(ctx, id, permission)
	if e != nil {
		cmdbError(w, req, e)
		return
	}
	defer tx.Rollback(ctx)
	out, e := fn(ctx, tx, id)
	if e == nil {
		e = tx.Commit(ctx)
	}
	if e != nil {
		cmdbError(w, req, e)
		return
	}
	registryJSONStatus(w, status, out)
}

func discoveryLimits() map[string]any {
	return map[string]any{"max_prefix": sources.DiscoveryMaxPrefix, "rate_per_second": sources.DiscoveryRate, "min_schedule_minutes": sources.DiscoveryMinPeriod, "tcp_ports": sources.DiscoveryPorts}
}

func (r *Registry) discoveryHandlers() map[string]route51 {
	return map[string]route51{
		"GET /api/v1/discovery/networks": {"sources:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := queryOnly(w, req); !ok {
				return
			}
			r.discoveryDo(w, req, http.StatusOK, "sources:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				items, e := src51.DiscoveryNetworks(ctx, tx, id.TenantID)
				return map[string]any{"items": items, "limits": discoveryLimits()}, e
			})
		})},
		"POST /api/v1/discovery/networks": {"sources:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body sources.DiscoveryNetworkInput
			if !readOperationBody(w, req, &body) {
				return
			}
			r.discoveryDo(w, req, http.StatusCreated, "sources:admin", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				n, e := src51.CreateDiscoveryNetwork(ctx, tx, id.TenantID, body)
				if e == nil {
					e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "discovery.network_created", "discovery_network", n.ID)
				}
				return n, e
			})
		})},
		"PATCH /api/v1/discovery/networks/{network_id}": {"sources:admin", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body sources.DiscoveryNetworkPatch
			if !readOperationBody(w, req, &body) {
				return
			}
			r.discoveryDo(w, req, http.StatusOK, "sources:admin", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				n, e := src51.PatchDiscoveryNetwork(ctx, tx, id.TenantID, req.PathValue("network_id"), body)
				if e == nil {
					e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "discovery.network_changed", "discovery_network", n.ID)
				}
				return n, e
			})
		})},
		"POST /api/v1/discovery/networks/{network_id}/runs": {"jobs:write", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var body struct{}
			if !readOperationBody(w, req, &body) {
				return
			}
			r.discoveryDo(w, req, http.StatusAccepted, "jobs:write", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				network := req.PathValue("network_id")
				if !identifier.Valid(network) {
					return nil, domain.NotFound
				}
				run, e := src51.StartDiscovery(ctx, tx, id.TenantID, network, "manual", id.UserID)
				if e == nil {
					e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "discovery.run_requested", "discovery_run", run)
				}
				return map[string]string{"run_id": run, "state": "queued"}, e
			})
		})},
		"GET /api/v1/discovery/networks/{network_id}/runs": {"sources:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := queryOnly(w, req); !ok {
				return
			}
			r.discoveryDo(w, req, http.StatusOK, "sources:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				if _, e := src51.DiscoveryNetwork(ctx, tx, id.TenantID, req.PathValue("network_id")); e != nil {
					return nil, e
				}
				items, e := src51.DiscoveryRuns(ctx, tx, id.TenantID, req.PathValue("network_id"), 20)
				return map[string]any{"items": items}, e
			})
		})},
		"GET /api/v1/discovery/networks/{network_id}/hosts": {"sources:read", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, ok := queryOnly(w, req); !ok {
				return
			}
			r.discoveryDo(w, req, http.StatusOK, "sources:read", func(ctx context.Context, tx pgx.Tx, id accessport.Identity) (any, error) {
				if _, e := src51.DiscoveryNetwork(ctx, tx, id.TenantID, req.PathValue("network_id")); e != nil {
					return nil, e
				}
				items, e := src51.DiscoveryHosts(ctx, tx, id.TenantID, req.PathValue("network_id"))
				return map[string]any{"items": items}, e
			})
		})},
	}
}

// Машинный канал C51: collector по mTLS (контракт c51-discovery).
func (m *MachineAPI) discoveryMachine(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), 20*time.Second)
	defer cancel()
	if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 || len(req.TLS.PeerCertificates) == 0 {
		access.APIError(w, 401, "AUTHENTICATION_REQUIRED")
		return
	}
	if req.URL.RawQuery != "" {
		access.APIError(w, 400, "INVALID_QUERY")
		return
	}
	if kind, _, e := mime.ParseMediaType(req.Header.Get("Content-Type")); e != nil || kind != "application/json" {
		access.APIError(w, 400, "INVALID_JSON")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, req.Body, 512<<10))
	if e != nil {
		access.APIError(w, 413, "PAYLOAD_TOO_LARGE")
		return
	}
	if m.Sources == nil || m.Sources.Pool == nil {
		access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
		return
	}
	fp := pki.Fingerprint(req.TLS.PeerCertificates[0])
	switch req.URL.Path {
	case "/api/v1/machine/discovery-jobs":
		if string(raw) != "{}" {
			access.APIError(w, 400, "INVALID_JSON")
			return
		}
		job, e := m.Sources.DiscoveryJob(ctx, fp)
		if e != nil {
			m.fail(w, e)
			return
		}
		registryJSON(w, map[string]any{"job": job})
	case "/api/v1/machine/discovery-results":
		out, e := m.Sources.SubmitDiscovery(ctx, fp, raw)
		if e != nil {
			m.fail(w, e)
			return
		}
		registryJSON(w, out)
	default:
		access.APIError(w, 404, "NOT_FOUND")
	}
}

// DiscoveryMaintain — раз в минуту ставит обследования по расписанию и закрывает зависшие (под арендой работ).
func (r *Registry) DiscoveryMaintain(ctx context.Context, log func(string)) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		task, done := context.WithTimeout(ctx, 30*time.Second)
		tx, e := r.Pool.Begin(task)
		if e == nil {
			var tenants []string
			if tenants, e = src51.DiscoveryTenants(task, tx); e == nil {
				n := 0
				for _, tenant := range tenants {
					k, e2 := src51.DiscoveryDue(task, tx, tenant)
					if e2 != nil {
						e = e2
						break
					}
					n += k
				}
				if e == nil {
					e = tx.Commit(task)
				}
				if e == nil && n > 0 {
					log(fmt.Sprintf("discovery: %d scheduled run(s) queued", n))
				}
			}
			tx.Rollback(task)
		}
		if e != nil {
			log("discovery schedule failed: " + e.Error())
		}
		done()
	}
}
