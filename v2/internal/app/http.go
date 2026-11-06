package app

import (
	"encoding/json"
	"fmt"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	"net/http"
	"strings"
)

// NewHTTP связывает реализации auth с fail-closed gates будущих доменных handlers.
func NewHTTP(auth *access.HTTP, health http.Handler, registry ...*Registry) (http.Handler, error) {
	mux := http.NewServeMux()
	auth.Register(mux)
	mux.HandleFunc("GET /api/v1/contracts/c12", func(w http.ResponseWriter, r *http.Request) {
		b, e := contracts.Files.ReadFile("c12.openapi.json")
		if e != nil {
			access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /api/v1/contracts/c15", func(w http.ResponseWriter, req *http.Request) {
		b, err := contracts.C15API12Files.ReadFile("c15.openapi.json")
		if err != nil {
			access.APIError(w, 503, "TEMPORARILY_UNAVAILABLE")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(b)
	})
	implementations := map[string]http.Handler{}
	if len(registry) > 0 && registry[0] != nil {
		implementations = registry[0].Handlers()
		if registry[0].Machine != nil {
			mux.Handle("GET /api/v1/sources/{source_id}/profile", auth.Wrap("sources:read", false, http.HandlerFunc(registry[0].Machine.humanProfile)))
			mux.Handle("PATCH /api/v1/sources/{source_id}/profile", auth.Wrap("sources:admin", true, http.HandlerFunc(registry[0].Machine.humanProfile)))
			mux.HandleFunc("POST /api/v1/machine/profile", registry[0].Machine.machineProfile)
			mux.HandleFunc("POST /api/v1/machine/inventory-capabilities", registry[0].Machine.inventoryCapabilities)
			mux.Handle("GET /api/v1/diagnostics", auth.Wrap("sources:read", false, http.HandlerFunc(registry[0].Machine.diagnostics)))
			mux.Handle("GET /api/v1/metrics", auth.Wrap("sources:read", false, http.HandlerFunc(registry[0].Machine.diagnostics)))
		}
		mux.Handle("GET /api/v1/assets/{asset_uid}/inventory", auth.Wrap("assets:read", false, registry[0].inventoryHandler()))
		mux.Handle("GET /api/v1/assets/{asset_uid}/inventory/facts/{section}", auth.Wrap("assets:read", false, registry[0].inventoryRecordsHandler12()))
		if registry[0].Machine != nil {
			for operation, handler := range registry[0].Machine.human() {
				implementations[operation] = handler
			}
		}
	}
	var api struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	b, e := contracts.Files.ReadFile("openapi.json")
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(b, &api); e != nil {
		return nil, e
	}
	policies := map[string]string{"listAssets": "assets:read", "getAsset": "assets:read", "patchAssetBusiness": "assets:write", "listSources": "sources:read", "getSource": "sources:read", "createEnrollmentGrant": "sources:admin", "resetSourceGeneration": "sources:admin", "createInventoryJob": "jobs:write", "getJob": "jobs:read", "cancelJob": "jobs:write", "revokeSource": "sources:admin"}
	for path, methods := range api.Paths {
		for method, op := range methods {
			if strings.HasPrefix(path, "/health/") || strings.HasPrefix(path, "/api/v1/auth/") {
				continue
			}
			pattern := strings.ToUpper(method) + " " + path
			if strings.HasPrefix(path, "/api/v1/machine/") {
				if len(registry) > 0 && registry[0] != nil && registry[0].Machine != nil {
					mux.Handle(pattern, registry[0].Machine.machine(op.OperationID))
				} else {
					mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { access.APIError(w, 401, "AUTHENTICATION_REQUIRED") })
				}
				continue
			}
			action, ok := policies[op.OperationID]
			if !ok {
				return nil, fmt.Errorf("missing authorization policy: %s", op.OperationID)
			}
			handler, implemented := implementations[op.OperationID]
			if !implemented {
				handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { access.APIError(w, 501, "CAPABILITY_NOT_ENABLED") })
			}
			mux.Handle(pattern, auth.Wrap(action, false, handler))
		}
	}
	mux.Handle("/health/", health)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { access.APIError(w, 404, "NOT_FOUND") })
	return mux, nil
}
