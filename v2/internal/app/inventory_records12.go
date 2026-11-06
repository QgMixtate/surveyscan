package app

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/access"
	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"github.com/jackc/pgx/v5"
)

var recordField12 = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var recordProjectionChanged = errors.New("record projection changed between pages")

func decodeRecordCursor12(token, tenant, asset, section, revision string) (string, string, error) {
	if token == "" {
		return "", "", nil
	}
	if len(token) > 2048 {
		return "", "", domain.Invalid
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(token)
	var parts []string
	if err != nil || json.Unmarshal(b, &parts) != nil || len(parts) != 6 || parts[0] != tenant || parts[1] != asset || parts[2] != section {
		return "", "", domain.Invalid
	}
	key, err := hex.DecodeString(parts[4])
	if err != nil || len(key) != 32 || hex.EncodeToString(key) != parts[4] || !recordField12.MatchString(parts[5]) {
		return "", "", domain.Invalid
	}
	if n, e := strconv.ParseUint(parts[3], 10, 64); e != nil || strconv.FormatUint(n, 10) != parts[3] {
		return "", "", domain.Invalid
	}
	if parts[3] != revision {
		return "", "", recordProjectionChanged
	}
	return parts[4], parts[5], nil
}

// InventoryRecordFacts reads observation1.2 projection only; it does not enable
// upload of 1.2 observations or change C09 inventory/detail responses.
func (r *Registry) InventoryRecordFacts(ctx context.Context, id accessport.Identity, uid, section, cursor string, limit int) (contracts.RecordFactPage12, error) {
	out := contracts.RecordFactPage12{Version: contracts.Version{Major: 1, Minor: 2}, Tenant: id.TenantID, Asset: uid, Section: section, Items: []contracts.RecordFact12{}}
	if !identifier.Valid(uid) {
		return out, domain.NotFound
	}
	if !contracts.InventorySection12(section) || limit < 1 || limit > wire.RecordPage12MaxItems {
		return out, domain.Invalid
	}
	tx, err := r.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	if _, err = r.Auth.Authorize(ctx, tx, id.CredentialID, id.TenantID, "assets:read"); err != nil {
		return out, err
	}
	if _, err = r.Assets.Get(ctx, tx, id.TenantID, uid); err != nil {
		return out, err
	}
	out.Revision, out.State, err = r.Inventory.RecordState12(ctx, tx, id.TenantID, uid, section)
	if err != nil {
		return out, err
	}
	afterRecord, afterField, err := decodeRecordCursor12(cursor, id.TenantID, uid, section, out.Revision)
	if err != nil {
		return out, err
	}
	var more bool
	out.Items, more, err = r.Inventory.RecordFacts12(ctx, tx, id.TenantID, uid, section, afterRecord, afterField, limit)
	if err != nil {
		return out, err
	}
	if more {
		last := out.Items[len(out.Items)-1]
		b, _ := json.Marshal([]string{id.TenantID, uid, section, out.Revision, last.Record, last.Field})
		token := base64.RawURLEncoding.EncodeToString(b)
		out.NextCursor = &token
	}
	b, err := wire.RecordJSON(out)
	if err != nil {
		return out, err
	}
	if err = wire.ValidateRecordPage12(b); err != nil {
		return out, errors.New("record projection response unavailable")
	}
	return out, tx.Commit(ctx)
}

func (r *Registry) inventoryRecordsHandler12() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		for key, values := range q {
			if (key != "limit" && key != "cursor") || len(values) != 1 || values[0] == "" {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
		}
		limit := 50
		if value := q.Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
			if err != nil || limit < 1 || limit > wire.RecordPage12MaxItems {
				access.APIError(w, 400, "INVALID_QUERY")
				return
			}
		}
		ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
		defer cancel()
		id, _ := access.Identity(ctx)
		out, err := r.InventoryRecordFacts(ctx, id, req.PathValue("asset_uid"), req.PathValue("section"), q.Get("cursor"), limit)
		if errors.Is(err, domain.Invalid) {
			access.APIError(w, 400, "INVALID_QUERY")
			return
		}
		if errors.Is(err, recordProjectionChanged) {
			access.APIError(w, 409, "PROJECTION_CHANGED")
			return
		}
		if err != nil {
			registryError(w, err)
			return
		}
		b, err := wire.RecordJSON(out)
		if err != nil {
			registryError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(b)
	})
}
