package sourceprofile

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/pki"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
	"os"
	"strconv"
	"time"
)

type Post func(context.Context, string, []byte) (int, []byte, error)

func Poll(ctx context.Context, v *wire.Validator, claims pki.Claims, key ed25519.PrivateKey, current *contracts.ProfilePayload, post Post, diagnostics ...contracts.RuntimeDiagnostics) ([]byte, contracts.ProfilePayload, error) {
	var applied *string
	if current != nil && current.Managed {
		applied = &current.Config.Revision
	}
	random := make([]byte, 32)
	if _, e := rand.Read(random); e != nil {
		return nil, contracts.ProfilePayload{}, e
	}
	nonce := base64.RawURLEncoding.EncodeToString(random)
	req := contracts.ProfileRequestPayload{Version: contracts.Version{Major: 1, Minor: 1}, Tenant: claims.Tenant, Origin: contracts.Origin{SourceID: claims.Source, SourceKind: claims.Kind, GenerationID: claims.Generation}, Nonce: nonce, Sent: time.Now().UTC(), Applied: applied}
	if len(diagnostics) > 0 {
		req.Diagnostics = &diagnostics[0]
	}
	frame, e := SignRequest(req, claims.KeyID, key)
	if e != nil {
		return nil, contracts.ProfilePayload{}, e
	}
	raw, _ := json.Marshal(frame)
	code, raw, e := post(ctx, "/api/v1/machine/profile", raw)
	if e != nil || code != 200 {
		return nil, contracts.ProfilePayload{}, errors.New("profile center unavailable; last valid profile retained")
	}
	next, e := VerifyResponse(v, raw, claims, nonce, true)
	if e != nil {
		return nil, next, e
	}
	if current != nil {
		oldRevision, _ := strconv.ParseUint(current.Config.Revision, 10, 64)
		nextRevision, _ := strconv.ParseUint(next.Config.Revision, 10, 64)
		if nextRevision < oldRevision {
			return nil, next, errors.New("profile rollback refused")
		}
		oldJSON, _ := json.Marshal(current.Config)
		nextJSON, _ := json.Marshal(next.Config)
		if nextRevision == oldRevision && string(oldJSON) != string(nextJSON) {
			return nil, next, errors.New("profile revision conflict")
		}
	}
	return raw, next, nil
}
func Cached(path string, v *wire.Validator, claims pki.Claims) (contracts.ProfilePayload, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() {
		return contracts.ProfilePayload{}, errors.New("cached profile must be private regular file")
	}
	raw, e := privatefile.Read(path, 65536)
	if e != nil {
		return contracts.ProfilePayload{}, e
	}
	var frame contracts.ProfileFrame
	var payload contracts.ProfilePayload
	if json.Unmarshal(raw, &frame) != nil || json.Unmarshal(frame.Payload, &payload) != nil {
		return payload, errors.New("invalid cached profile")
	}
	return VerifyResponse(v, raw, claims, payload.Nonce, false)
}
