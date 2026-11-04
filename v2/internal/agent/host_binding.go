package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type hostBinding struct {
	Version int    `json:"version"`
	Digest  string `json:"digest"`
}

func localMachineID() (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("host continuity adapter unavailable")
	}
	raw, e := os.ReadFile("/etc/machine-id")
	if e != nil || len(raw) > 128 {
		return "", errors.New("stable local machine identity unavailable")
	}
	id := strings.ToLower(strings.TrimSpace(string(raw)))
	decoded, e := hex.DecodeString(id)
	if e != nil || len(decoded) != 16 || id == strings.Repeat("0", 32) {
		return "", errors.New("stable local machine identity unavailable")
	}
	return id, nil
}
func bindingValue(source, id string, key ed25519.PrivateKey) hostBinding {
	h := hmac.New(sha256.New, key.Seed())
	_, _ = h.Write([]byte("SURVEYSCAN-HOST-BINDING-V1\n" + source + "\n" + id))
	return hostBinding{Version: 1, Digest: hex.EncodeToString(h.Sum(nil))}
}
func verifyBindingValue(binding hostBinding, source, id string, key ed25519.PrivateKey) error {
	expected := bindingValue(source, id, key)
	actual, e := hex.DecodeString(binding.Digest)
	wanted, _ := hex.DecodeString(expected.Digest)
	if e != nil || binding.Version != 1 || !hmac.Equal(actual, wanted) {
		return errors.New("agent host continuity mismatch; preserve state and enroll a new source on the replacement host")
	}
	return nil
}
func verifyHostBinding(c Config, source string, key ed25519.PrivateKey) error {
	var binding hostBinding
	exists, e := loadOptionalJSON(filepath.Join(c.State, "host-binding.json"), &binding)
	if e != nil {
		return e
	}
	if !exists {
		return errors.New("legacy agent state requires explicit bind-host adoption on its verified original host")
	}
	id, e := localMachineID()
	if e != nil {
		return e
	}
	return verifyBindingValue(binding, source, id, key)
}

// BindHost is explicit one-time adoption of a pre-C11 enrolled identity, never a rebind/reset.
func BindHost(ctx context.Context, c Config) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	unlock, e := lockState(c.State)
	if e != nil {
		return e
	}
	defer unlock()
	client, e := open(c, false)
	if e != nil {
		return e
	}
	defer client.http.CloseIdleConnections()
	var existing hostBinding
	exists, e := loadOptionalJSON(filepath.Join(c.State, "host-binding.json"), &existing)
	if e != nil {
		return e
	}
	if exists {
		return verifyHostBinding(c, client.claims.Source, client.key)
	}
	id, e := localMachineID()
	if e != nil {
		return e
	}
	return saveJSON(filepath.Join(c.State, "host-binding.json"), bindingValue(client.claims.Source, id, client.key))
}
