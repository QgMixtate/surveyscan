//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// Живой сбор на этом хосте (не фикстура): 12 секций в профиле 1.2, все частичные или явно
// unavailable/unsupported, строки проходят настоящую схему наблюдения, секретов нет.
func TestCollectLinux12LiveHostPassesObservationSchema(t *testing.T) {
	if platform12() != contracts.InventoryPlatformLinux12 {
		t.Skip("платформа не linux/amd64")
	}
	snap, err := CollectLinux12(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Sections) != 12 {
		t.Fatal("expected 12 sections", len(snap.Sections))
	}
	byName := map[string]contracts.Section{}
	for _, s := range snap.Sections {
		byName[s.Name] = s
		if s.Complete || s.Status == "ok" {
			t.Fatalf("%s: 1.2 partial profile forbids complete/ok (%s)", s.Name, s.Status)
		}
		t.Logf("%-13s status=%-11s reason=%-28s rows=%d", s.Name, s.Status, s.Reason, len(s.Records))
	}
	for _, name := range []string{"identity", "os", "network", "hardware", "users_groups", "routes_ports", "resources"} {
		if byName[name].Status != "partial" || len(byName[name].Records) == 0 {
			t.Errorf("%s not collected on live host: %+v", name, byName[name].Status)
		}
	}
	for _, name := range []string{"updates", "services", "protection", "neighbors"} {
		if byName[name].Status != "unsupported" {
			t.Errorf("%s must be explicitly unsupported", name)
		}
	}
	// Секреты: ни одна строка не содержит поля пароля/хэша.
	raw, _ := json.Marshal(snap.Sections)
	for _, bad := range []string{"$6$", "$y$", "$5$", "$1$", "\"password\"", "\"hash\""} {
		if json.Valid(raw) && contains(raw, bad) {
			t.Errorf("secret-like text %q in inventory", bad)
		}
	}
	// Схема наблюдения (контракт C15) на реальных данных.
	b, err := os.ReadFile("../../../docs/plans/surveyscan-v2/contracts/C15/fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		ID      string                `json:"id"`
		Payload contracts.Observation `json:"payload"`
	}
	if err = json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	var o contracts.Observation
	for _, f := range fixtures {
		if f.ID == "all-sections" {
			o = f.Payload
		}
	}
	o.Sections = snap.Sections
	o.CollectedAt = time.Now().UTC().Add(time.Second) // секции не могут быть новее наблюдения
	v, err := wire.NewInventory12()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(o)
	if _, err = v.Payload(body); err != nil {
		t.Fatal("live Linux sections rejected by observation schema: ", err)
	}
}

func contains(b []byte, s string) bool { return len(s) > 0 && indexOf(b, s) >= 0 }
func indexOf(b []byte, s string) int {
	for i := 0; i+len(s) <= len(b); i++ {
		if string(b[i:i+len(s)]) == s {
			return i
		}
	}
	return -1
}
