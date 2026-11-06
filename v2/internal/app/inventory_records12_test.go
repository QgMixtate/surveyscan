package app

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
)

func TestRecordCursor12CannotCrossScopeOrRevision(t *testing.T) {
	parts := []string{"tenant", "asset", "services", "9", strings.Repeat("a", 64), "state"}
	encode := func(parts []string) string {
		b, _ := json.Marshal(parts)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	if key, field, err := decodeRecordCursor12(encode(parts), "tenant", "asset", "services", "9"); err != nil || key != parts[4] || field != "state" {
		t.Fatal(err)
	}
	for _, index := range []int{0, 1, 2} {
		other := append([]string(nil), parts...)
		other[index] += "-other"
		if _, _, err := decodeRecordCursor12(encode(other), "tenant", "asset", "services", "9"); !errors.Is(err, domain.Invalid) {
			t.Fatal("cross-scope cursor accepted", index, err)
		}
	}
	if _, _, err := decodeRecordCursor12(encode(parts), "tenant", "asset", "services", "10"); !errors.Is(err, recordProjectionChanged) {
		t.Fatal("mixed projection revisions", err)
	}
	for _, bad := range []string{"09", "18446744073709551616", "-1"} {
		other := append([]string(nil), parts...)
		other[3] = bad
		if _, _, err := decodeRecordCursor12(encode(other), "tenant", "asset", "services", "9"); !errors.Is(err, domain.Invalid) {
			t.Fatal("invalid revision accepted", err)
		}
	}
}
