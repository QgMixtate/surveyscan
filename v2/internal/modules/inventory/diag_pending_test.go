//go:build diag

package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// Диагностика стенда (не часть обычных тестов): PENDING=/путь/к/*.pending go test -tags=diag -run TestDiagPending -v ./internal/modules/inventory
// Применяет к наблюдению из очереди collector те же проверки, что центр (схема + адреса + уникальность ключей),
// и по секциям/строкам показывает, что отвергается.
func TestDiagPending(t *testing.T) {
	path := os.Getenv("PENDING")
	if path == "" {
		t.Skip("PENDING не задан")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Batch struct {
			Records []struct {
				Payload contracts.Observation `json:"payload"`
			} `json:"records"`
		} `json:"batch"`
	}
	if err = json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	brief := func(row map[string]any) string {
		b, _ := json.Marshal(row)
		if len(b) > 220 {
			b = append(b[:220], []byte("...")...)
		}
		return string(b)
	}
	only := func(o contracts.Observation, name string, rows []map[string]any) contracts.Observation {
		probe := o
		probe.Sections = make([]contracts.Section, len(o.Sections))
		for i, sec := range o.Sections {
			if sec.Name == name {
				sec.Records, sec.Count = rows, len(rows)
				if len(rows) == 0 {
					sec.Status, sec.Reason = "unavailable", "DIAG_EMPTY"
				}
			} else {
				sec.Records, sec.Count, sec.Status, sec.Reason = []map[string]any{}, 0, "unavailable", "DIAG_EMPTY"
			}
			probe.Sections[i] = sec
		}
		return probe
	}
	// Полный путь центра: декодер подписанного наблюдения (схема + digest + запрет complete/ok).
	var rawRecords struct {
		Batch struct {
			Records []json.RawMessage `json:"records"`
		} `json:"batch"`
	}
	_ = json.Unmarshal(raw, &rawRecords)
	if base, e := wire.New(); e == nil {
		if decoder, e := wire.NewInventoryDecoder(base, true); e == nil {
			for i, rr := range rawRecords.Batch.Records {
				_, _, _, e := decoder.Observation(rr)
				t.Logf("record %d: signed observation decoder (centre) -> %v", i, e)
				var sig struct {
					Payload json.RawMessage `json:"payload"`
					Digest  string          `json:"digest"`
				}
				_ = json.Unmarshal(rr, &sig)
				if c, e := wire.Canonical(sig.Payload); e == nil {
					sum := sha256.Sum256(c)
					t.Logf("record %d: digest matches canonical payload: %v", i, hex.EncodeToString(sum[:]) == sig.Digest)
				}
			}
		}
	}
	for number, record := range file.Batch.Records {
		o := record.Payload
		_, whole := preparePartial12(o)
		t.Logf("record %d: whole observation -> %v", number, whole)
		for _, section := range o.Sections {
			if _, e := preparePartial12(only(o, section.Name, section.Records)); e == nil {
				t.Logf("  section %-13s rows=%-5d OK", section.Name, len(section.Records))
				continue
			}
			t.Logf("  section %-13s rows=%-5d REJECTED", section.Name, len(section.Records))
			shown := 0
			for i, row := range section.Records {
				if _, e := preparePartial12(only(o, section.Name, []map[string]any{row})); e != nil {
					t.Logf("    bad row %d: %s", i, brief(row))
					if shown++; shown >= 5 {
						break
					}
				}
			}
			seen := map[string]int{}
			dups := 0
			for i, row := range section.Records {
				key, e := recordKey12(section.Name, row)
				if e != nil {
					t.Logf("    row %d key error: %v: %s", i, e, brief(row))
					continue
				}
				if j, dup := seen[key]; dup && dups < 5 {
					dups++
					t.Logf("    duplicate key: rows %d and %d: %s | %s", j, i, brief(section.Records[j]), brief(row))
				}
				seen[key] = i
			}
		}
	}
}
