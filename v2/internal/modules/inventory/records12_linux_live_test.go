//go:build linux

package inventory

import (
	"context"
	"testing"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/agent"
)

// Живые данные этого Linux-хоста должны проходить проекцию 1.2: схема наблюдения и уникальность
// ключей записей внутри секции (дубль ключа отвергает всю секцию).
func TestRecord12LiveLinuxSnapshotProjects(t *testing.T) {
	snap, err := agent.CollectLinux12(context.Background())
	if err != nil {
		t.Skip("сбор недоступен:", err)
	}
	o := partial12Fixture(t)
	o.CollectedAt = time.Now().UTC().Add(time.Second)
	o.Sections = snap.Sections
	prepared, err := preparePartial12(o)
	if err != nil {
		for _, s := range snap.Sections {
			seen := map[string]int{}
			for i, row := range s.Records {
				key, kerr := recordKey12(s.Name, row)
				if kerr != nil {
					t.Logf("%s row %d: key error %v: %v", s.Name, i, kerr, row)
					break
				}
				if j, dup := seen[key]; dup {
					t.Logf("%s: duplicate key rows %d and %d: %v | %v", s.Name, j, i, s.Records[j], row)
					break
				}
				seen[key] = i
			}
		}
		t.Fatal("live Linux snapshot rejected by projection: ", err)
	}
	total := 0
	for _, rows := range prepared {
		total += len(rows)
	}
	t.Logf("projected %d sections, %d records", len(prepared), total)
}
