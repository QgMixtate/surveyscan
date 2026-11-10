package portableaudit

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/agent"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// TestWriteBigPackage — генератор большого пакета для smoke загрузки (scripts/portable_http_smoke.py --big).
// Без SURVEYSCAN_BIGPKG_STATE/OUT пропускается. Один реальный снимок хоста клонируется COUNT раз как отдельные
// цели аудита со своим hostname-кандидатом (иначе центр законно отправит клоны в конфликт идентичности).
func TestWriteBigPackage(t *testing.T) {
	state, out := os.Getenv("SURVEYSCAN_BIGPKG_STATE"), os.Getenv("SURVEYSCAN_BIGPKG_OUT")
	if state == "" || out == "" {
		t.Skip("generator: set SURVEYSCAN_BIGPKG_STATE, SURVEYSCAN_BIGPKG_OUT, SURVEYSCAN_BIGPKG_COUNT")
	}
	count, err := strconv.Atoi(os.Getenv("SURVEYSCAN_BIGPKG_COUNT"))
	if err != nil || count < 1 || count > 10000 {
		t.Fatal("SURVEYSCAN_BIGPKG_COUNT must be 1..10000")
	}
	base, err := agent.CollectHost12(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	run := identifier.New()[:8]
	targets := make([]Target, count)
	for i := range targets {
		name := fmt.Sprintf("bigpkg-%s-%05d", run, i)
		targets[i] = Target{Kind: "host", Name: name, Collect: func(context.Context) (agent.Snapshot, error) {
			s := agent.Snapshot{Sections: base.Sections, Candidates: []contracts.Candidate{{Kind: "hostname", Namespace: "hostname.raw", Value: name}}}
			return s, nil
		}}
	}
	rep, err := Run(context.Background(), state, targets, out, nil)
	if err != nil || rep.Exported != count {
		t.Fatal("export:", rep.Exported, err)
	}
	info, _ := os.Stat(out)
	t.Logf("BIGPKG observations=%d bytes=%d", rep.Exported, info.Size())
}
