package portableaudit

import (
	"context"
	"encoding/json"
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

// TestWriteDemoPackage — генератор ДЕМО-пакета (синтетические хосты для показа схемы сети и карточки 1.2).
// Без SURVEYSCAN_DEMOPKG_STATE/OUT/SPEC пропускается. SPEC — JSON-массив хостов: name, os{name,version},
// network[{name,mac,addresses[{ip,prefix}],gateways[]}], routes[{destination,gateway,interface}]. Остальные разделы
// берутся из реального снимка этого хоста.
func TestWriteDemoPackage(t *testing.T) {
	state, out, spec := os.Getenv("SURVEYSCAN_DEMOPKG_STATE"), os.Getenv("SURVEYSCAN_DEMOPKG_OUT"), os.Getenv("SURVEYSCAN_DEMOPKG_SPEC")
	if state == "" || out == "" || spec == "" {
		t.Skip("demo generator: set SURVEYSCAN_DEMOPKG_STATE, SURVEYSCAN_DEMOPKG_OUT, SURVEYSCAN_DEMOPKG_SPEC")
	}
	raw, err := os.ReadFile(spec)
	if err != nil {
		t.Fatal(err)
	}
	var hosts []struct {
		Name    string           `json:"name"`
		OS      map[string]any   `json:"os"`
		Network []map[string]any `json:"network"`
		Routes  []map[string]any `json:"routes"`
	}
	if err = json.Unmarshal(raw, &hosts); err != nil {
		t.Fatal(err)
	}
	base, err := agent.CollectHost12(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	targets := []Target{}
	for _, h := range hosts {
		h := h
		targets = append(targets, Target{Kind: "host", Name: h.Name, Collect: func(context.Context) (agent.Snapshot, error) {
			s := agent.Snapshot{Candidates: []contracts.Candidate{{Kind: "hostname", Namespace: "hostname.raw", Value: h.Name}}}
			for _, sec := range base.Sections {
				sec.Records = append(make([]map[string]any, 0, len(sec.Records)), sec.Records...)
				switch sec.Name {
				case "identity":
					sec.Records = []map[string]any{{"hostname": h.Name}}
				case "os":
					sec.Records = []map[string]any{h.OS}
				case "network":
					sec.Records = h.Network
				case "routes_ports":
					sec.Records = h.Routes
				default:
					if len(sec.Records) > 150 { // демо: урезанный список, чтобы импорт десятка хостов шёл секунды
						sec.Records = sec.Records[:150]
					}
				}
				if len(sec.Records) > 0 && sec.Status != "partial" {
					sec.Status, sec.Reason = "partial", "BASELINE_COVERAGE_ONLY"
				}
				sec.Count = len(sec.Records)
				s.Sections = append(s.Sections, sec)
			}
			return s, nil
		}})
	}
	rep, err := Run(context.Background(), state, targets, out, nil)
	if err != nil || rep.Exported != len(hosts) {
		t.Fatal("export:", rep.Exported, err, rep.Results)
	}
}
