package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
)

func partial12Fixture(t *testing.T) contracts.Observation {
	t.Helper()
	b, err := os.ReadFile("../../../../docs/plans/surveyscan-v2/contracts/C15/fixtures.json")
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
	for _, f := range fixtures {
		if f.ID != "all-sections" {
			continue
		}
		for i := range f.Payload.Sections {
			f.Payload.Sections[i].Status = "partial"
			f.Payload.Sections[i].Complete = false
		}
		return f.Payload
	}
	t.Fatal("missing fixture")
	return contracts.Observation{}
}

func TestRecord12StableKeysAndTypedFields(t *testing.T) {
	o := partial12Fixture(t)
	prepared, err := preparePartial12(o)
	if err != nil || len(prepared) != 12 {
		t.Fatal("all 12 sections must project", err)
	}
	for _, section := range o.Sections {
		for _, row := range section.Records {
			key, err := recordKey12(section.Name, row)
			if err != nil || len(key) != 64 {
				t.Fatal(section.Name, err)
			}
			copy := map[string]any{}
			for k, v := range row {
				copy[k] = v
			}
			// None of these values is part of a provider locator.
			for _, field := range []string{"state", "enabled", "free_bytes", "metric", "disabled", "mac", "version", "vendor"} {
				if _, ok := copy[field]; ok {
					copy[field] = "changed"
				}
			}
			again, err := recordKey12(section.Name, copy)
			if err != nil || again != key {
				t.Fatal("mutable field changed record identity", section.Name, err)
			}
		}
	}
	software := map[string]any{"source": "uninstall_registry", "scope": "current_user", "registry_view": "64", "registry_key": "Product-Key", "principal_sid": "S-1-5-21-1001"}
	aKey, _ := recordKey12("software", software)
	software["registry_key"] = "PRODUCT-KEY"
	bKey, _ := recordKey12("software", software)
	if aKey != bKey {
		t.Fatal("registry key casing changed identity")
	}
	software["principal_sid"] = "S-1-5-21-1002"
	cKey, _ := recordKey12("software", software)
	if cKey == aKey {
		t.Fatal("HKCU records from different users collapsed")
	}
	users := map[string]any{"kind": "membership", "sid": "S-1-5-21-1", "group_sid": "S-1-5-32-1"}
	a, _ := recordKey12("users_groups", users)
	users["group_sid"] = "S-1-5-32-2"
	b, _ := recordKey12("users_groups", users)
	if a == b {
		t.Fatal("memberships of different groups collapsed")
	}
}

func TestRecord12RejectsAmbiguityAndCompleteBeforeSQL(t *testing.T) {
	for name, mutate := range map[string]func(*contracts.Observation){
		"duplicate": func(o *contracts.Observation) {
			s := &o.Sections[6]
			s.Records = append(s.Records, s.Records[0])
			s.Count++
		},
		"singleton-duplicate": func(o *contracts.Observation) {
			s := &o.Sections[0]
			s.Records = append(s.Records, s.Records[0])
			s.Count++
		},
		"complete":                 func(o *contracts.Observation) { o.Sections[6].Complete = true; o.Sections[6].Status = "ok" },
		"unknown":                  func(o *contracts.Observation) { o.Sections[6].Name = "future_section" },
		"software-without-locator": func(o *contracts.Observation) { delete(o.Sections[4].Records[0], "registry_key") },
		"user-without-principal": func(o *contracts.Observation) {
			o.Sections[4].Records[0]["scope"] = "current_user"
			delete(o.Sections[4].Records[0], "principal_sid")
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := partial12Fixture(t)
			mutate(&o)
			if _, err := (Store{}).ProjectPartial12(context.Background(), nil, o, "", "", "", 1); !errors.Is(err, domain.Invalid) {
				t.Fatal("invalid projection reached SQL", err)
			}
		})
	}
}

func TestLegacyProjectionRejectsUnknownEvenEmptyBeforeSQL(t *testing.T) {
	for _, count := range []int{0, 1} {
		s := contracts.Section{Name: "hardware"}
		if count == 1 {
			s.Records = []map[string]any{{"name": "cpu"}}
		}
		if _, err := flatten(s); !errors.Is(err, domain.Invalid) {
			t.Fatal("unknown section silently lost", err)
		}
		if _, err := (Store{}).Project(context.Background(), nil, contracts.Observation{Sections: []contracts.Section{s}}, "", "", "", 1); !errors.Is(err, domain.Invalid) {
			t.Fatal("unknown section reached SQL", err)
		}
	}
}
