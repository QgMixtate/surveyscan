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

// Linux-строки проходят схему наблюдения и получают устойчивые ключи без registry_key/SID.
func TestRecord12LinuxRowsKeysAndSchema(t *testing.T) {
	o := partial12Fixture(t)
	linux := map[string][]map[string]any{
		"software": {{"name": "bash", "version": "5.2-1", "architecture": "amd64", "scope": "machine", "source": "dpkg"}},
		"users_groups": {
			{"kind": "user", "name": "root", "uid": 0, "gid": 0, "shell": "/bin/bash"},
			{"kind": "group", "name": "wheel", "gid": 10},
			{"kind": "membership", "name": "root", "group": "wheel", "gid": 10},
		},
		"routes_ports": {
			{"kind": "route", "family": "ipv4", "destination": "0.0.0.0/0", "gateway": "192.168.0.1", "interface": "eth0", "metric": 100},
			{"kind": "tcp", "family": "ipv4", "local_address": "127.0.0.1", "local_port": 22, "remote_address": "0.0.0.0", "remote_port": 0, "state": "LISTEN"},
		},
		"resources": {{"kind": "mount", "name": "/", "filesystem": "ext4", "device_id": "/dev/sda1", "read_only": false}},
	}
	for i := range o.Sections {
		if rows, ok := linux[o.Sections[i].Name]; ok {
			o.Sections[i].Records = rows
			o.Sections[i].Count = len(rows)
		}
	}
	prepared, err := preparePartial12(o)
	if err != nil {
		t.Fatal("linux rows rejected", err)
	}
	if len(prepared["users_groups"]) != 3 || len(prepared["routes_ports"]) != 2 || len(prepared["software"]) != 1 {
		t.Fatal("linux rows lost")
	}
	// Идентичность — не изменяемые поля; разные пакеты/архитектуры/пользователи не сливаются.
	a, _ := recordKey12("software", linux["software"][0])
	changed := map[string]any{"name": "bash", "version": "9", "architecture": "amd64", "scope": "machine", "source": "dpkg"}
	b, _ := recordKey12("software", changed)
	if a != b {
		t.Fatal("version changed package identity")
	}
	changed["architecture"] = "arm64"
	if c, _ := recordKey12("software", changed); c == a {
		t.Fatal("architectures collapsed")
	}
	u0, _ := recordKey12("users_groups", map[string]any{"kind": "user", "name": "root", "uid": 0, "gid": 0})
	u1, _ := recordKey12("users_groups", map[string]any{"kind": "user", "name": "svc", "uid": 101, "gid": 101})
	if u0 == u1 {
		t.Fatal("users collapsed")
	}
	// Строка Windows (SID) по-прежнему требует прежнего ключа: ключ Linux-пакета не должен совпасть.
	if _, err = recordKey12("software", map[string]any{"source": "uninstall_registry", "scope": "machine"}); err == nil {
		t.Fatal("windows software without registry_key accepted")
	}
	// Смешение: Linux-источник пакетов вместе с полями реестра отвергается схемой.
	bad := partial12Fixture(t)
	for i := range bad.Sections {
		if bad.Sections[i].Name == "software" {
			bad.Sections[i].Records = []map[string]any{{"name": "x", "scope": "machine", "source": "dpkg", "registry_key": "K"}}
			bad.Sections[i].Count = 1
		}
	}
	if _, err = preparePartial12(bad); err == nil {
		t.Fatal("mixed windows/linux software row accepted")
	}
}
