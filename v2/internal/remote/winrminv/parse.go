// Package winrminv — безагентный сбор Windows по WinRM (C18): HTTPS с проверкой сертификата, один фиксированный
// read-only сценарий, разбор JSON в секции профиля 1.2 со статусами. Нормализация проверена на фикстурах;
// транспорт и сценарий на живой Windows НЕ проверялись (C18.04).
package winrminv

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
)

type jsonOS struct {
	Caption  string `json:"caption"`
	Version  string `json:"version"`
	Build    string `json:"build"`
	Arch     string `json:"arch"`
	Boot     string `json:"boot"`
	MemoryKB uint64 `json:"memory_kb"`
}
type jsonNIC struct {
	Index    int      `json:"index"`
	Name     string   `json:"name"`
	MAC      string   `json:"mac"`
	IPs      []string `json:"ips"`
	Masks    []string `json:"masks"`
	DNS      []string `json:"dns"`
	Gateways []string `json:"gateways"`
	DHCP     bool     `json:"dhcp"`
	MTU      int      `json:"mtu"`
}
type jsonService struct {
	Name    string `json:"name"`
	Display string `json:"display"`
	State   string `json:"state"`
	Mode    string `json:"mode"`
	Account string `json:"account"`
	Path    string `json:"path"`
}
type jsonSoftware struct {
	View    string `json:"view"`
	Key     string `json:"key"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  string `json:"vendor"`
}
type payload struct {
	Fatal       string                                    `json:"fatal"`
	Errors      []string                                  `json:"errors"`
	Hostname    string                                    `json:"hostname"`
	Domain      string                                    `json:"domain"`
	UUID        string                                    `json:"uuid"`
	MachineGUID string                                    `json:"machine_guid"`
	OS          *jsonOS                                   `json:"os"`
	BIOS        *struct{ Vendor, Version, Serial string } `json:"bios"`
	CPULogical  int                                       `json:"cpu_logical"`
	CPUName     string                                    `json:"cpu_name"`
	NICs        []jsonNIC                                 `json:"nics"`
	Services    []jsonService                             `json:"services"`
	Software    []jsonSoftware                            `json:"software"`
}

var (
	ctrl      = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	macRe     = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$`)
	placehold = map[string]bool{"": true, "to be filled by o.e.m.": true, "default string": true, "none": true, "system serial number": true, "0": true}
)

// str — строка без управляющих символов и в пределах лимита, иначе пусто (значение не выдумывается).
func str(s string, limit int) string {
	s = strings.TrimSpace(s)
	if len(s) > limit || ctrl.MatchString(s) {
		return ""
	}
	return s
}

func maskBits(mask string) (int, bool) {
	a, err := netip.ParseAddr(mask)
	if err != nil || !a.Is4() {
		return 0, false
	}
	bits := 0
	for _, b := range a.As4() {
		for ; b != 0; b <<= 1 {
			bits += int(b >> 7)
		}
	}
	return bits, true
}

var stateMap = map[string]string{"running": "running", "stopped": "stopped", "start pending": "start_pending", "stop pending": "stop_pending",
	"continue pending": "continue_pending", "pause pending": "pause_pending", "paused": "paused"}
var modeMap = map[string]string{"auto": "auto", "manual": "demand", "disabled": "disabled", "boot": "boot", "system": "system"}

// sectionSources — какие источники сценария питают секцию (для причины недоступности).
var sectionSources = map[string][]string{"identity": {"cs", "prod"}, "os": {"os"}, "network": {"nics"}, "hardware": {"os", "cpu", "bios"},
	"software": {"sw64", "sw32"}, "services": {"svcs"}}

// reasonFor возвращает причину пустой секции по ошибкам источников: ACCESS_DENIED (категория PermissionDenied), иначе SOURCE_ERROR / SOURCE_UNAVAILABLE.
func reasonFor(name string, errs []string) string {
	reason := "SOURCE_UNAVAILABLE"
	for _, e := range errs {
		src, cat, _ := strings.Cut(e, ":")
		for _, s := range sectionSources[name] {
			if s == src {
				if cat == "PermissionDenied" {
					return "ACCESS_DENIED"
				}
				reason = "SOURCE_ERROR"
			}
		}
	}
	return reason
}

func sec(name string, rows []map[string]any, now time.Time, errs []string) contracts.Section {
	if len(rows) == 0 {
		return contracts.Section{Name: name, CollectedAt: now, Status: "unavailable", Reason: reasonFor(name, errs), Records: []map[string]any{}}
	}
	return contracts.Section{Name: name, CollectedAt: now, Status: "partial", Reason: "REMOTE_WINRM_PARTIAL", Count: len(rows), Records: rows}
}

// Parse превращает JSON сценария в секции identity/os/network/hardware/software/services (остальное — Complete12).
func Parse(raw []byte, now time.Time) ([]contracts.Section, []contracts.Candidate, error) {
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, nil, err
	}
	if p.Fatal != "" {
		return nil, nil, errors.New("winrm: collection script failed on the target (" + str(p.Fatal, 64) + ")")
	}
	now = now.UTC()
	cands := []contracts.Candidate{}
	var identity, osRows, nets, hw, soft, svcs []map[string]any
	if h := str(p.Hostname, 255); h != "" {
		row := map[string]any{"hostname": h}
		// пространства имён как у родного Windows-агента (loop12.candidatesFromSections): иначе центр не сопоставит источники
		cands = append(cands, contracts.Candidate{Kind: "hostname", Namespace: "hostname.raw", Value: h})
		if d := str(p.Domain, 255); d != "" {
			row["domain"] = d
		}
		if uuidRe.MatchString(p.UUID) && !strings.EqualFold(p.UUID, "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF") && p.UUID != "00000000-0000-0000-0000-000000000000" {
			u := strings.ToLower(p.UUID)
			row["machine_uuid"] = u
			cands = append(cands, contracts.Candidate{Kind: "bios_uuid", Namespace: "smbios", Value: u})
		}
		if g := strings.ToLower(strings.TrimSpace(p.MachineGUID)); uuidRe.MatchString(g) && g != "00000000-0000-0000-0000-000000000000" {
			cands = append(cands, contracts.Candidate{Kind: "machine_uuid", Namespace: "windows-machine-guid", Value: g})
		}
		identity = append(identity, row)
	}
	if o := p.OS; o != nil {
		arch := map[string]string{"64-bit": "amd64", "32-bit": "386", "arm 64-bit processor": "arm64"}[strings.ToLower(strings.TrimSpace(o.Arch))]
		if name, ver := str(o.Caption, 128), str(o.Version, 128); name != "" && ver != "" && arch != "" {
			row := map[string]any{"name": name, "version": ver, "architecture": arch}
			if b := str(o.Build, 128); b != "" {
				row["build"] = b
			}
			if t, err := time.Parse(time.RFC3339, o.Boot); err == nil {
				row["boot_time"], row["boot_time_quality"] = t.UTC().Format(time.RFC3339), "estimated"
			}
			osRows = append(osRows, row)
		}
		if o.MemoryKB > 0 {
			hw = append(hw, map[string]any{"kind": "memory", "name": "Physical memory", "bytes": o.MemoryKB * 1024})
		}
	}
	if p.CPULogical > 0 {
		row := map[string]any{"kind": "cpu", "name": "Logical processors", "logical_processors": p.CPULogical}
		if m := str(p.CPUName, 256); m != "" {
			row["model"] = m
		}
		hw = append(hw, row)
	}
	if b := p.BIOS; b != nil {
		row := map[string]any{"kind": "bios", "name": "System firmware"}
		if v := str(b.Version, 190); v != "" {
			row["name"] = "BIOS " + v
		}
		if v := str(b.Vendor, 256); v != "" {
			row["vendor"] = v
		}
		if s := str(b.Serial, 256); s != "" && !placehold[strings.ToLower(s)] {
			row["serial"] = s
		}
		hw = append(hw, row)
	}
	for _, n := range p.NICs {
		name := str(n.Name, 128)
		if name == "" {
			continue
		}
		row := map[string]any{"name": name}
		addrs := []map[string]any{}
		for i, ip := range n.IPs {
			a, err := netip.ParseAddr(ip)
			if err != nil || a.IsLinkLocalUnicast() || len(addrs) >= 64 {
				continue
			}
			prefix := 0
			if i < len(n.Masks) {
				if a.Is4() {
					if b, ok := maskBits(n.Masks[i]); ok {
						prefix = b
					}
				} else if _, err := fmtInt(n.Masks[i], &prefix); err != nil {
					prefix = 64
				}
			}
			addrs = append(addrs, map[string]any{"ip": a.String(), "prefix": prefix})
		}
		row["addresses"] = addrs
		if macRe.MatchString(n.MAC) {
			row["mac"] = strings.ToLower(strings.ReplaceAll(n.MAC, "-", ":"))
		}
		for key, list := range map[string][]string{"dns_servers": n.DNS, "gateways": n.Gateways} {
			if vals := cleanAddrs(list); len(vals) > 0 {
				row[key] = vals
			}
		}
		row["dhcp_enabled"] = n.DHCP
		if n.MTU > 0 {
			row["mtu"] = n.MTU
		}
		if n.Index > 0 {
			row["interface_index"] = n.Index
		}
		nets = append(nets, row)
	}
	for _, s := range p.Services {
		name := str(s.Name, 256)
		state := stateMap[strings.ToLower(strings.TrimSpace(s.State))]
		if name == "" {
			continue
		}
		if state == "" {
			state = "unknown"
		}
		row := map[string]any{"name": name, "state": state}
		if d := str(s.Display, 256); d != "" {
			row["display_name"] = d
		}
		if m := modeMap[strings.ToLower(strings.TrimSpace(s.Mode))]; m != "" {
			row["start_mode"] = m
		} else {
			row["start_mode"] = "unknown"
		}
		if a := str(s.Account, 256); a != "" {
			row["account"] = a
		}
		if e := str(s.Path, 2048); e != "" {
			row["executable"] = e
		}
		if len(svcs) < 100000 {
			svcs = append(svcs, row)
		}
	}
	for _, s := range p.Software {
		name, key := str(s.Name, 256), str(s.Key, 256)
		if name == "" || key == "" || (s.View != "32" && s.View != "64") || len(soft) >= 100000 {
			continue
		}
		row := map[string]any{"name": name, "scope": "machine", "source": "uninstall_registry", "registry_view": s.View, "registry_key": key}
		if v := str(s.Version, 256); v != "" {
			row["version"] = v
		}
		if v := str(s.Vendor, 256); v != "" {
			row["vendor"] = v
		}
		soft = append(soft, row)
	}
	return []contracts.Section{sec("identity", identity, now, p.Errors), sec("os", osRows, now, p.Errors), sec("network", nets, now, p.Errors),
		sec("hardware", hw, now, p.Errors), sec("software", soft, now, p.Errors), sec("services", svcs, now, p.Errors)}, cands, nil
}

func cleanAddrs(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		if a, err := netip.ParseAddr(s); err == nil && !seen[a.String()] && len(out) < 32 {
			seen[a.String()] = true
			out = append(out, a.String())
		}
	}
	return out
}

func fmtInt(s string, out *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errBadInt
		}
		n = n*10 + int(c-'0')
		if n > 128 {
			return 0, errBadInt
		}
	}
	*out = n
	return n, nil
}

var errBadInt = &parseError{"bad prefix"}

type parseError struct{ s string }

func (e *parseError) Error() string { return e.s }
