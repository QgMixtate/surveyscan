package agent

import (
	"context"
	"errors"
	"runtime"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/agent/linuxinventory"
)

// platform12 — платформа агента для профиля 1.2; пусто, если сборка не поддерживается профилем.
func platform12() string {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "windows/amd64":
		return contracts.InventoryPlatform12
	case "linux/amd64":
		return contracts.InventoryPlatformLinux12
	}
	return ""
}

func machineNamespace12() string {
	if runtime.GOOS == "linux" {
		return "linux-machine-id"
	}
	return "windows-machine-guid"
}

func failedSection12(name, status, reason string) contracts.Section {
	return contracts.Section{Name: name, CollectedAt: time.Now().UTC(), Status: status, Complete: false, Reason: reason, Records: []map[string]any{}}
}

func partialSection12(name string, rows []map[string]any) contracts.Section {
	if len(rows) == 0 {
		return failedSection12(name, "unavailable", "DATA_UNAVAILABLE")
	}
	return contracts.Section{Name: name, CollectedAt: time.Now().UTC(), Status: "partial", Complete: false, Reason: "BASELINE_COVERAGE_ONLY", Count: len(rows), Records: rows}
}

// readText читает ограниченный по размеру источник; ошибка — «источник недоступен», а не пустой факт.
func readText(path string, limit int64) (string, bool) {
	b, err := readSmall(path, limit)
	if err != nil {
		return "", false
	}
	return string(b), true
}

const (
	procSmall = 1 << 20
	procLarge = 8 << 20
)

// CollectLinux12 собирает секции профиля 1.2 для Linux чтением /proc и /etc (без внешних команд).
// Секции независимы: сбой одной не отбрасывает остальные. Все секции частичные (partial): полнота
// и удаление отсутствующих записей без покрытия провайдеров не поддерживаются. Реализованы только
// секции, перечисленные в decisions/C16-linux-capabilities.md; остальные — unsupported.
func CollectLinux12(ctx context.Context) (Snapshot, error) {
	if runtime.GOOS != "linux" {
		return Snapshot{}, errors.New("Linux inventory requires Linux")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	base, err := Collect(ctx) // identity, os, network — прежние, проверенные источники
	if err != nil {
		return Snapshot{}, err
	}
	out := Snapshot{Candidates: base.Candidates, Sections: []contracts.Section{}}
	byName := map[string]contracts.Section{}
	for _, s := range base.Sections {
		// Прежние секции помечены полными; в профиле 1.2 они частичные.
		s.Complete = false
		if s.Status == "ok" {
			s.Status = "partial"
			s.Reason = "BASELINE_COVERAGE_ONLY"
		}
		byName[s.Name] = s
	}
	cpu, okCPU := readText("/proc/cpuinfo", procSmall)
	mem, okMem := readText("/proc/meminfo", procSmall)
	if okCPU || okMem {
		byName["hardware"] = partialSection12("hardware", linuxinventory.Hardware(cpu, mem))
	}
	if dpkg, ok := readText("/var/lib/dpkg/status", 64<<20); ok {
		byName["software"] = partialSection12("software", linuxinventory.Packages(dpkg))
	} else {
		byName["software"] = failedSection12("software", "unsupported", "PACKAGE_MANAGER_UNSUPPORTED")
	}
	if passwd, ok := readText("/etc/passwd", procSmall); ok {
		group, _ := readText("/etc/group", procSmall)
		byName["users_groups"] = partialSection12("users_groups", linuxinventory.Accounts(passwd, group))
	}
	rows := []map[string]any{}
	readAny := false
	for _, s := range []struct {
		proto, path string
		v6          bool
	}{{"tcp", "/proc/net/tcp", false}, {"tcp", "/proc/net/tcp6", true}, {"udp", "/proc/net/udp", false}, {"udp", "/proc/net/udp6", true}} {
		if text, ok := readText(s.path, procLarge); ok {
			readAny = true
			rows = append(rows, linuxinventory.Sockets(s.proto, text, s.v6)...)
		}
	}
	if text, ok := readText("/proc/net/route", procSmall); ok {
		readAny = true
		rows = append(rows, linuxinventory.Routes(text)...)
	}
	if readAny {
		byName["routes_ports"] = partialSection12("routes_ports", rows)
	}
	if mi, ok := readText("/proc/self/mountinfo", procLarge); ok {
		byName["resources"] = partialSection12("resources", linuxinventory.Mounts(mi))
	}
	for _, name := range []string{"identity", "os", "network", "hardware", "software", "updates", "services", "users_groups", "routes_ports", "resources", "protection", "neighbors"} {
		s, ok := byName[name]
		switch {
		case ok:
		case name == "updates" || name == "services" || name == "protection" || name == "neighbors":
			s = failedSection12(name, "unsupported", "SECTION_UNSUPPORTED")
		default:
			s = failedSection12(name, "unavailable", "SOURCE_UNAVAILABLE")
		}
		out.Sections = append(out.Sections, s)
	}
	return out, ctx.Err()
}
