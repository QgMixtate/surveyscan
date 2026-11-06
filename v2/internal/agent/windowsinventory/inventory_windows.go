//go:build windows

// Package windowsinventory implements an isolated, read-only native Windows
// baseline. It is not yet connected to agent enrollment, scheduling or delivery.
package windowsinventory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func name(kind uint32) (string, error) {
	var buf [256]uint16
	n := uint32(len(buf))
	if err := windows.GetComputerNameEx(kind, &buf[0], &n); err != nil || n >= uint32(len(buf)) {
		return "", errors.New("computer name unavailable")
	}
	return windows.UTF16ToString(buf[:n]), nil
}

func identity() []map[string]any {
	host, err := name(windows.ComputerNameDnsHostname)
	if err != nil || host == "" {
		return nil
	}
	row := map[string]any{"hostname": host}
	if fqdn, err := name(windows.ComputerNameDnsFullyQualified); err == nil && fqdn != "" {
		row["fqdn"] = fqdn
	}
	if domain, err := name(windows.ComputerNameDnsDomain); err == nil && domain != "" {
		row["domain"] = domain
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == nil {
		defer key.Close()
		if guid := registryText(key, "MachineGuid", 128); identifier.Valid(guid) {
			row["machine_uuid"] = strings.ToLower(guid)
		}
	}
	return []map[string]any{row}
}

func operatingSystem() []map[string]any {
	v := windows.RtlGetVersion()
	product := "Windows Server"
	if v.ProductType == 1 {
		product = "Windows"
	}
	return []map[string]any{{"name": product, "version": fmt.Sprintf("%d.%d", v.MajorVersion, v.MinorVersion), "build": fmt.Sprint(v.BuildNumber), "architecture": runtime.GOARCH}}
}

func network(ctx context.Context) []map[string]any {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Index < interfaces[j].Index })
	rows := []map[string]any{}
	for _, nic := range interfaces {
		if ctx.Err() != nil || len(rows) == 512 {
			break
		}
		if nic.Flags&net.FlagLoopback != 0 || nic.Name == "" || len([]rune(nic.Name)) > 128 {
			continue
		}
		addresses := []map[string]any{}
		ips, err := nic.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range ips {
			if len(addresses) == 64 {
				break
			}
			ip, prefix, err := net.ParseCIDR(raw.String())
			if err != nil {
				continue
			}
			ones, _ := prefix.Mask.Size()
			addresses = append(addresses, map[string]any{"ip": ip.String(), "prefix": ones})
		}
		row := map[string]any{"name": nic.Name, "addresses": addresses, "interface_index": nic.Index}
		if len(nic.HardwareAddr) == 6 {
			row["mac"] = strings.ToLower(nic.HardwareAddr.String())
		}
		rows = append(rows, row)
	}
	return rows
}

// nativeSection runs only inside the dedicated read-only worker process.
// COM providers use their own branch in WriteWorkerSection.
func nativeSection(ctx context.Context, name string) contracts.Section {
	var rows []map[string]any
	switch name {
	case "identity":
		rows = identity()
	case "os":
		rows = operatingSystem()
	case "network":
		rows = network(ctx)
	case "hardware":
		rows = hardware()
	case "software":
		rows = software(ctx)
	case "services":
		rows = services(ctx)
	case "users_groups":
		if windows.RtlGetVersion().ProductType == 2 {
			return failedSection(name, "unsupported", "LOCAL_SAM_UNSUPPORTED_ON_DC")
		}
		rows = accounts(ctx)
	case "routes_ports":
		rows = routes(ctx)
	case "resources":
		rows = resources(ctx)
	case "neighbors":
		rows = neighbors(ctx)
	default:
		return failedSection(name, "unsupported", "SECTION_UNSUPPORTED")
	}
	if len(rows) == 0 {
		return failedSection(name, "unavailable", "API_DATA_UNAVAILABLE")
	}
	return contracts.Section{Name: name, CollectedAt: time.Now().UTC(), Status: "partial", Complete: false, Reason: "BASELINE_COVERAGE_ONLY", Count: len(rows), Records: rows}
}

// Collect isolates every native provider in our own bounded worker process.
// A failed/timed-out provider cannot discard other section results or strand
// an in-process registry/NetAPI call in the future daemon collection goroutine.
func Collect(ctx context.Context) ([]contracts.Section, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runtime.GOARCH != "amd64" {
		return nil, errors.New("Windows baseline currently targets amd64")
	}
	names := []string{"identity", "os", "network", "hardware", "software", "updates", "services", "users_groups", "routes_ports", "resources", "protection", "neighbors"}
	sections := make([]contracts.Section, 0, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return sections, err
		}
		sections = append(sections, workerSection(ctx, name, 30*time.Second))
	}
	return sections, nil
}
