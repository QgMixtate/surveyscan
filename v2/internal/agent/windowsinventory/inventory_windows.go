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

// Collect returns all section statuses; baseline sections remain partial because
// full C15 coverage is not implemented. Unsupported sections never imply absence.
// Only local APIs are called, with no shell, external targets or user file reads.
func Collect(ctx context.Context) ([]contracts.Section, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runtime.GOARCH != "amd64" {
		return nil, errors.New("Windows baseline currently targets amd64")
	}
	collectors := []struct {
		name string
		read func() []map[string]any
	}{
		{"identity", identity}, {"os", operatingSystem}, {"network", func() []map[string]any { return network(ctx) }},
		{"hardware", hardware}, {"software", func() []map[string]any { return software(ctx) }}, {"updates", nil}, {"services", func() []map[string]any { return services(ctx) }},
		{"users_groups", func() []map[string]any { return accounts(ctx) }}, {"routes_ports", func() []map[string]any { return routes(ctx) }}, {"resources", func() []map[string]any { return resources(ctx) }}, {"protection", nil}, {"neighbors", func() []map[string]any { return neighbors(ctx) }},
	}
	sections := make([]contracts.Section, 0, len(collectors))
	for _, c := range collectors {
		if err := ctx.Err(); err != nil {
			return sections, err
		}
		rows := []map[string]any{}
		status, reason := "unsupported", "ADAPTER_NOT_IMPLEMENTED"
		if c.name == "users_groups" && windows.RtlGetVersion().ProductType == 2 {
			reason = "LOCAL_SAM_UNSUPPORTED_ON_DC"
		} else if c.read != nil {
			rows = c.read()
			status, reason = "partial", "BASELINE_COVERAGE_ONLY"
			if len(rows) == 0 {
				rows = []map[string]any{}
				status, reason = "unavailable", "API_DATA_UNAVAILABLE"
			}
		}
		sections = append(sections, contracts.Section{Name: c.name, CollectedAt: time.Now().UTC(), Status: status, Complete: false, Reason: reason, Count: len(rows), Records: rows})
	}
	return sections, nil
}
