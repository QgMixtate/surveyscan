//go:build windows

package windowsinventory

import (
	"context"
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// MIB_IPNET_ROW2 layout from netioapi.h. This adapter targets Windows/amd64.
type neighborRow struct {
	Address          windows.RawSockaddrInet
	InterfaceIndex   uint32
	InterfaceLuid    uint64
	PhysicalAddress  [32]byte
	PhysicalLength   uint32
	State            uint32
	Flags            uint8
	_                [3]byte
	ReachabilityTime uint32
}

type neighborTable struct {
	Count uint32
	_     uint32
	Rows  [1]neighborRow
}

// neighbors reads the local ARP/NDP cache only. It never resolves a neighbor,
// sends discovery probes, enables an interface or promises a complete topology.
func neighbors(ctx context.Context) []map[string]any {
	rows, _ := neighborSnapshot(ctx)
	return rows
}

func neighborSnapshot(ctx context.Context) ([]map[string]any, error) {
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetIpNetTable2")
	if proc.Find() != nil || ctx.Err() != nil {
		return nil, errors.New("native neighbor API unavailable or cancelled")
	}
	var table *neighborTable
	code, _, _ := proc.Call(windows.AF_UNSPEC, uintptr(unsafe.Pointer(&table)))
	if code != 0 || table == nil {
		return nil, errors.New("native neighbor table unavailable")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	count := table.Count
	if count > 10000 {
		count = 10000
	}
	states := map[uint32]string{0: "unreachable", 1: "incomplete", 2: "probe", 3: "delay", 4: "stale", 5: "reachable", 6: "permanent"}
	rows := []map[string]any{}
	for _, entry := range unsafe.Slice(&table.Rows[0], int(count)) {
		if ctx.Err() != nil {
			break
		}
		ip, ok := sockaddrIP(&entry.Address)
		if !ok || ip.Is4In6() {
			continue
		}
		family := "ipv6"
		if ip.Is4() {
			family = "ipv4"
		}
		row := map[string]any{"family": family, "address": ip.String(), "interface_index": entry.InterfaceIndex}
		if state := states[entry.State]; state != "" {
			row["state"] = state
		}
		if entry.PhysicalLength == 6 {
			row["mac"] = net.HardwareAddr(entry.PhysicalAddress[:6]).String()
		}
		rows = append(rows, row)
	}
	return rows, ctx.Err()
}
