//go:build windows

package windowsinventory

import (
	"context"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

func resources(ctx context.Context) []map[string]any {
	var roots [1024]uint16
	n, err := windows.GetLogicalDriveStrings(uint32(len(roots)), &roots[0])
	if err != nil || n == 0 || n >= uint32(len(roots)) {
		return nil
	}
	rows := []map[string]any{}
	for offset := 0; offset < int(n) && ctx.Err() == nil; {
		end := offset
		for end < int(n) && roots[end] != 0 {
			end++
		}
		root := windows.UTF16ToString(roots[offset:end])
		offset = end + 1
		if root == "" {
			continue
		}
		path, err := windows.UTF16PtrFromString(root)
		// Do not probe remote drives, removable media or trigger mounts.
		if err != nil || windows.GetDriveType(path) != windows.DRIVE_FIXED {
			continue
		}
		var callerFree, total, free uint64
		if windows.GetDiskFreeSpaceEx(path, &callerFree, &total, &free) != nil {
			continue
		}
		row := map[string]any{"kind": "volume", "name": root, "total_bytes": total, "free_bytes": free}
		var filesystem [64]uint16
		if windows.GetVolumeInformation(path, nil, 0, nil, nil, nil, &filesystem[0], uint32(len(filesystem))) == nil {
			if value := safeText(windows.UTF16ToString(filesystem[:]), 64); value != "" {
				row["filesystem"] = value
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func sockaddrIP(raw *windows.RawSockaddrInet) (netip.Addr, bool) {
	switch raw.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(raw)).Addr), true
	case windows.AF_INET6:
		return netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(raw)).Addr), true
	}
	return netip.Addr{}, false
}

func routes(ctx context.Context) []map[string]any {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil || table == nil {
		return nil
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	count := table.NumEntries
	if count > 10000 {
		count = 10000
	}
	rows := []map[string]any{}
	for _, entry := range unsafe.Slice(&table.Table[0], int(count)) {
		if ctx.Err() != nil {
			break
		}
		ip, ok := sockaddrIP(&entry.DestinationPrefix.Prefix)
		if !ok || int(entry.DestinationPrefix.PrefixLength) > ip.BitLen() || ip.Is4In6() {
			continue
		}
		family := "ipv6"
		if ip.Is4() {
			family = "ipv4"
		}
		row := map[string]any{"kind": "route", "family": family, "destination": netip.PrefixFrom(ip, int(entry.DestinationPrefix.PrefixLength)).String(), "interface_index": entry.InterfaceIndex, "metric": entry.Metric}
		if gateway, ok := sockaddrIP(&entry.NextHop); ok && gateway.Is4() == ip.Is4() {
			row["gateway"] = gateway.String()
		}
		rows = append(rows, row)
	}
	return rows
}
