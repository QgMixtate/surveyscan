//go:build windows

package windowsinventory

import (
	"context"
	"encoding/binary"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func safeText(value string, limit int) string {
	if value == "" || len([]rune(value)) > limit || strings.ContainsFunc(value, func(r rune) bool { return r < 32 || r == 127 }) {
		return ""
	}
	return value
}

func registryText(key registry.Key, name string, limit int) string {
	buf := make([]byte, (limit+1)*2)
	n, kind, err := key.GetValue(name, buf)
	if err != nil || kind != registry.SZ || n < 2 || n > len(buf) || n%2 != 0 {
		return ""
	}
	units := make([]uint16, n/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(buf[i*2 : i*2+2])
	}
	if units[len(units)-1] == 0 {
		units = units[:len(units)-1]
	}
	return safeText(string(utf16.Decode(units)), limit)
}

func hardware() []map[string]any {
	rows := []map[string]any{}
	if count := windows.GetActiveProcessorCount(0xffff); count > 0 {
		rows = append(rows, map[string]any{"kind": "cpu", "name": "Logical processors", "logical_processors": count})
	}
	var memory struct {
		Length, Load                                       uint32
		TotalPhys, AvailPhys, TotalPageFile, AvailPageFile uint64
		TotalVirtual, AvailVirtual, AvailExtendedVirtual   uint64
	}
	memory.Length = uint32(unsafe.Sizeof(memory))
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
	if err := proc.Find(); err == nil {
		if ok, _, _ := proc.Call(uintptr(unsafe.Pointer(&memory))); ok != 0 && memory.TotalPhys > 0 {
			rows = append(rows, map[string]any{"kind": "memory", "name": "Physical memory", "bytes": memory.TotalPhys})
		}
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == nil {
		defer key.Close()
		row := map[string]any{"kind": "bios", "name": "BIOS"}
		for property, valueName := range map[string]string{"vendor": "BIOSVendor", "model": "BIOSVersion"} {
			if value := registryText(key, valueName, 256); value != "" {
				row[property] = value
			}
		}
		if len(row) > 2 {
			rows = append(rows, row)
		}
	}
	return rows
}

func software(ctx context.Context) []map[string]any {
	rows := []map[string]any{}
	// The current token identifies HKCU; never load another profile hive.
	principal := ""
	if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		principal = user.User.Sid.String()
	}
	for _, root := range []struct {
		key   registry.Key
		scope string
	}{{registry.LOCAL_MACHINE, "machine"}, {registry.CURRENT_USER, "current_user"}} {
		if root.scope == "current_user" && principal == "" {
			continue
		}
		for _, view := range []struct {
			flag uint32
			name string
		}{{registry.WOW64_64KEY, "64"}, {registry.WOW64_32KEY, "32"}} {
			if ctx.Err() != nil || len(rows) >= 10000 {
				return rows
			}
			key, err := registry.OpenKey(root.key, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, registry.ENUMERATE_SUB_KEYS|view.flag)
			if err != nil {
				continue
			}
			// Bounded enumeration, no MSI product queries or profile hive loading.
			names, _ := key.ReadSubKeyNames(10000)
			for _, subkey := range names {
				if ctx.Err() != nil || len(rows) >= 10000 {
					break
				}
				entry, err := registry.OpenKey(key, subkey, registry.QUERY_VALUE|view.flag)
				if err != nil {
					continue
				}
				name := registryText(entry, "DisplayName", 256)
				if name != "" && safeText(subkey, 256) != "" {
					row := map[string]any{"name": name, "scope": root.scope, "source": "uninstall_registry", "registry_view": view.name, "registry_key": subkey}
					if root.scope == "current_user" {
						row["principal_sid"] = principal
					}
					for property, valueName := range map[string]string{"version": "DisplayVersion", "vendor": "Publisher"} {
						if value := registryText(entry, valueName, 256); value != "" {
							row[property] = value
						}
					}
					rows = append(rows, row)
				}
				entry.Close()
			}
			key.Close()
		}
	}
	return rows
}

// API pointers are accepted only inside the owned enumeration buffer, with a
// bounded, terminated UTF-16 string; no arbitrary memory or command-line reads.
func serviceText(pointer *uint16, buffer []byte, limit int) string {
	if pointer == nil || len(buffer) == 0 {
		return ""
	}
	start, address := uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(pointer))
	if address < start || address-start >= uintptr(len(buffer)) || (address-start)%2 != 0 {
		return ""
	}
	remaining := (len(buffer) - int(address-start)) / 2
	if remaining > limit+1 {
		remaining = limit + 1
	}
	units := unsafe.Slice(pointer, remaining)
	for i, unit := range units {
		if unit == 0 {
			return safeText(string(utf16.Decode(units[:i])), limit)
		}
	}
	return ""
}

func services(ctx context.Context) []map[string]any {
	handle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil
	}
	defer windows.CloseServiceHandle(handle)
	states := map[uint32]string{1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running", 5: "continue_pending", 6: "pause_pending", 7: "paused"}
	rows := []map[string]any{}
	var resume uint32
	for page := 0; page < 8 && ctx.Err() == nil && len(rows) < 4096; page++ {
		buffer := make([]byte, 256*1024)
		var needed, returned uint32
		err = windows.EnumServicesStatusEx(handle, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL, &buffer[0], uint32(len(buffer)), &needed, &returned, &resume, nil)
		if err != nil && err != windows.ERROR_MORE_DATA {
			break
		}
		if uint64(returned)*uint64(unsafe.Sizeof(windows.ENUM_SERVICE_STATUS_PROCESS{})) > uint64(len(buffer)) {
			break
		}
		entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buffer[0])), int(returned))
		for _, entry := range entries {
			if len(rows) == 4096 {
				break
			}
			name := serviceText(entry.ServiceName, buffer, 256)
			if name == "" {
				continue
			}
			state := states[entry.ServiceStatusProcess.CurrentState]
			if state == "" {
				state = "unknown"
			}
			row := map[string]any{"name": name, "state": state}
			if display := serviceText(entry.DisplayName, buffer, 256); display != "" {
				row["display_name"] = display
			}
			rows = append(rows, row)
		}
		if err == nil || returned == 0 {
			break
		}
	}
	return rows
}
