//go:build windows

package windowsinventory

import (
	"context"
	"unsafe"

	"golang.org/x/sys/windows"
)

const accountPageBytes = 64 * 1024

// NetAPI returns only public local account/group names and membership SIDs.
// No SAM/LSA secrets, password material, remote server or domain enumeration.
func accounts(ctx context.Context) []map[string]any {
	if windows.RtlGetVersion().ProductType == 2 {
		return nil // A domain controller has no local SAM; do not enumerate AD.
	}
	rows := []map[string]any{}
	host, err := name(windows.ComputerNameNetBIOS)
	if err != nil || host == "" {
		return nil
	}
	var resume uint32
	for page := 0; page < 32 && ctx.Err() == nil && len(rows) < 10000; page++ {
		var buffer *byte
		var count, total uint32
		err := windows.NetUserEnum(nil, 0, 2, &buffer, accountPageBytes, &count, &total, &resume)
		if err != nil && err != windows.ERROR_MORE_DATA {
			if buffer != nil {
				windows.NetApiBufferFree(buffer)
			}
			break
		}
		if buffer != nil && count <= accountPageBytes/uint32(unsafe.Sizeof(uintptr(0))) {
			for _, pointer := range unsafe.Slice((**uint16)(unsafe.Pointer(buffer)), int(count)) {
				if ctx.Err() != nil || len(rows) == 10000 {
					break
				}
				if pointer == nil {
					continue
				}
				user := safeText(windows.UTF16PtrToString(pointer), 256)
				if user == "" {
					continue
				}
				sid, _, kind, e := windows.LookupSID("", host+`\`+user)
				if e == nil && kind == windows.SidTypeUser && sid != nil && sid.IsValid() {
					rows = append(rows, map[string]any{"kind": "user", "sid": sid.String(), "name": user})
				}
			}
		}
		if buffer != nil {
			windows.NetApiBufferFree(buffer)
		}
		if err == nil || count == 0 {
			break
		}
	}
	return localGroups(ctx, rows)
}

func localGroups(ctx context.Context, rows []map[string]any) []map[string]any {
	host, err := name(windows.ComputerNameNetBIOS)
	if err != nil || host == "" {
		return rows
	}
	dll := windows.NewLazySystemDLL("netapi32.dll")
	enumerate, members := dll.NewProc("NetLocalGroupEnum"), dll.NewProc("NetLocalGroupGetMembers")
	if enumerate.Find() != nil || members.Find() != nil {
		return rows
	}
	var resume uintptr // PDWORD_PTR, unlike NetUserEnum's PDWORD resume handle.
	groups := 0
	for page := 0; page < 32 && ctx.Err() == nil && len(rows) < 10000 && groups < 512; page++ {
		var buffer *byte
		var count, total uint32
		code, _, _ := enumerate.Call(0, 0, uintptr(unsafe.Pointer(&buffer)), accountPageBytes,
			uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
		if code != 0 && code != uintptr(windows.ERROR_MORE_DATA) {
			if buffer != nil {
				windows.NetApiBufferFree(buffer)
			}
			break
		}
		if buffer != nil && count <= accountPageBytes/uint32(unsafe.Sizeof(uintptr(0))) {
			for _, pointer := range unsafe.Slice((**uint16)(unsafe.Pointer(buffer)), int(count)) {
				if ctx.Err() != nil || len(rows) >= 10000 || groups == 512 {
					break
				}
				if pointer == nil {
					continue
				}
				group := safeText(windows.UTF16PtrToString(pointer), 256)
				if group == "" {
					continue
				}
				sid, _, kind, err := windows.LookupSID("", host+`\`+group)
				if err != nil {
					sid, _, kind, err = windows.LookupSID("", `BUILTIN\`+group)
				}
				if err != nil || kind != windows.SidTypeAlias || sid == nil || !sid.IsValid() {
					continue
				}
				id := sid.String()
				rows = append(rows, map[string]any{"kind": "group", "sid": id, "name": group})
				groups++
				rows = groupMembers(ctx, members, pointer, id, rows)
			}
		}
		if buffer != nil {
			windows.NetApiBufferFree(buffer)
		}
		if code == 0 || count == 0 {
			break
		}
	}
	return rows
}

func groupMembers(ctx context.Context, enumerate *windows.LazyProc, group *uint16, id string, rows []map[string]any) []map[string]any {
	var resume uintptr
	for page := 0; page < 32 && ctx.Err() == nil && len(rows) < 10000; page++ {
		var buffer *byte
		var count, total uint32
		code, _, _ := enumerate.Call(0, uintptr(unsafe.Pointer(group)), 0,
			uintptr(unsafe.Pointer(&buffer)), accountPageBytes, uintptr(unsafe.Pointer(&count)),
			uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
		if code != 0 && code != uintptr(windows.ERROR_MORE_DATA) {
			if buffer != nil {
				windows.NetApiBufferFree(buffer)
			}
			break
		}
		if buffer != nil && count <= accountPageBytes/uint32(unsafe.Sizeof(uintptr(0))) {
			for _, sid := range unsafe.Slice((**windows.SID)(unsafe.Pointer(buffer)), int(count)) {
				if ctx.Err() != nil || len(rows) == 10000 {
					break
				}
				if sid != nil && sid.IsValid() {
					rows = append(rows, map[string]any{"kind": "membership", "sid": sid.String(), "group_sid": id})
				}
			}
		}
		if buffer != nil {
			windows.NetApiBufferFree(buffer)
		}
		if code == 0 || count == 0 {
			break
		}
	}
	return rows
}
