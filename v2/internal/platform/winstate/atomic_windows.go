//go:build windows

package winstate

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"golang.org/x/sys/windows"
)

// Test-only injection is never set from config, environment or profile in the
// product. A crash after staging leaves a private orphan, not a partial target.
var replaceHook func(string)

// AtomicReplace requires the exclusive state lock. A fresh private file is
// flushed before same-directory handle-relative NT rename, then flushed again.
// This provides atomic namespace replacement/process-crash recovery; physical
// power-loss durability and orphan recovery still require separate acceptance.
func (r *Root) AtomicReplace(name string, value []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.writer == nil || r.writer.closed || !fileName(name) || len(value) > MaxBytes || runtime.GOARCH != "amd64" {
		return ErrPrivate
	}
	// Never overwrite an unsafe existing leaf or silently treat an I/O/ACL error
	// as absence. The expected previous file may be missing on first acceptance.
	old, err := r.open(name, windows.GENERIC_READ, windows.FILE_OPEN, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE)
	if err != nil {
		var missing *stateError
		if !errors.As(err, &missing) || missing.stage != "relative_open" || missing.code != uint32(windows.ERROR_FILE_NOT_FOUND) {
			return err
		}
	} else {
		windows.CloseHandle(old)
	}
	temporary := ".tmp-" + identifier.New()
	handle, err := r.open(temporary, windows.GENERIC_WRITE|windows.DELETE, windows.FILE_CREATE, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), "private-state")
	renamed := false
	defer func() {
		if !renamed {
			mark := byte(1)
			var status windows.IO_STATUS_BLOCK
			_ = windows.NtSetInformationFile(handle, &status, &mark, 1, windows.FileDispositionInformation)
		}
		_ = file.Close()
	}()
	if _, err = file.Write(value); err != nil {
		return ErrPrivate
	}
	if err = file.Sync(); err != nil {
		return privateError("atomic_flush", err)
	}
	if replaceHook != nil {
		replaceHook("before_rename")
	}
	chars, err := windows.UTF16FromString(name)
	if err != nil {
		return ErrPrivate
	}
	chars = chars[:len(chars)-1]
	// FILE_RENAME_INFORMATION on amd64: BOOLEAN at0, HANDLE at8, ULONG at16,
	// counted WCHAR name at20. Extra tail padding is zero and not part of name.
	buffer := make([]byte, 24+len(chars)*2)
	buffer[0] = 1
	binary.LittleEndian.PutUint64(buffer[8:16], uint64(r.handle))
	binary.LittleEndian.PutUint32(buffer[16:20], uint32(len(chars)*2))
	for i, c := range chars {
		binary.LittleEndian.PutUint16(buffer[20+i*2:], c)
	}
	var status windows.IO_STATUS_BLOCK
	if err = windows.NtSetInformationFile(handle, &status, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation); err != nil {
		return privateError("atomic_rename", err)
	}
	renamed = true
	if replaceHook != nil {
		replaceHook("after_rename")
	}
	if err = file.Sync(); err != nil {
		return privateError("atomic_flush", err)
	}
	if file.Close() != nil {
		return ErrPrivate
	}
	return nil
}
