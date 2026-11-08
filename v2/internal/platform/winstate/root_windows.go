//go:build windows

// Package winstate contains isolated Windows private-state primitives. It does
// not enable the agent, repair existing ACLs, replace files or bind host identity.
package winstate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ErrPrivate = errors.New("private Windows state unavailable or unsafe")

const MaxBytes = 2 << 20

type stateError struct {
	stage string
	code  uint32
	// status — сырой NTSTATUS (0 для win32-ошибок): разные статусы, например
	// ACCESS_DENIED и DELETE_PENDING, сворачиваются в один win32-код 5.
	status uint32
}

func (e *stateError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("%s [%s code=%d status=0x%08x]", ErrPrivate, e.stage, e.code, e.status)
	}
	return fmt.Sprintf("%s [%s code=%d]", ErrPrivate, e.stage, e.code)
}
func (e *stateError) Unwrap() error { return ErrPrivate }
func privateError(stage string, err error) error {
	switch stage {
	case "root_create", "root_open", "root_path", "root_type", "root_acl", "relative_open", "file_type", "file_acl", "atomic_rename", "atomic_flush", "orphan_scan", "orphan_delete":
	default:
		stage = "unknown"
	}
	var code, status uint32
	var native windows.NTStatus
	var win32 syscall.Errno
	if errors.As(err, &native) {
		code = uint32(native.Errno())
		status = uint32(native)
	} else if errors.As(err, &win32) {
		code = uint32(win32)
	}
	return &stateError{stage: stage, code: code, status: status}
}

type stateLock struct {
	handle windows.Handle
	closed bool
}

type Root struct {
	writer *stateLock
	mu     sync.Mutex
	handle windows.Handle
	owner  string
	sd     *windows.SECURITY_DESCRIPTOR
}

// enabledAdministrator: группа Administrators в токене включена и не «только для запрета»
// (так у повышенного администратора и у LocalSystem). IsMember здесь не подходит: он требует
// токен олицетворения, а у основного токена процесса молча отвечает «нет».
func enabledAdministrator(token windows.Token) bool {
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.Equals(admins) && g.Attributes&windows.SE_GROUP_ENABLED != 0 && g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return true
		}
	}
	return false
}
func descriptor() (*windows.SECURITY_DESCRIPTOR, string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, "", ErrPrivate
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, "", ErrPrivate
	}
	sid := user.User.Sid.String()
	// Администратор (включённая группа Administrators; LocalSystem тоже в ней) получает доступ
	// через BA, а запись с его личным SID лишняя и вредная: служба под другой учётной записью
	// не доверяла бы такому каталогу. Обычный пользователь сохраняет свою запись.
	sddl := "O:" + sid + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid + ")"
	if enabledAdministrator(token) {
		sddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, "", ErrPrivate
	}
	return sd, sid, nil
}
func localPath(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return "", ErrPrivate
	}
	path = filepath.Clean(path)
	if len(path) <= 3 || path[1] != ':' || strings.Contains(path[2:], ":") {
		return "", ErrPrivate
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if part == "" || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return "", ErrPrivate
		}
	}
	return path, nil
}
func longPath(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", ErrPrivate
	}
	buffer := make([]uint16, 32768)
	n, err := windows.GetLongPathName(p, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) >= len(buffer) {
		return "", ErrPrivate
	}
	return windows.UTF16ToString(buffer[:n]), nil
}
func finalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil || n == 0 || int(n) >= len(buffer) {
		return "", ErrPrivate
	}
	return strings.TrimPrefix(windows.UTF16ToString(buffer[:n]), `\\?\`), nil
}
func trusted(sid, owner string) bool {
	return sid == owner || sid == "S-1-5-18" || sid == "S-1-5-32-544"
}
func checkACL(handle windows.Handle, owner string) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !sd.IsValid() {
		return ErrPrivate
	}
	defer runtime.KeepAlive(sd)
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrPrivate
	}
	user, _, err := sd.Owner()
	if err != nil || user == nil || !trusted(user.String(), owner) {
		return ErrPrivate
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 || acl.AceCount > 64 {
		return ErrPrivate
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil || ace.Header.AceSize < 16 || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return ErrPrivate
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrPrivate
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len() > int(ace.Header.AceSize)-8 || !trusted(sid.String(), owner) {
			return ErrPrivate
		}
	}
	return nil
}
func info(handle windows.Handle, directory bool) (windows.ByHandleFileInformation, error) {
	var out windows.ByHandleFileInformation
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK {
		return out, ErrPrivate
	}
	if windows.GetFileInformationByHandle(handle, &out) != nil || out.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return out, ErrPrivate
	}
	isDir := out.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDir != directory || !directory && out.NumberOfLinks > 1 {
		return out, ErrPrivate
	}
	return out, nil
}

// CreateRoot creates a new directory with its private descriptor already set.
// Existing directories are never silently adopted or permission-repaired.
func CreateRoot(path string) (*Root, error) {
	clean, err := localPath(path)
	if err != nil {
		return nil, err
	}
	sd, _, err := descriptor()
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(clean)
	if err != nil {
		return nil, ErrPrivate
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err = windows.CreateDirectory(p, &sa); err != nil {
		return nil, privateError("root_create", err)
	}
	runtime.KeepAlive(sd)
	return OpenRoot(clean)
}

// OpenRoot rejects leaf/ancestor reparse redirection by comparing the opened
// handle's normalized final path. All subsequent file operations are relative
// to this handle, not another absolute path lookup.
func OpenRoot(path string) (*Root, error) {
	clean, err := localPath(path)
	if err != nil {
		return nil, err
	}
	expected, err := longPath(clean)
	if err != nil {
		return nil, err
	}
	sd, owner, err := descriptor()
	if err != nil {
		return nil, err
	}
	p, _ := windows.UTF16PtrFromString(clean)
	handle, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_TRAVERSE|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, privateError("root_open", err)
	}
	actual, err := finalPath(handle)
	if err != nil || !strings.EqualFold(expected, actual) {
		windows.CloseHandle(handle)
		return nil, privateError("root_path", err)
	}
	if _, err = info(handle, true); err != nil {
		windows.CloseHandle(handle)
		return nil, privateError("root_type", err)
	}
	if err = checkACL(handle, owner); err != nil {
		windows.CloseHandle(handle)
		return nil, privateError("root_acl", err)
	}
	return &Root{handle: handle, owner: owner, sd: sd}, nil
}
func (r *Root) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == windows.InvalidHandle {
		return nil
	}
	if r.writer != nil && !r.writer.closed {
		windows.CloseHandle(r.writer.handle)
		r.writer.closed = true
		r.writer = nil
	}
	err := windows.CloseHandle(r.handle)
	r.handle = windows.InvalidHandle
	if err != nil {
		return ErrPrivate
	}
	return nil
}
func fileName(name string) bool {
	if name == "" || len(name) > 128 || name == "." || name == ".." || strings.ContainsAny(name, "\\/:\x00") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	// Device names cannot become NT object aliases or alternate streams.
	first := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if first == "CON" || first == "PRN" || first == "AUX" || first == "NUL" || strings.HasPrefix(first, "COM") && len(first) == 4 || strings.HasPrefix(first, "LPT") && len(first) == 4 {
		return false
	}
	return true
}
func (r *Root) open(name string, access, disposition, share uint32) (windows.Handle, error) {
	if r.handle == windows.InvalidHandle || !fileName(name) {
		return windows.InvalidHandle, ErrPrivate
	}
	if err := checkACL(r.handle, r.owner); err != nil {
		return windows.InvalidHandle, err
	}
	text, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, ErrPrivate
	}
	attrs := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: r.handle, ObjectName: text, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: r.sd}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, &attrs, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, share, disposition, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_WRITE_THROUGH, 0, 0)
	runtime.KeepAlive(text)
	runtime.KeepAlive(r.sd)
	if err != nil {
		return windows.InvalidHandle, privateError("relative_open", err)
	}
	if _, err = info(handle, false); err != nil {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, privateError("file_type", err)
	}
	if err = checkACL(handle, r.owner); err != nil {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, privateError("file_acl", err)
	}
	return handle, nil
}
func (r *Root) read(name string, max int64) ([]byte, error) {
	if max < 1 || max > MaxBytes {
		return nil, ErrPrivate
	}
	// A published atomic writer can still hold its write handle while flushing
	// and closing. Retry only that transient sharing window, never ACL/I/O or
	// reparse failures, and keep read handles excluding in-place data writes.
	deadline := time.Now().Add(time.Second)
	var handle windows.Handle
	var err error
	for {
		handle, err = r.open(name, windows.GENERIC_READ, windows.FILE_OPEN, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE)
		if err == nil {
			break
		}
		var busy *stateError
		if !errors.As(err, &busy) || busy.stage != "relative_open" || busy.code != uint32(windows.ERROR_SHARING_VIOLATION) || !time.Now().Before(deadline) {
			return nil, err
		}
		time.Sleep(2 * time.Millisecond)
	}
	f := os.NewFile(uintptr(handle), "private-state")
	defer f.Close()
	size, err := f.Stat()
	if err != nil || size.Size() > max {
		return nil, ErrPrivate
	}
	value, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(value)) > max {
		return nil, ErrPrivate
	}
	return value, nil
}
func (r *Root) Read(name string, max int64) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.read(name, max)
}

// Only an actual missing leaf is absence. ACL/reparse/I/O errors stay errors.
func (r *Root) ReadOptional(name string, max int64) ([]byte, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, err := r.read(name, max)
	var missing *stateError
	if errors.As(err, &missing) && missing.stage == "relative_open" && missing.code == uint32(windows.ERROR_FILE_NOT_FOUND) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

// CreateNew never overwrites an existing state file. Atomic replacement/cache
// commit is intentionally not provided by this foundation API yet.
func (r *Root) CreateNew(name string, value []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(value) > MaxBytes {
		return ErrPrivate
	}
	handle, err := r.open(name, windows.GENERIC_WRITE, windows.FILE_CREATE, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(handle), "private-state")
	defer f.Close()
	if _, err = f.Write(value); err != nil {
		return ErrPrivate
	}
	if f.Sync() != nil {
		return ErrPrivate
	}
	if f.Close() != nil {
		return ErrPrivate
	}
	return nil
}
func (r *Root) Lock() (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.writer != nil && !r.writer.closed {
		return nil, ErrPrivate
	}
	handle, err := r.open(".state.lock", windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_OPEN_IF, 0)
	if err != nil {
		return nil, err
	}
	owned := &stateLock{handle: handle}
	r.writer = owned
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !owned.closed {
			windows.CloseHandle(owned.handle)
			owned.closed = true
		}
		if r.writer == owned {
			r.writer = nil
		}
	}, nil
}
