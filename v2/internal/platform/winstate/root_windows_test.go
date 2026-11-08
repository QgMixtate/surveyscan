//go:build windows

package winstate

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestPrivateRootRoundtripBoundsAndNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	root, err := CreateRoot(path)
	if err != nil {
		t.Fatal("private root create", err)
	}
	defer root.Close()
	value := []byte("canary-private-state")
	if err = root.CreateNew("profile.json", value); err != nil {
		t.Fatal("private create", err)
	}
	actual, err := root.Read("profile.json", 128)
	if err != nil || string(actual) != string(value) {
		t.Fatal("private roundtrip failed")
	}
	if root.CreateNew("profile.json", []byte("replacement")) == nil {
		t.Fatal("existing state overwritten")
	}
	actual, err = root.Read("profile.json", 128)
	if err != nil || string(actual) != string(value) {
		t.Fatal("failed create changed original bytes")
	}
	if _, err = root.Read("profile.json", 1); err == nil {
		t.Fatal("read limit ignored")
	}
	if root.CreateNew("oversized", make([]byte, MaxBytes+1)) == nil {
		t.Fatal("write limit ignored")
	}
	for _, name := range []string{"../escape", "..", `a\b`, "state:stream", "NUL", "COM1", "tail.", "tail ", "canary\n"} {
		if root.CreateNew(name, value) == nil {
			t.Fatal("unsafe file name accepted")
		}
	}
	if _, err = CreateRoot(path); err == nil {
		t.Fatal("existing root silently adopted")
	}
}

func TestStateLockHelperProcess(t *testing.T) {
	if os.Getenv("SURVEYSCAN_WINSTATE_LOCK_HELPER") != "1" {
		return
	}
	root, err := OpenRoot(os.Getenv("SURVEYSCAN_WINSTATE_ROOT"))
	if err != nil {
		os.Exit(2)
	}
	defer root.Close()
	unlock, err := root.Lock()
	if err != nil {
		os.Exit(3)
	}
	unlock()
	os.Exit(0)
}
func TestExclusiveStateLockAcrossProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	root, err := CreateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	unlock, err := root.Lock()
	if err != nil {
		t.Fatal("first lock", err)
	}
	defer unlock()
	child := func() int {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "-test.run=^TestStateLockHelperProcess$")
		cmd.Env = append(os.Environ(), "SURVEYSCAN_WINSTATE_LOCK_HELPER=1", "SURVEYSCAN_WINSTATE_ROOT="+path)
		err = cmd.Run()
		if err == nil {
			return 0
		}
		if failure, ok := err.(*exec.ExitError); ok {
			return failure.ExitCode()
		}
		t.Fatal("helper unavailable")
		return -1
	}
	if child() != 3 {
		t.Fatal("second process acquired state lock or could not open root")
	}
	unlock()
	if child() != 0 {
		t.Fatal("lock did not release")
	}
}
func setDACL(t *testing.T, path, sddl string, protected bool) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal("test descriptor")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal("test DACL")
	}
	info := windows.DACL_SECURITY_INFORMATION
	if protected {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.SECURITY_INFORMATION(info), nil, nil, acl, nil) != nil {
		t.Fatal("test DACL update")
	}
}
func TestUnsafeDACLRejectedWithoutRepair(t *testing.T) {
	for _, mode := range []string{"everyone-read", "unprotected", "null"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			root, err := CreateRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if root.CreateNew("state.json", []byte("canary-private")) != nil {
				t.Fatal("fixture write")
			}
			base := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + root.owner + ")"
			switch mode {
			case "everyone-read":
				setDACL(t, path, base+"(A;;GR;;;WD)", true)
			case "unprotected":
				setDACL(t, path, base, false)
			case "null":
				if windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil) != nil {
					t.Fatal("null test DACL")
				}
			}
			if _, err = OpenRoot(path); err == nil {
				t.Fatal("unsafe directory adopted")
			}
			if _, err = root.Read("state.json", 128); err == nil {
				t.Fatal("ACL drift ignored on held root")
			}
		})
	}
}
func TestReparseAndHardlinkAreRejected(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "state")
	root, err := CreateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if root.CreateNew("original", []byte("canary-private")) != nil {
		t.Fatal("fixture create")
	}
	if err = os.Link(filepath.Join(path, "original"), filepath.Join(path, "hardlink")); err != nil {
		t.Fatal("hardlink fixture unavailable")
	}
	if _, err = root.Read("original", 128); err == nil {
		t.Fatal("multiple-link file accepted")
	}
	if err = os.Remove(filepath.Join(path, "hardlink")); err != nil {
		t.Fatal("hardlink fixture cleanup")
	}
	if _, err = root.Read("original", 128); err != nil {
		t.Fatal("single-link fixture not readable")
	}
	if err = os.Symlink(filepath.Join(path, "original"), filepath.Join(path, "alias")); err != nil {
		t.Fatal("file reparse fixture unavailable")
	}
	if _, err = root.Read("alias", 128); err == nil {
		t.Fatal("leaf reparse followed")
	}
	// Root leaf points to the same safe descriptor; final-path/attribute checks
	// must reject the alias rather than relying only on target ACL correctness.
	rootAlias := filepath.Join(parent, "root-alias")
	if err = os.Symlink(path, rootAlias); err != nil {
		t.Fatal("root reparse fixture unavailable")
	}
	if alias, err := OpenRoot(rootAlias); err == nil {
		alias.Close()
		t.Fatal("root alias accepted")
	}
	// Existing private root beneath an aliased parent exercises ancestor reparse.
	container := filepath.Join(parent, "container")
	if err = os.Mkdir(container, 0700); err != nil {
		t.Fatal(err)
	}
	nested, err := CreateRoot(filepath.Join(container, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer nested.Close()
	containerAlias := filepath.Join(parent, "container-alias")
	if err = os.Symlink(container, containerAlias); err != nil {
		t.Fatal("ancestor reparse fixture unavailable")
	}
	if alias, err := OpenRoot(filepath.Join(containerAlias, "state")); err == nil {
		alias.Close()
		t.Fatal("ancestor alias accepted")
	}
}

func TestPrivateErrorsNeverExposePathsOrArbitraryMessages(t *testing.T) {
	err := privateError("canary-private-path", errors.New("canary-private-key"))
	if !errors.Is(err, ErrPrivate) || strings.Contains(err.Error(), "canary") {
		t.Fatal("private diagnostic leak")
	}
}

// Для администратора каталог доступен только SYSTEM и Administrators: так состояние, подготовленное
// администратором, принимает и служба под LocalSystem. Обычный пользователь проверяется отдельно.
func TestAdministratorRootHasNoUserSpecificEntry(t *testing.T) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	if !enabledAdministrator(token) {
		t.Skip("current token is not an enabled administrator")
	}
	path := filepath.Join(t.TempDir(), "state")
	root, err := CreateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatal("dacl", err)
	}
	seen := map[string]bool{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			t.Fatal("ace")
		}
		seen[(*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()] = true
	}
	if len(seen) != 2 || !seen["S-1-5-18"] || !seen["S-1-5-32-544"] {
		t.Fatal("administrator root must grant only SYSTEM and Administrators", seen)
	}
	unlock, err := root.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err = root.AtomicReplace("probe", []byte("x")); err != nil {
		t.Fatal("files created under the administrator root must pass the same trust check", err)
	}
	if data, err := root.Read("probe", 8); err != nil || string(data) != "x" {
		t.Fatal("read back", err)
	}
}
