//go:build windows

package winstate

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

func TestAtomicReplacementRequiresLockAndPreservesUnsafeTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	root, err := CreateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if root.AtomicReplace("profile", []byte("new")) == nil {
		t.Fatal("replacement allowed without exclusive state lock")
	}
	if _, present, err := root.ReadOptional("absent", 64); err != nil || present {
		t.Fatal("missing optional file not distinguished", err)
	}
	unlock, err := root.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err = root.AtomicReplace("profile", []byte("old")); err != nil {
		t.Fatal("initial atomic creation", err)
	}
	if err = root.AtomicReplace("profile", []byte("new")); err != nil {
		t.Fatal("atomic replace", err)
	}
	data, err := root.Read("profile", 64)
	if err != nil || string(data) != "new" {
		t.Fatal("replacement bytes", err)
	}
	// A missing leaf is optional; an unsafe existing leaf is never absence.
	wide := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + root.owner + ")(A;;GR;;;WD)"
	setDACL(t, filepath.Join(path, "profile"), wide, true)
	if _, _, err = root.ReadOptional("profile", 64); err == nil {
		t.Fatal("unsafe optional leaf ignored")
	}
	if root.AtomicReplace("profile", []byte("replacement")) == nil {
		t.Fatal("unsafe existing leaf silently replaced")
	}
}

func TestAtomicRenameSharingFailurePreservesTargetAndCleansStage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	root, err := CreateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	unlock, err := root.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err = root.AtomicReplace("profile", []byte("original")); err != nil {
		t.Fatal(err)
	}
	name, _ := windows.UTF16PtrFromString(filepath.Join(path, "profile"))
	held, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal("sharing fixture")
	}
	if root.AtomicReplace("profile", []byte("changed")) == nil {
		windows.CloseHandle(held)
		t.Fatal("rename ignored a non-delete-sharing reader")
	}
	windows.CloseHandle(held)
	data, err := root.Read("profile", 64)
	if err != nil || string(data) != "original" {
		t.Fatal("failed rename altered old state")
	}
	files, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".tmp-") {
			t.Fatal("failed operation did not clean its stage")
		}
	}
}

func TestAtomicReadersSeeWholeOldOrNewData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	writer, err := CreateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	unlock, err := writer.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	a := bytes.Repeat([]byte("A"), 32768)
	b := bytes.Repeat([]byte("B"), 32768)
	if err = writer.AtomicReplace("profile", a); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	failures := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(done)
		for i := 0; i < 40; i++ {
			next := a
			if i%2 == 0 {
				next = b
			}
			if err := writer.AtomicReplace("profile", next); err != nil {
				failures <- err
				return
			}
		}
	}()
	for {
		data, err := reader.Read("profile", 65536)
		if err != nil {
			t.Fatal("concurrent snapshot read", err)
		}
		if !bytes.Equal(data, a) && !bytes.Equal(data, b) {
			t.Fatal("torn state visible")
		}
		select {
		case <-done:
			wg.Wait()
			select {
			case err := <-failures:
				t.Fatal("concurrent replace", err)
			default:
			}
			return
		default:
		}
	}
}

func TestAtomicCrashHelperProcess(t *testing.T) {
	point := os.Getenv("SURVEYSCAN_WINSTATE_CRASH_POINT")
	if point == "" {
		return
	}
	root, err := OpenRoot(os.Getenv("SURVEYSCAN_WINSTATE_ROOT"))
	if err != nil {
		os.Exit(2)
	}
	unlock, err := root.Lock()
	if err != nil {
		os.Exit(3)
	}
	defer unlock()
	defer root.Close()
	replaceHook = func(stage string) {
		if stage == point {
			os.Exit(44)
		}
	}
	if root.AtomicReplace("profile", []byte("new-complete")) != nil {
		os.Exit(4)
	}
	os.Exit(5)
}
func TestAtomicProcessCrashKeepsWholeStateAndReleasesLock(t *testing.T) {
	for _, point := range []string{"before_rename", "after_rename"} {
		t.Run(point, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			root, err := CreateRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			unlock, err := root.Lock()
			if err != nil {
				t.Fatal(err)
			}
			if err = root.AtomicReplace("profile", []byte("old-complete")); err != nil {
				t.Fatal(err)
			}
			unlock()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child := exec.Command(binary, "-test.run=^TestAtomicCrashHelperProcess$")
			child.Env = append(os.Environ(), "SURVEYSCAN_WINSTATE_CRASH_POINT="+point, "SURVEYSCAN_WINSTATE_ROOT="+path)
			err = child.Run()
			failure, ok := err.(*exec.ExitError)
			if !ok || failure.ExitCode() != 44 {
				t.Fatal("crash fixture did not hit declared point")
			}
			unlock, err = root.Lock()
			if err != nil {
				t.Fatal("OS retained dead-process lock", err)
			}
			defer unlock()
			data, err := root.Read("profile", 64)
			if err != nil {
				t.Fatal(err)
			}
			expected := "old-complete"
			if point == "after_rename" {
				expected = "new-complete"
			}
			if string(data) != expected {
				t.Fatal("crash exposed partial or wrong generation")
			}
		})
	}
}
