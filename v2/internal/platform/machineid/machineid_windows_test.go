//go:build windows

package machineid

import "testing"

func TestLocalMachineGuidIsValidAndStable(t *testing.T) {
	first, e := Local()
	if e != nil {
		t.Fatal(e)
	}
	second, e := Local()
	if e != nil || first != second || len(first) != 32 {
		t.Fatal("machine identity unstable or malformed", e)
	}
}
