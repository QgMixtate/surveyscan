package machineid

import "testing"

func TestNormalize(t *testing.T) {
	good := map[string]string{
		"0123456789abcdef0123456789abcdef":     "0123456789abcdef0123456789abcdef",
		" 0123456789ABCDEF0123456789ABCDEF\n":  "0123456789abcdef0123456789abcdef",
		"01234567-89AB-CDEF-0123-456789ABCDEF": "0123456789abcdef0123456789abcdef",
	}
	for in, want := range good {
		if got, e := normalize(in); e != nil || got != want {
			t.Fatal("normalize", in, got, e)
		}
	}
	for _, bad := range []string{"", "0123", "00000000000000000000000000000000", "00000000-0000-0000-0000-000000000000",
		"0123456789abcdef0123456789abcdeg", "01234567-89ab-cdef-0123-456789abcde", "0123456789abcdef0123456789abcdef00"} {
		if _, e := normalize(bad); e == nil {
			t.Fatal("accepted invalid identity", bad)
		}
	}
}
