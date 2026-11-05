package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapValidityRejectedBeforePrivateIO(t *testing.T) {
	for _, value := range []string{"0s", "169h"} {
		output := filepath.Join(t.TempDir(), "must-not-create")
		err := bootstrapIssuer([]string{"--config", "/missing-private-config", "--output-directory", output, "--server-validity", value})
		if err == nil || !strings.Contains(err.Error(), "validity") {
			t.Fatal("invalid certificate lifetime must fail before loading credentials", value, err)
		}
		if _, err = os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("invalid lifetime must not create issuer artifacts")
		}
	}
}
