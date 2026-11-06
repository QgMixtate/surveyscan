package access

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLoginDiagnosticNeverExportsErrorOrUntrustedStage(t *testing.T) {
	var output bytes.Buffer
	err := fmt.Errorf("SQL/password/session canary-private: %w", context.DeadlineExceeded)
	recordLoginFailure(&output, context.Background(), err, "canary-private-stage", 6*time.Second, 5500*time.Millisecond)
	if strings.Contains(output.String(), "canary") || strings.Contains(output.String(), "password") {
		t.Fatal("private error/stage exported")
	}
	var diagnostic map[string]any
	if err := json.Unmarshal(output.Bytes(), &diagnostic); err != nil {
		t.Fatal(err)
	}
	if len(diagnostic) != 6 || diagnostic["stage"] != "unknown" || diagnostic["reason"] != "deadline_exceeded" || diagnostic["verify_ms"] != float64(5500) {
		t.Fatal("incorrect safe diagnostic")
	}
}

func TestLoginDiagnosticSkipsExpectedFailures(t *testing.T) {
	for _, err := range []error{nil, ErrAuth, ErrLimit, ErrInvalid, ErrForbidden, fmt.Errorf("private: %w", ErrAuth)} {
		var output bytes.Buffer
		recordLoginFailure(&output, context.Background(), err, "password_verify", time.Second, time.Second)
		if output.Len() != 0 {
			t.Fatal("expected auth result produced unavailable event")
		}
	}
	for _, item := range []struct {
		err    error
		reason string
	}{{context.Canceled, "request_cancelled"}, {errors.New("private dependency credentials"), "dependency_unavailable"}} {
		var output bytes.Buffer
		recordLoginFailure(&output, context.Background(), item.err, "session_begin", time.Second, time.Second)
		if !strings.Contains(output.String(), item.reason) || strings.Contains(output.String(), "credentials") {
			t.Fatal("unexpected diagnostic category")
		}
	}
}
