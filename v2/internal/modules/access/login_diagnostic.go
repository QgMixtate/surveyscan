package access

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// The diagnostic never encodes an error string, username, credential, query,
// remote address or response body. It preserves the original error semantics.
func recordLoginFailure(w io.Writer, ctx context.Context, err error, stage string, elapsed, verify time.Duration) {
	if err == nil || errors.Is(err, ErrAuth) || errors.Is(err, ErrLimit) || errors.Is(err, ErrInvalid) || errors.Is(err, ErrForbidden) {
		return
	}
	switch stage {
	case "rate", "user_lookup", "password_verify", "session_begin", "user_recheck", "active_sessions", "session_insert", "audit", "commit":
	default:
		stage = "unknown"
	}
	reason := "dependency_unavailable"
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		reason = "deadline_exceeded"
	} else if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		reason = "request_cancelled"
	}
	_ = json.NewEncoder(w).Encode(struct {
		Component string `json:"component"`
		Event     string `json:"event"`
		Reason    string `json:"reason"`
		Stage     string `json:"stage"`
		ElapsedMS int64  `json:"elapsed_ms"`
		VerifyMS  int64  `json:"verify_ms"`
	}{"access", "login_unavailable", reason, stage, elapsed.Milliseconds(), verify.Milliseconds()})
}
