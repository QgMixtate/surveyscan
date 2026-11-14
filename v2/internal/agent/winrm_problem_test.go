package agent

import (
	"errors"
	"fmt"
	"testing"

	"github.com/QgMixtate/surveyscan/v2/internal/remote/winrminv"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/winrmkrb"
)

func TestWinRMProblemCodes(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{nil, ""},
		{fmt.Errorf("%w: dial tcp: i/o timeout", winrminv.ErrNet), "host_unreachable"},
		{winrminv.ErrAuth, "auth_failed"},
		{winrminv.ErrAccess, "access_denied"},
		{winrminv.ErrTLS, "tls_failed"},
		{&winrmkrb.CodedError{Code: "kerberos_login:KRB_AP_ERR_SKEW"}, "kerberos_login:KRB_AP_ERR_SKEW"},
		{errors.New("something else"), ""},
	} {
		if got := WinRMProblem(c.err); got != c.want {
			t.Fatalf("%v: %q, want %q", c.err, got, c.want)
		}
	}
}
