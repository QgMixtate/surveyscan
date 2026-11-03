package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthAndNoErrorLeak(t *testing.T) {
	for _, tc := range []struct {
		name   string
		checks []Check
		want   int
	}{{"missing", nil, 503}, {"ready", []Check{func(context.Context) error { return nil }}, 200}, {"failed", []Check{func(context.Context) error { return errors.New("SECRET") }}, 503}} {
		t.Run(tc.name, func(t *testing.T) {
			h := Handler(tc.checks...)
			for path, want := range map[string]int{"/health/live": 200, "/health/ready": tc.want, "/api/v1/assets": 404} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
				if w.Code != want || strings.Contains(w.Body.String(), "SECRET") {
					t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
				}
			}
		})
	}
}
func TestBaoRequiresUnsealedInitialized(t *testing.T) {
	for _, tc := range []struct {
		body string
		code int
		ok   bool
	}{{`{"initialized":true,"sealed":false}`, 200, true}, {`{"initialized":true,"sealed":true}`, 200, false}, {`{}`, 200, false}, {`{"initialized":true}`, 200, false}, {`not-json`, 200, false}, {`{"initialized":true,"sealed":false}`, 503, false}} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/health" {
				t.Error("wrong path")
			}
			w.WriteHeader(tc.code)
			_, _ = w.Write([]byte(tc.body))
		}))
		err := Bao(s.URL)(context.Background())
		s.Close()
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.body, err)
		}
	}
}
