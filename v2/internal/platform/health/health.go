package health

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type Check func(context.Context) error

func Handler(checks ...Check) http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, status int, value string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": value})
	}
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, "ok") })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if len(checks) == 0 {
			reply(w, 503, "unavailable")
			return
		}
		for _, check := range checks {
			if err := check(ctx); err != nil {
				reply(w, 503, "unavailable")
				return
			}
		}
		reply(w, 200, "ok")
	})
	return mux
}
func Bao(addr string) Check {
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr+"/v1/sys/health", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		var state struct {
			Initialized *bool `json:"initialized"`
			Sealed      *bool `json:"sealed"`
		}
		if response.StatusCode != 200 {
			return io.ErrUnexpectedEOF
		}
		if err = json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&state); err != nil {
			return err
		}
		if state.Initialized == nil || state.Sealed == nil || !*state.Initialized || *state.Sealed {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
}
