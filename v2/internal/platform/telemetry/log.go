package telemetry

import (
	"encoding/json"
	"io"
	"time"
)

// Only fixed event codes reach this encoder; no raw transport/SQL/target error strings.
func Log(w io.Writer, component, event string) {
	_ = json.NewEncoder(w).Encode(map[string]string{"at": time.Now().UTC().Format(time.RFC3339Nano), "component": component, "event": event})
}
