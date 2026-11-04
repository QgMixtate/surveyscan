package buildinfo

import (
	"encoding/json"
	"io"
	"runtime"
)

var Version = "0.0.0-c12"
var Revision = "unknown"

func Print(w io.Writer, component string) error {
	stage := "C11 Linux agent with TLS renewal"
	if component == "collector" {
		stage = "C11 durable HTTPS relay with TLS renewal"
	}
	if component == "server" {
		stage = "C11 scoped OpenBao and machine lifecycle"
	}
	if component == "cli" {
		stage = "C12 human API client"
	}
	return json.NewEncoder(w).Encode(map[string]any{"component": component, "version": Version, "revision": Revision, "go_version": runtime.Version(), "stage": stage, "inventory_implemented": component == "agent"})
}
