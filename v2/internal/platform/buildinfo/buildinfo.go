package buildinfo

import (
	"encoding/json"
	"io"
	"runtime"
)

var Version = "0.0.0-c13"
var Revision = "unknown"
var Dirty = "unknown"

func Print(w io.Writer, component string) error {
	stage := "C12 Linux agent with profiles and diagnostics"
	if component == "collector" {
		stage = "C12 durable HTTPS relay with profiles and diagnostics"
	}
	if component == "server" {
		stage = "C12 scoped OpenBao, machine lifecycle and diagnostics"
	}
	if component == "cli" {
		stage = "C12 human API client"
	}
	return json.NewEncoder(w).Encode(map[string]any{"component": component, "version": Version, "revision": Revision, "source_dirty": Dirty, "go_version": runtime.Version(), "stage": stage, "inventory_implemented": component == "agent"})
}
