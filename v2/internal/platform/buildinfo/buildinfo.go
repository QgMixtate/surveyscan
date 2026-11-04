package buildinfo

import (
	"encoding/json"
	"io"
	"runtime"
)

var Version = "0.0.0-c10"
var Revision = "unknown"

func Print(w io.Writer, component string) error {
	stage := "C08 Linux host agent"
	if component == "collector" {
		stage = "C10 durable HTTPS relay"
	}
	if component == "server" {
		stage = "C10 fenced import/registry"
	}
	return json.NewEncoder(w).Encode(map[string]any{"component": component, "version": Version, "revision": Revision, "go_version": runtime.Version(), "stage": stage, "inventory_implemented": component == "agent"})
}
