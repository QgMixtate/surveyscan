package buildinfo

import (
	"encoding/json"
	"io"
	"runtime"
)

var Version = "0.0.0-c07"
var Revision = "unknown"

func Print(w io.Writer, component string) error {
	stage := "C04 scaffold"
	if component == "collector" {
		stage = "C07 HTTPS relay"
	}
	if component == "server" {
		stage = "C07 center/registry"
	}
	return json.NewEncoder(w).Encode(map[string]any{"component": component, "version": Version, "revision": Revision, "go_version": runtime.Version(), "stage": stage, "inventory_implemented": false})
}
