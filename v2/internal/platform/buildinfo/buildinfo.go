package buildinfo

import (
	"encoding/json"
	"io"
	"runtime"
)

var Version = "0.0.0-c04"
var Revision = "unknown"

func Print(w io.Writer, component string) error {
	return json.NewEncoder(w).Encode(map[string]any{"component": component, "version": Version, "revision": Revision, "go_version": runtime.Version(), "stage": "C04 scaffold", "inventory_implemented": false})
}
