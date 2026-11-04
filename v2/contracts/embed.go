// Package contracts embeds API/schema metadata, never Web UI assets.
package contracts

import "embed"

//go:embed openapi.json wire.schema.json compatibility.json state-machines.json c09.schema.json c09.openapi.json c12.schema.json c12.openapi.json
var Files embed.FS
