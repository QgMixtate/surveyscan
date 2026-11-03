// Package contracts embeds API/schema metadata, never Web UI assets.
package contracts

import "embed"

//go:embed openapi.json wire.schema.json compatibility.json state-machines.json
var Files embed.FS
