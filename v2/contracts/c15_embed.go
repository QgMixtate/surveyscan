package contracts

import "embed"

// C15Files contains the isolated draft inventory contract. Embedding it does not
// enable observation 1.2 in the existing upload/relay/registry handlers.
//
//go:embed c15.schema.json
var C15Files embed.FS

// C15API12Files is the additive server read contract, separate from agent payloads.
//
//go:embed c15-records.schema.json c15.openapi.json
var C15API12Files embed.FS

// Transport12Files is an opt-in draft; existing ingest still uses frozen C03.
//
//go:embed c15-transport.schema.json
var Transport12Files embed.FS

//go:embed c15-capabilities.schema.json
var InventoryCapabilityFiles embed.FS
