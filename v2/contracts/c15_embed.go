package contracts

import "embed"

// C15Files contains the isolated draft inventory contract. Embedding it does not
// enable observation 1.2 in the existing upload/relay/registry handlers.
//
//go:embed c15.schema.json
var C15Files embed.FS
