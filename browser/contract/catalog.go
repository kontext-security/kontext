// Package contract embeds the browser contract's catalog, so the daemon checks
// visits against the same list the extension is built from.
package contract

import _ "embed"

// CatalogJSON is catalog.json: the AI web apps a visit may name.
//
//go:embed catalog.json
var CatalogJSON []byte
