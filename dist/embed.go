// Package fritterwasm exposes the canonical Fritter WebAssembly module.
package fritterwasm

import _ "embed"

// Module contains the Fritter CLI compiled to WebAssembly.
//
//go:embed fritter.wasm
var Module []byte
