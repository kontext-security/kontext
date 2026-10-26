//go:build nostepsafetymodel

package stepsafety

import "embed"

// nativeAssets is empty in a build without the model, for hosts that cannot
// carry the full binary. Loading then fails, so New returns an unavailable
// evaluator and health reports "unavailable"; decisions do not depend on it.
var nativeAssets embed.FS

// modelEmbedded reports whether this build carries the model; tests that
// need it skip without it.
const modelEmbedded = false
