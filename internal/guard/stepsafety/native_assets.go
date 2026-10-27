//go:build !nostepsafetymodel

package stepsafety

import "embed"

// nativeAssets holds the checkpoint, tokenizer and classifiers. They are about
// 213 MB of the binary; the nostepsafetymodel tag leaves them out.
//
//go:embed model/native/*.gz
var nativeAssets embed.FS

// modelEmbedded reports whether this build carries the model; tests that
// need it skip without it.
const modelEmbedded = true
