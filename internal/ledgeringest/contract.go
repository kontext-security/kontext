// Package ledgeringest pins the published ledger-ingest v1 wire contract.
//
// The bundle under docs/contracts/ledger-ingest/v1 is vendored verbatim from
// the published server artifact and is never edited here: the manifest digest
// below is the single pin, and contract_test.go re-verifies every file
// against the manifest so any local edit or partial re-vendor fails CI. This
// replaces maintaining a CLI-authored schema mirror by hand — the CLI
// consumes the published contract and tests its producer behavior against
// it, mirroring how internal/ledgerfact pins the decision-fact corpus.
//
// To move to a new contract release, re-vendor the whole bundle and update
// ContractRelease and ManifestDigest together in one commit.
package ledgeringest

// BundleDir is the repository-relative location of the vendored bundle.
const BundleDir = "docs/contracts/ledger-ingest/v1"

// ContractRelease identifies the vendored artifact release. It must equal
// the `release` field of the bundle manifest.
const ContractRelease = "1.0.0"

// BatchVersion is the clean v1 ledger-batch envelope marker. It identifies
// the batch form only — never a parser selector, and it does not version
// session, action, or receipt records independently.
const BatchVersion = "v1"

// ManifestDigest is the SHA-256 over the raw bytes of the bundle's
// manifest.json. The manifest in turn digests every other file in the
// bundle, so this one constant pins the entire vendored contract.
const ManifestDigest = "d41836c21b482e7824ae62c716a5d3f183db0d6bdfc69d608f45e88e73f0cad6"
