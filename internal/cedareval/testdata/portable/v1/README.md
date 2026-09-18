# Portable Cedar fixtures v1

These JSON files are the canonical portable corpus for request-contract v1.

Request-contract v1 interprets JSON numbers using binary64 semantics, matching
`JSON.parse`. Lexically different number tokens that decode to the same
binary64 value are therefore the same policy input; callers that require exact
textual precision must send a string.

`authorization-v1.json`, `context-errors-v1.json`,
`evaluation-errors-v1.json`, and `hashing-v1.json` are copied byte-for-byte
from the shared contract. Do not recreate equivalent vectors independently in
another runtime. The evaluation-error corpus asserts diagnostic presence and
count, never unstable engine error text.

The hashing corpus pins the semantic seven-term
`kontext:cedar-deployment:v2` identity. It contains no storage revision or
endpoint operational configuration.

The decision-contract, decision-mapping, and evaluation-errors v2 files pin
decision-contract v2: evaluation errors allow execution while completed denies,
unavailable approvals, unresolved principals, and unready enforcement still deny.
They use request-contract v1 inputs and are copied byte-for-byte from the shared
contract. The v1 files remain pinned as historical evidence of the earlier
error-deny behavior.

`TestPortableFixtureProvenance` pins the contract version and SHA-256 digest of
every portable JSON file. Update the version and digests only when intentionally
adopting a reviewed contract revision.
