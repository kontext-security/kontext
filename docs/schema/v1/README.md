# Ledger batch wire contract, version 1

This directory contains the JSON Schema for what the managed daemon uploads to
the Kontext backend. It exists so you can see exactly what leaves an endpoint
without reading the upload code, and so any change to that payload is a visible
diff rather than an implementation detail.

`ledger-batch-v1.json` is the body of `POST /api/v1/authorization-ledger/batches`
— agent sessions, authorization actions, and receipts drained from the local
store, plus the batch envelope.

## Consuming it

Draft-07. Validate the request body as a whole; the schema is at the root of the
file, with no `$ref`s to resolve. Enable `date-time` format assertions —
timestamps are RFC 3339 and the schema relies on format checking to reject
impossible values.

The contract is **strict**: the server rejects a batch containing any field the
schema does not declare. Additive changes to the payload are therefore not
backward compatible on their own; they arrive with a wire version.

## Versioning

The directory name is the wire version, not a CLI release. It changes only when
a payload change is observable to an already-installed daemon — a removed or
renamed field, a newly required field, a narrowed type, or a new enum value a
receiver must understand. Adding an optional field does not change it.

Older wire versions keep working for as long as the support window states;
retirement is announced before it takes effect.

`schema_version` inside the payload identifies the record contract
(`authorization-ledger-v1`) and is pinned by this schema.

## Do not edit by hand

The file is generated from the server's ingest definition, so it cannot drift
from what is actually enforced. `internal/managedstream/wirecontract_test.go`
validates real uploaded batches against it, which is what keeps this directory
honest rather than aspirational.
