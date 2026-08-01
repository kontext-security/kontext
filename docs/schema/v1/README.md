# Managed-stream ledger batch payload schema, version 1

This directory contains the JSON Schema for the body the managed daemon emits.
It makes the payload visible without reconstructing it from the upload code,
and makes a change to that payload a reviewable diff.

`ledger-batch-v1.json` is the body of `POST /api/v1/authorization-ledger/batches`
— agent sessions, authorization actions, and receipts drained from the local
store, plus the batch envelope.

## Consuming it

Draft-07. Validate the request body as a whole; the schema is at the root of the
file, with no `$ref`s to resolve. Enable `date-time` format assertions —
timestamps are RFC 3339 and the schema relies on format checking to reject
impossible values.

The schema is **strict**: an unexpected field is a failure in the CLI's
documented payload shape. It describes this CLI; it is not the server's ingest
schema and does not prove what a server accepts or rejects.

## Versioning

The directory name is the payload-schema version, not a CLI release and not the
HTTP API version. `/api/v1/` versions the API independently. This directory
changes when the documented shape emitted by the CLI changes incompatibly — a
removed or renamed field, a newly required field, a narrowed type, or a new
enum value. Adding an optional field does not change it.

How the backend supports, negotiates, and retires payload versions is a server
contract concern and is intentionally not defined here.

`schema_version` inside the payload identifies the emitted record schema
(`authorization-ledger-v1`) and is pinned by this schema.

## Maintenance

Update the schema alongside intentional exporter changes.
`internal/managedstream/wirecontract_test.go` captures a real upload and
validates it against this file. The schema is maintained in this repository; it
is not generated from the server's ingest definition.
