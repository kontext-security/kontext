# JSON contract

Two commands emit machine-readable output that is consumed by tooling built
**outside this repository** — currently the `kontext-management` menu bar app:

```bash
kontext profile ls --json
kontext doctor --json
```

Treat their output as an interface, not an implementation detail.

## Why this file exists

The menu bar app used to live in this repo, on the theory that co-location would
keep the two sides in step. It did not. A field (`allow_http_loopback`) was added
to the doctor report and the consumer's model silently never decoded it — nothing
failed, because JSON decoders are lenient by design, so a missing field is
invisible rather than loud.

What actually protects the contract is a test that fails when the shape changes.
That works regardless of which repository the consumer lives in, which is why the
consumer was subsequently moved out.

## What is pinned

`cmd/kontext/json_contract_test.go` pins the **key set** of each payload against a
golden file in `cmd/kontext/testdata/`. Values are not pinned — paths, pids, and
versions are machine-specific — but adding, removing, or renaming a field fails
the test.

To change a contract deliberately:

```bash
UPDATE_GOLDEN=1 go test ./cmd/kontext/ -run JSONContract
```

Update the golden file in the same commit as the change, and say in the commit
message whether it is:

- **additive** — a new field. Safe: consumers ignore unknown fields.
- **breaking** — a removed or renamed field, or a changed type or meaning.
  Consumers need updating, and an older consumer will silently lose that value.

## Guarantees

- **Unknown fields are ignored by consumers**, so additive changes are safe.
- **Absent optional fields are normal.** Anything with `omitempty` in Go is absent
  when empty; consumers must treat every such field as optional rather than
  failing to decode.
- **`doctor --json` exits zero even when unhealthy.** Health is read from the
  `healthy` field. A non-zero exit would force consumers to interpret both a
  status code and a document that already says the same thing. It cannot be
  combined with `--fix`.
- **Neither command performs network I/O**, and `profile ls --json` never touches
  the keychain. Both are safe for a GUI to poll. Do not add keychain access to
  `profile ls`: a background process prodding the login keychain on a timer earns
  a stream of authorization prompts.

## Version skew

A consumer may be paired with an older CLI than it expects. A CLI that predates
profiles fails with `unknown command "profile"`, which consumers should detect
and report as "CLI too old" rather than as a generic failure — a bare error there
sends people looking in the wrong place.

There is no version negotiation. The contract is append-mostly, and the golden
tests make removals deliberate.
