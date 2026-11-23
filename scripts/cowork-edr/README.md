# Internal Cowork EDR test (ENG-1109)

Run the test from Claude Desktop on an Apple silicon Mac. Cowork executes the
sensor inside its local Linux ARM64 VM; the Mac hosts the signed archive and
device profile. No separate container test is required for this milestone.

**Current integration gap (Claude Desktop 6.28899.6):** installation and the
shared sensor socket work in the real VM, and staging receives heartbeats.
The tested local session runs Claude Code 2.1.330 on the Mac (`hostLoopMode:
true`, CLI cwd `/private/var/empty`) while Bash runs as a separate user in the
VM. The VM's managed hook drop-in therefore does not automatically receive
those tool events. Automatic collection is not complete. Resolve an approved
host-to-sensor hook path or a VM process-observation design before treating
this as a working Cowork collection integration. A manually submitted
synthetic hook tests transport only and must not be counted as automatic
Cowork event capture.

This prototype uses a dedicated staging enrollment token. It always allows tool
execution, ignores remote enforcement settings, and starts no model, compactor,
Codex proxy, browser bridge, agent discovery or transcript-recovery workers.
Only SessionStart, SessionEnd, PreToolUse, PostToolUse and PostToolUseFailure
hooks reach the ledger runtime. Session users cannot supply transcript files or
user prompts for the daemon to read. Ordinary hook metadata and authorization
actions/receipts use the existing ledger uploader; turns and usage recovery do
not run. Test with synthetic activity only.

## Build and sign

Create a separate revocable token in the internal staging dashboard. Save it in
a private file (0600) outside the repository; do not put it in shell arguments,
`.args`, environment configuration committed to Git, or logs.

```sh
python3 scripts/cowork-edr/build.py \
  --cloud-url https://api.staging.kontext.security \
  --token-file /absolute/private/test-token \
  --source-revision BASE_COMMIT \
  --output /absolute/private/package-directory
```

The build uses `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`,
`-tags=nostepsafetymodel`, `-trimpath` and `-buildvcs=false`. The manifest records
the base revision, Go/module source hash and binary hash. Preserve the source
patch alongside the build when testing an uncommitted change. Reuse the
generated installation ID with `--installation-id` to reproduce identical bytes
for the same source, token and configuration. The archive contains a private
test credential and must stay restricted to the internal test.

```sh
gcloud auth login --account=jens@kontext.security
cd scripts/cowork-edr/sign
go test ./...
go run . --archive /absolute/private/package.tar.gz \
  --public-key ../approved-public-key.asc --key-version 1
```

The signer verifies that KMS version 1 matches approved fingerprint
`BBBDFE996C02A0E482F116A6DE2037B4E5CF93B9`. The OpenPGP library creates a binary
detached signature over the archive with a 30-day lifetime and no notation or
policy URI. Only the final SHA-256 digest reaches KMS; key material never leaves
KMS. Request/response CRC32C and the returned ECDSA signature are checked. The
finished OpenPGP signature is verified locally before writing `.sig`.

## Mac deployment

Verify `.sig` with the approved public key before staging the package. Run
`sudo sh scripts/cowork-edr/stage-mac.sh /absolute/private/package.tar.gz`.
It installs root-owned, admin-readable files below
`/Library/Application Support/KontextCoworkEDR` and rejects writable ancestors.
The internal archive is not readable by ordinary non-admin users.

```sh
python3 scripts/cowork-edr/mac-profile.py --output /absolute/path/test.mobileconfig
```

The profile contains only the package path and vendor ID, scoped to System.
The partner guide documents MDM deployment. For this one-Mac QA test, manually
installing the same System profile supplies forced device preferences; verify
that Claude actually recognizes them through its diagnostics. A user preference
written with `defaults write` does not replace this device policy.

Quit Claude fully and reopen it. In Settings → Cowork, enable **Only on this
computer** before creating a new task. Confirm the task URL uses `local_` and
the task displays "Only on this computer". A `cse_` cloud task does not test VM
hook delivery, even when a connected Mac is shown. Use one tool
call such as:

```sh
mkdir -p /tmp/kontext-edr-eng1109-empty && ls -la /tmp/kontext-edr-eng1109-empty
```

Inside the VM, install.sh copies all files out of the unpack directory, creates
the unprivileged `kontext-cowork` account, and starts the sensor with systemd or
`setpriv` without capabilities. Startup must authenticate to staging before the
installer returns success. Re-running it stops and replaces its own service.
Failure removes its hook drop-in and returns nonzero. It never installs OS
packages or downloads dependencies.

The cross-user socket is `/run/kontext-cowork/sensor.sock` (0666), inside a
service-owned directory (0755) that other session users cannot modify. Config,
credential and state are private. The root-owned hook drop-in is
`/etc/claude-code/managed-settings.d/95-kontext-cowork.json`.

Record the Cowork session ID and the matching action in staging. Generate a
Claude diagnostic report via Help → Troubleshooting → Generate Diagnostic
Report, and inspect `cowork-edr-integration.txt`. Installer success alone does
not prove that hooks were delivered or that the event reached staging.

## Removal

Stop the test sensor inside the VM by running its root removal entry point:
`/usr/local/lib/kontext-cowork/uninstall.sh`. It stops only its own process and
removes its own hook file, unit, binary, credentials and state. The locked
service account remains and can be reused on reinstall. If a session cannot
run a root command, deliver a separately signed removal package through the
same approved installer mechanism; do not bypass VM privileges.

Remove the System profile from Mac Device Management and remove the staged
package directory as administrator. Removing the profile alone does not remove
an already installed VM sensor. Finally revoke the dedicated staging token by
its ENG-1109 label and remove credential-bearing archives and the private token
file. Do not revoke a shared Mac enrollment token.

## Checks

```sh
go test -tags=nostepsafetymodel ./internal/coworksensor \
  ./internal/localruntime ./internal/runtimehost ./internal/managedstream
cd scripts/cowork-edr/sign && go test ./...
```

The sensor test runs its core runtime on the Mac against an isolated local API
fixture. It checks authentication, rejected credentials, the real hook socket,
ledger upload, fixed observe mode, cross-user socket permissions and the
restricted request scope. The production command itself accepts Linux only.
