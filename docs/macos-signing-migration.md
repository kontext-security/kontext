# Company macOS signing

Work for [ENG-888](https://linear.app/cobrowser/issue/ENG-888). Activation is blocked until Apple membership, certificates, notarization and upgrades are verified. Keep Michel's membership and existing release credentials intact.

## Failure cases to check before implementation

- An unset selector must preserve the current release path, including unsigned development builds.
- Selecting the company must fail if its Team ID or any signing/notary credential is absent. It must never fall back to the personal certificate.
- Reject unknown selectors, the personal Team ID, another legal entity, a different team, a non-Application certificate, expired certificates, corrupt PKCS#12 data and an incorrect password.
- Never print credentials or extract a private key. Temporary files must be private and removed on failure.
- A signed customer package must contain a validly signed binary and use a Developer ID Installer certificate from that same team. Preserve unsigned local staging.
- Signing, notarization, packaging and stapling change hashes. Generate manifests only from the final package.
- Preserve the binary identifier, installation paths, package receipt identifiers, configuration, installation identity and tokens across an overlay upgrade and rollback.
- Existing privacy grants and customer allowlists can reject a new team. Validate them before fleet rollout, including Intel and Apple Silicon.

## Verification record

As of 3 November 2026:

- The installed Homebrew cask 1.17.1 is signed by `Developer ID Application: Michel Osswald (L2LV5YHMJ3)`. Its identifier is `kontext`, its hardened runtime is enabled, and its designated requirement includes `certificate leaf[subject.OU] = L2LV5YHMJ3`.
- The initial default-keychain inventory had no usable Developer ID Application identity. Company identities were subsequently imported into the separate company keychain described below. Apple Development certificates are not release certificates.
- The authenticated company membership is active: entity `CoBrowser Technology GmbH`, enrolled as `Organization`, Team ID `GB932D44Y3`, renewal date 4 November 2027. Separate G2 Developer ID Application and Developer ID Installer certificates have been issued for that team, both expiring 3 December 2027. Both match their separate encrypted private keys and pass native certificate trust checks. Password-protected PKCS#12 exports are held privately on the signing Mac; both identities are imported into a dedicated encrypted company keychain without changing the default keychain or personal identities.
- Apple displays a notice to accept the latest Developer Program License Agreement by 14 November 2026. Certificate resources are currently accessible. Agreement acceptance remains a separate approval step. App Store Connect first-use Terms of Service V100 were accepted with Michel's explicit approval; the company account is accessible. Organization API access and its internal-team-use agreement were approved. A team key named `Kontext macOS notarization`, Developer role, was created; native `notarytool` authentication and company-keychain credential storage succeeded.
- Repository secret metadata confirms the five existing `MACOS_*` signing/notary secrets in `kontext-security/kontext`. Their encrypted values and ownership were not read. The new company Application PKCS#12 and export-password secrets are configured in both CLI and staging repositories. All three company notarization secrets are configured in both repositories as well. The one-time API key download was moved into private storage, backed up with encryption, then removed from plaintext storage after setup. `MACOS_COMPANY_TEAM_ID=GB932D44Y3` is configured in the CLI and staging repositories; `MACOS_SIGNING_PROFILE` remains unset. No existing secrets were changed.
- The 18 fixture checks use disposable self-signed certificates. Additional checks against the real company exports passed native certificate trust and preflight acceptance/rejection. GoReleaser snapshot sign-only builds for both Darwin architectures passed native company signature, authority and TeamIdentifier verification. The actual fixture PKG also passed native company Installer signature verification.
- Side-by-side `whoami --json` checks on this Mac authenticated with the installed personal binary and company arm64 candidate using existing local credentials, returning the same workspace/person. This did not install an upgrade, switch profiles or reset tokens; other customer ACLs remain unverified.
- Both current Darwin architectures passed Apple notarization and native company signature/notarization verification in [candidate run 41640118372](https://github.com/kontext-security/kontext/actions/runs/41640118372), binary source `2633a0af`. The exact downloaded archives also passed local checksums, source binding and CDHash matching against Apple's Accepted tickets.
- [Cask run 41648455399](https://github.com/kontext-security/kontext/actions/runs/41648455399) passed personal-signed 1.17.1 installation, company upgrade and personal rollback on macOS 15 Apple Silicon, macOS 15 Intel and macOS 26. Artifacts retain signer/Team transitions, notarization, quarantine removal, version/hash restoration and launchd `--version` results. These checks do not establish authenticated daemon restart or customer FDA/EDR continuity.
- The earlier local company-signed fixture PKG passed Apple notarization, stapling, staple validation, Installer signature, Gatekeeper installation assessment and final manifest hash verification. Hosted native PKG upgrade/rollback passed on all three Mac images against the accepted CI binaries. See the authenticated native validation below for the separate real-backend check.
- Nonpublishing validation changes only `wait: true` to `wait: false` in a temporary staging-config copy, then requires native Apple lookup to succeed for each architecture. This avoids GoReleaser's 20-minute authenticated-wait cap. Interrupted binaries/archives are retained separately for diagnosis. Production and staging release configurations remain unchanged.

| Company certificate | SHA-256 fingerprint | Expiry (UTC) |
| --- | --- | --- |
| Developer ID Application | `96:A6:86:1F:E9:EB:02:BA:1B:26:32:72:1C:F9:E3:7D:A4:2F:51:A8:B5:45:F9:7F:11:F0:82:BE:7B:09:EA:DA` | 3 December 2027 10:31:59 |
| Developer ID Installer | `F2:DC:A7:A3:DE:2C:88:EA:91:64:27:49:ED:04:75:5E:18:2B:09:85:8A:7F:3E:23:F5:9C:2E:31:B4:AD:7A:EE` | 3 December 2027 10:33:58 |


## Release ownership and current path

The starting checkout, historically called `kontext`, now points to `kontext-security/kontext-cloud`. It serves deployment manifests and uploaded artifacts; it does not sign them. The local `kontext-cli` checkout now points to the public `kontext-security/kontext` repository. Its `main` push runs `.github/workflows/release-please.yml`, creates the release, then GoReleaser 2.18 builds, signs and notarizes the two Darwin binaries on Linux through Quill. `.goreleaser.yaml` and `.goreleaser.staging.yaml` use the same `MACOS_*` inputs. The signer comes from the PKCS#12 certificate, not a hardcoded GoReleaser Team ID.

The release job renders the Homebrew formula and, when signing is enabled, the cask in `kontext-security/homebrew-tap`. Their URLs and checksums do not pin the signer. The cask installs the original signed binary; the source formula can produce a locally signed binary and is not a company signature validation path. `internal/managedobserve/updater.go` delegates updates to Homebrew without pinning a Developer ID.

`kontext-security/kontext-staging-releases` has a separate dispatch workflow that checks out trusted tooling from CLI `main`, builds a requested source ref, publishes a private prerelease and updates the staging formula. Before this migration it had no signing secrets and used GoReleaser 2.13. The companion PR upgrades it to 2.18 and makes company signing opt-in. Company-signed staging accepts only commits reachable from CLI `origin/main`; arbitrary refs remain available in the unsigned mode. Do not dispatch this workflow during validation because it publishes a release.

Customer packages are assembled on macOS in `kontext-security/enterprise-deployments`, `shared/macos/pkg/build-pkg.sh`, also called by `make customer-build-pkg`. It copies the supplied binary without re-signing it. `--sign` previously optionally called `productsign`, with no team consistency check or package notarization. The companion PR checks both signers, adds `--notary-profile`, and writes manifests after notarization and stapling. Package signing is local, not a hidden customer-package CI pipeline. Customer-specific findings and rollout instructions live in that private repository's `shared/macos/signing-migration.md`.

`kontext-management` currently builds and ad-hoc signs its local management app. It is not this published CLI/PKG pipeline. This change introduces no new app, entitlement, provisioning profile, updater protocol or Cowork sensor key.

## Apple account and certificate setup

1. In [Apple Developer](https://developer.apple.com/account), select **CoBrowser Technology GmbH**, then Membership details. Record the exact legal name, Organization entity type, active paid membership, Team ID, your role and renewal date. If the company team does not exist or is not active, finish a separate organization enrollment with the company Account Holder. Do not convert Michel's individual membership. A EUR 99 checkout, an Apple Development identity, a D-U-N-S record or an App Store Connect invitation alone is insufficient evidence.
2. In that team's Certificates, Identifiers & Profiles, inventory Developer ID Application and Developer ID Installer certificates, including expiry and certificate fingerprint. Confirm that their private keys are available to the release operator. A downloadable `.cer` without its matching private key cannot sign. Do not revoke or replace existing personal certificates.
3. If either identity is absent, the company Account Holder creates it using a CSR whose private key remains on a controlled signing Mac. Use separate Developer ID Application and Developer ID Installer identities from the company team. If macOS rejects a modern OpenSSL PKCS#12 during native import, create a temporary compatibility export with `-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1`, import it into the isolated company keychain, then remove that temporary export. Keep the modern encrypted export for GoReleaser. Import the downloaded certificates on the CSR Mac. Export only the company Application certificate and its matching private key as a password-protected PKCS#12 for GoReleaser. Keep the Installer identity on the package-signing Mac, or import its encrypted PKCS#12 into a dedicated CI keychain if packaging later moves to CI. Never commit exports, paste them into chat, or print them in logs.
4. In company App Store Connect, use a **team** API key with the **Developer** role and notarization access and record its issuer UUID and key ID. Use a team key for this pipeline, which supplies an issuer UUID. Current Xcode `notarytool` also supports individual keys without an issuer, but that is a different credential flow and is not configured here. Keep the `.p8` in secret storage. The issuer UUID is not the Apple Team ID. The signed validation build is the actual authorization check.

Apple documents [Developer ID certificate types and creation roles](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/), [finding the Team ID](https://developer.apple.com/help/glossary/team-id/), and [team API keys](https://developer.apple.com/documentation/appstoreconnectapi/creating-api-keys-for-app-store-connect-api). GoReleaser documents its [PKCS#12 and notarization inputs](https://goreleaser.com/customization/notarize/).

## CI configuration and activation

Add these **new repository secrets** in `kontext-security/kontext`. Repeat in `kontext-security/kontext-staging-releases` before enabling signed staging. Keep the existing five personal `MACOS_*` secrets intact.

| Secret | Value |
| --- | --- |
| `MACOS_COMPANY_SIGN_P12` | Single-line base64 company Developer ID Application PKCS#12, containing exactly one signing identity |
| `MACOS_COMPANY_SIGN_PASSWORD` | PKCS#12 export password |
| `MACOS_COMPANY_NOTARY_ISSUER_ID` | Company team API issuer UUID |
| `MACOS_COMPANY_NOTARY_KEY_ID` | Company team API key ID |
| `MACOS_COMPANY_NOTARY_KEY` | Single-line base64 company `.p8` |

Set repository variable `MACOS_COMPANY_TEAM_ID` to the verified company Team ID. Leave `MACOS_SIGNING_PROFILE` unset while preparing credentials. Production continues using the existing secrets; staging stays unsigned. The new validation workflow always selects company credentials and fails if anything is missing or the certificate's legal name/OU differs. It checks expiry and certificate identity, not Apple trust or possession of a working private key. The signed-build verification supplies those checks.

For example, from a trusted shell with local paths already set, upload files without showing their contents:

```bash
openssl base64 -A -in "$COMPANY_APPLICATION_P12" |
  gh secret set MACOS_COMPANY_SIGN_P12 --repo kontext-security/kontext
openssl base64 -A -in "$COMPANY_NOTARY_P8" |
  gh secret set MACOS_COMPANY_NOTARY_KEY --repo kontext-security/kontext
# Run these separately; gh prompts for each value without echoing it.
gh secret set MACOS_COMPANY_SIGN_PASSWORD --repo kontext-security/kontext
gh secret set MACOS_COMPANY_NOTARY_ISSUER_ID --repo kontext-security/kontext
gh secret set MACOS_COMPANY_NOTARY_KEY_ID --repo kontext-security/kontext
gh variable set MACOS_COMPANY_TEAM_ID --body "$COMPANY_TEAM_ID" --repo kontext-security/kontext
```

Never set the selector before the five secrets and verified Team ID exist. The workflow names each secret explicitly and gates the company and legacy references separately. An absent company secret cannot fall back to a personal value. An empty selector or `legacy` preserves the current path; other values fail preflight.

## Validation and rollout order

1. Merge the CLI and package-preparation PRs with selectors unset. Merge the staging PR only after CLI `main` includes `scripts/check-macos-signing.sh`. Merging preparation is not migration completion.
2. Verify company membership and both identities, then install the new company CI secrets and Team ID. Keep the existing certificates, secrets, packages and manifests available for rollback.
3. Dispatch **Validate company macOS signing** on the reviewed CLI commit. It has read-only repository permission, runs `release --skip=publish`, and uploads two Darwin archives plus certificate identity, TeamIdentifier, designated requirement, Apple notarization lookup, checksums and source SHA. It does not publish a GitHub release, push tags or update Homebrew. Apple notarization uploads the candidate binaries to Apple. Run only reviewed code because the workflow receives company signing credentials.
4. Build and notarize a customer candidate from the downloaded validation binary using the private runbook. Confirm the PKG's Installer identity and payload Application identity belong to the same company team. Retain the notarization receipt, staple verification, final hash and package receipt metadata.
5. Customer changes are conditional: if an existing privacy or security rule pins the personal Team ID/certificate, add the exact company requirement **before** the new binary and retain the old rule during rollback. No such deployed rule was found in the available customer inputs; do not require a general policy reconfiguration or invent a profile.
6. On disposable or designated test Macs, test an existing personal-signed cask upgrade and the managed PKG overlay upgrade, separately on Intel and Apple Silicon. Verify daemon restart, hooks, authenticated API access, credential retrieval, file scanning/FDA, installation identity and rollback to the known-good personal package without uninstalling. Capture redacted logs, version/identity checks and customer policy evidence. Fixture overlays do not prove those OS behaviors.
7. After those gates pass, enable staging with its `MACOS_SIGNING_PROFILE=company` and a reviewed source commit. A later staging run publishes a private prerelease. Recheck its signer. Change production `MACOS_SIGNING_PROFILE` to `company` only for the agreed first company release, after all active customer policies are ready. This task does not activate either selector or publish anything.
8. Release normally, package the exact released binary with the company Installer identity, then upload the final stapled PKG and checksum using the established deployment path. Never replace old release assets or rewrite historical manifests. Publish customer instructions with the exact verified Team ID, captured new designated requirement, final hashes and rollback version. Retain old policies until the rollback period ends. Any later removal of personal credentials is separate work.

Rollback of CI selection means returning `MACOS_SIGNING_PROFILE` to its previous value, leaving all credentials in place. Endpoint rollback means reinstalling the previous package with its old policy still present, not uninstalling or deleting tokens. After a public company release, assess version ordering before trying a Homebrew downgrade; restoring CI selection alone does not downgrade installed endpoints.

## Compatibility findings and remaining checks

| Area | Confirmed from code or artifact | Still requires OS/customer verification |
| --- | --- | --- |
| Code identity | The old designated requirement pins the personal OU. New certificates change that requirement; keeping identifier `kontext` does not preserve the old DR. | Capture and approve the actual new DR. Check stored privacy grants and application control. |
| Updates | Homebrew updates use package metadata and checksums, with no Kontext signer pin. Managed installs use the stable `/usr/local/bin/kontext` and package receipt `security.kontext.<customer>.managed-observe`. | Gatekeeper acceptance, daemon restart and signed personal-to-company upgrades on both architectures. There is no inspected Sparkle-style updater trust key to rotate. |
| Credentials | CLI reads/writes generic passwords through Apple's `/usr/bin/security` tool. No direct `SecItem` or Team ID-based keychain access group was found in this release path. Managed packages use the existing root-owned install-token file. | Existing keychain item ACLs and interactive prompts may vary. Verify login-keychain retrieval after upgrade and rollback without logging token values. No blanket keychain reset or token rotation is justified by the code. |
| PPPC/FDA | A requirement containing OU `L2LV5YHMJ3` will reject the new team. Apple describes code requirements as the identity used for tracked grants in [TN2206](https://developer.apple.com/library/archive/technotes/tn2206/). | Customer profiles are not in these repositories. Determine actual paths, identifiers, `CodeRequirement` and `StaticCode` settings with IT; do not assume an installed profile or that an unmanaged user's grant transfers. |
| EDR/XDR | No customer Team ID allowlist is checked into the inspected package inputs. | Update an existing signer/hash pin only if the customer has one. No customer security-setting change is confirmed by this investigation. |
| Installer | `--sign` now rejects a mismatched binary team/legal entity. Company mode requires package notarization and stapling before manifest generation. | A successful signed/notarized PKG, trust-chain evaluation, receipt-preserving install and rollback. |

Repeatable local checks:

```bash
python3 scripts/test-macos-signing.py /tmp/kontext-signing-checks.json
shellcheck scripts/check-macos-signing.sh
actionlint .github/workflows/release-please.yml .github/workflows/validate-company-signing.yml .github/workflows/ci.yml
```

These checks and the private package fixtures do not complete the migration. Membership, company Team ID and certificate/key matching are verified. Company credentials and native signing-keychain setup are complete. Signed CLI notarization and hosted cask upgrade/rollback are verified. Hosted native PKG results, authenticated daemon upgrades and customer policy verification remain release gates.

## Hosted cask upgrade check

The existing Homebrew Install workflow is the entry point for the same hosted Mac setup used by the personal-signing rollout. Candidate validation must fail for a missing/mismatched archive checksum, an unexpected baseline signer, an invalid company signature or TeamIdentifier, absent Apple notarization, quarantine remaining on the installed binary, a cask upgrade that leaves the old binary installed, launchd execution failure, or rollback that does not restore the personal binary. Run on the existing macOS 15 Apple Silicon, macOS 15 Intel and macOS 26 runners, retaining commands, signatures, requirements and hashes as artifacts. Use a separate local validation tap/binary name so this does not publish a release or change the public tap. These hosted checks do not establish customer PPPC/FDA, EDR or existing login-keychain ACL continuity.

To run the signed candidate and hosted cask upgrade/rollback checks from the draft branch without merging or publishing:

```bash
gh workflow run homebrew-install.yml --repo kontext-security/kontext \
  --ref feat/eng-888-company-signing -f company_signing=true
```

This opt-in dispatch reuses Validate company macOS signing, then tests the candidate artifact against the pinned personal-signed 1.17.1 baseline on the three existing hosted Mac runners. Its `company-upgrade-*` artifacts contain baseline, company and rollback signatures, requirements, notarization checks, hashes, cask versions and launchd output. The ordinary scheduled/pull-request installation path remains the default.


The asynchronous validation must still fail if either native notarization lookup never succeeds, a submission is rejected, signature/team checks fail or the source archive cannot be extracted. Retained interrupted artifacts are diagnostic candidates, not approved builds. Upgrade jobs require the validation workflow to succeed. The temporary configuration changes only `wait: true` to `wait: false`; release configurations remain intact.


### Reusing an accepted candidate after a test failure

A test-only rerun must reject a foreign repository or workflow, a non-manual source run, a missing/failed company validation job, an absent or expired artifact, a source SHA mismatch, malformed or inconsistent archive versions and checksum/signature/notarization failures. Reusing an artifact must not receive signing credentials or build/submit a new candidate. Cask and PKG upgrade results are independent gates; a cask fixture failure does not invalidate an already successful binary validation or establish package upgrade success.


To rerun only cask upgrades against an already validated artifact, use:

```sh
gh workflow run homebrew-install.yml --repo kontext-security/kontext \
  --ref feat/eng-888-company-signing -f company_signing=true \
  -f candidate_run_id=41640118372
```

This skips the signing job and receives no signing secrets. It checks the original validation job, source SHA, archive version and checksums before native signature/notarization and upgrade/rollback checks. The source run's other jobs may have failed; their results remain separate gates. The artifact retains the original source and version even if test code is fixed on the PR branch.

Both current architectures in `41640118372` are Apple Accepted and passed native signature/notarization validation. Cask run `41648455399` passed all three hosted Mac images after the URL-rewrite fix. Production release configuration and signing selectors remain unchanged.


### Rollback to 1.17.1

The current candidate's Claude managed-hooks drop-in includes an owned saved-output read permission that 1.17.1's stricter hooks-only ownership check does not recognize. Native rollback by direct overlay failed for that reason, independently of the Apple Team ID change. After verifying the retained rollback PKG/hash, run `sudo /usr/local/bin/kontext hooks remove --scope system` with the still-installed current CLI, then overlay the old PKG. The old postinstall recreates its supported hooks. Do not run the application uninstall script, delete installation/token data, remove general policy or force an unknown ownership check.

This procedure passed native PKG upgrade/rollback on macOS 15 Apple Silicon, macOS 15 Intel and macOS 26, preserving identity/configuration and a separate policy file. The [rebuilt Intel fixture](https://github.com/kontext-security/enterprise-deployments/actions/runs/41665250594) is Apple Accepted and passed real staple validation and Gatekeeper after recovering from the injected CloudKit transport error. The authenticated launchd transition now also passes on the local Apple Silicon Mac, as detailed below. No signer-pinned customer rule was found in the available inputs; customer edits remain conditional. See the [private package runbook](https://github.com/kontext-security/enterprise-deployments/pull/38).

## Authenticated native validation (4 November 2026)

On Michel's Apple Silicon Mac, the exact accepted arm64 candidate (`2633a0af`, archive tag `0.0.0-signing.53.1`) passed personal 1.17.1 → company → company restart → personal rollback in an isolated native launchd job. Every phase authenticated through the unchanged existing login-Keychain reference, returned the same workspace/person and recorded a fresh successful staging-backend heartbeat. The installation identity and configuration remained byte-identical; rollback restored the exact baseline binary. The separate test job was removed, and the original development daemon PID, executable, profile pointer, configuration and inspected hook files stayed unchanged. This proves the local login-Keychain/daemon transition, not a customer-managed install-token file or Intel hardware authentication.

Twelve native `codesign -R` cases using the real signatures passed: a personal-only requirement rejects both company architectures, a company-only requirement rejects the personal baseline, and an additive rollout-window expression accepts all three while rejecting the ad-hoc control. These are compatibility checks, not deployed customer profiles. This Mac is not MDM-enrolled; its one user profile contains a family-controls content filter, not a PPPC grant. The inspected Katana XDR runbook lists paths/process/network only. No deployed signer pin or required customer policy edit is confirmed.

A local Katana-format package `1.17.2-signing.888.1`, with the real customer package ID/config and the same accepted CLI bytes, is also Apple Accepted (`baeae733-c4f5-4b52-9f32-ce3f3d8e5785`). Company Installer trust, staple, Gatekeeper, payload hash and token/identity exclusion passed. Its manifest remains draft with no storage URI. The full Addigy mimic also passed on this Apple Silicon Mac: pinned installer/condition checks, four company reinstalls (0/4 failures), authenticated production heartbeats on personal/company/rollback, same workspace/person, full token/identity preservation, exact rollback bytes and 0600 token ownership. Current-CLI owned-hook cleanup preceded rollback. Cleanup removed the test installation and restored the development daemon/profile/configuration; its doctor returned 0 and original staging authentication passed. Nothing is published and all signing selectors remain unset.

The Addigy mimic reused the matching identity from Michel's inactive production profile because its existing workspace credential is installation-bound. A fresh identity with that existing credential failed on the personal baseline too (HTTP 409); retaining the pair fixes the fixture without a token rotation or backend rebinding. During the temporary managed test, doctor warned about the intentionally preserved development hooks/proxy on this mixed host. That is separate from the successful native installer/authentication assertions; the restored development doctor is clean. Authenticated Intel hardware and an actual customer endpoint were not exercised.
