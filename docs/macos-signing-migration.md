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
- The local keychain has no usable Developer ID Application identity. Apple Development certificates are not release certificates.
- The authenticated Apple Developer portal shows `CoBrowser Technology GmbH (Pending)` under the company login. It does not yet offer Membership details or Certificates, Identifiers & Profiles. Company Team ID, active membership, certificate inventory and private-key availability remain unverified. The enrollment checkout shows EUR 99; payment alone does not prove activation.
- Repository secret metadata confirms the five existing `MACOS_*` signing/notary secrets in `kontext-security/kontext`. Their encrypted values and ownership were not read. There are no company signing secrets or selector variables yet. No secrets were changed.
- The fixture checks verify configuration and certificate parsing only. They use disposable self-signed certificates, not Apple identities. Signed builds, Apple acceptance and real upgrades remain release gates.

## Release ownership and current path

The starting checkout, historically called `kontext`, now points to `kontext-security/kontext-cloud`. It serves deployment manifests and uploaded artifacts; it does not sign them. The local `kontext-cli` checkout now points to the public `kontext-security/kontext` repository. Its `main` push runs `.github/workflows/release-please.yml`, creates the release, then GoReleaser 2.18 builds, signs and notarizes the two Darwin binaries on Linux through Quill. `.goreleaser.yaml` and `.goreleaser.staging.yaml` use the same `MACOS_*` inputs. The signer comes from the PKCS#12 certificate, not a hardcoded GoReleaser Team ID.

The release job renders the Homebrew formula and, when signing is enabled, the cask in `kontext-security/homebrew-tap`. Their URLs and checksums do not pin the signer. The cask installs the original signed binary; the source formula can produce a locally signed binary and is not a company signature validation path. `internal/managedobserve/updater.go` delegates updates to Homebrew without pinning a Developer ID.

`kontext-security/kontext-staging-releases` has a separate dispatch workflow that checks out trusted tooling from CLI `main`, builds a requested source ref, publishes a private prerelease and updates the staging formula. Before this migration it had no signing secrets and used GoReleaser 2.13. The companion PR upgrades it to 2.18 and makes company signing opt-in. Company-signed staging accepts only commits reachable from CLI `origin/main`; arbitrary refs remain available in the unsigned mode. Do not dispatch this workflow during validation because it publishes a release.

Customer packages are assembled on macOS in `kontext-security/enterprise-deployments`, `shared/macos/pkg/build-pkg.sh`, also called by `make customer-build-pkg`. It copies the supplied binary without re-signing it. `--sign` previously optionally called `productsign`, with no team consistency check or package notarization. The companion PR checks both signers, adds `--notary-profile`, and writes manifests after notarization and stapling. Package signing is local, not a hidden customer-package CI pipeline. Customer-specific findings and rollout instructions live in that private repository's `shared/macos/signing-migration.md`.

`kontext-management` currently builds and ad-hoc signs its local management app. It is not this published CLI/PKG pipeline. This change introduces no new app, entitlement, provisioning profile, updater protocol or Cowork sensor key.

## Apple account and certificate setup

1. In [Apple Developer](https://developer.apple.com/account), select **CoBrowser Technology GmbH**, then Membership details. Record the exact legal name, Organization entity type, active paid membership, Team ID, your role and renewal date. If the company team does not exist or is not active, finish a separate organization enrollment with the company Account Holder. Do not convert Michel's individual membership. A EUR 99 checkout, an Apple Development identity, a D-U-N-S record or an App Store Connect invitation alone is insufficient evidence.
2. In that team's Certificates, Identifiers & Profiles, inventory Developer ID Application and Developer ID Installer certificates, including expiry and certificate fingerprint. Confirm that their private keys are available to the release operator. A downloadable `.cer` without its matching private key cannot sign. Do not revoke or replace existing personal certificates.
3. If either identity is absent, the company Account Holder creates it using a CSR whose private key remains on a controlled signing Mac. Use separate Developer ID Application and Developer ID Installer identities from the company team. Import the downloaded certificates on the CSR Mac. Export only the company Application certificate and its matching private key as a password-protected PKCS#12 for GoReleaser. Keep the Installer identity on the package-signing Mac, or import its encrypted PKCS#12 into a dedicated CI keychain if packaging later moves to CI. Never commit exports, paste them into chat, or print them in logs.
4. In company App Store Connect, use a **team** API key with notarization access and record its issuer UUID and key ID. Individual API keys cannot use `notarytool`. Keep the `.p8` in secret storage. The issuer UUID is not the Apple Team ID. The signed validation build is the actual authorization check.

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

Never set the selector before the five secrets and verified Team ID exist. Selecting `company` chooses the company secret names first, so an absent secret cannot fall back to a personal value. An empty selector or `legacy` preserves the current path; other values fail preflight.

## Validation and rollout order

1. Merge the CLI and package-preparation PRs with selectors unset. Merge the staging PR only after CLI `main` includes `scripts/check-macos-signing.sh`. Merging preparation is not migration completion.
2. Verify company membership and both identities, then install the new company CI secrets and Team ID. Keep the existing certificates, secrets, packages and manifests available for rollback.
3. Dispatch **Validate company macOS signing** on the reviewed CLI commit. It has read-only repository permission, runs `release --skip=publish`, and uploads two Darwin archives plus certificate identity, TeamIdentifier, designated requirement, Apple notarization lookup, checksums and source SHA. It does not publish a GitHub release, push tags or update Homebrew. Apple notarization uploads the candidate binaries to Apple. Run only reviewed code because the workflow receives company signing credentials.
4. Build and notarize a customer candidate from the downloaded validation binary using the private runbook. Confirm the PKG's Installer identity and payload Application identity belong to the same company team. Retain the notarization receipt, staple verification, final hash and package receipt metadata.
5. Customer IT inventories PPPC/FDA, EDR/XDR, application control and any certificate/hash pins. Deploy their approved new requirement **before** the new binary. Retain the old requirement during the pilot and rollback window. Do not grant access to every executable signed by either team when a path/identifier-specific rule suffices.
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
| EDR/XDR | No customer Team ID allowlist is checked into the inspected package inputs. | Obtain actual publisher/team, certificate thumbprint, hash and process rules from every active fleet. Changes depend on their policy, not just macOS. |
| Installer | `--sign` now rejects a mismatched binary team/legal entity. Company mode requires package notarization and stapling before manifest generation. | A successful signed/notarized PKG, trust-chain evaluation, receipt-preserving install and rollback. |

Repeatable local checks:

```bash
python3 scripts/test-macos-signing.py /tmp/kontext-signing-checks.json
shellcheck scripts/check-macos-signing.sh
actionlint .github/workflows/release-please.yml .github/workflows/validate-company-signing.yml .github/workflows/ci.yml
```

These checks and the private package fixtures do not complete the migration. Missing inputs are an authenticated company membership view, verified company Team ID, working Application and Installer identities with private keys, company notarization credentials, and customer policy/upgrade evidence.
