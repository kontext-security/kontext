#!/usr/bin/env bash
set -euo pipefail

fail() { echo "error: $*" >&2; exit 1; }

case "${MACOS_SIGNING_PROFILE:-}" in
  ""|legacy) ;;
  company)
    [[ "${MACOS_EXPECTED_TEAM_ID:-}" =~ ^[A-Z0-9]{10}$ ]] || fail "company signing requires MACOS_EXPECTED_TEAM_ID"
    [[ "$MACOS_EXPECTED_TEAM_ID" != L2LV5YHMJ3 ]] || fail "company signing cannot use the personal team"
    [[ -n "${MACOS_SIGN_P12:-}" ]] || fail "company signing certificate is missing"
    ;;
  *) fail "unknown MACOS_SIGNING_PROFILE" ;;
esac

[[ -n "${MACOS_SIGN_P12:-}" ]] || exit 0
for name in MACOS_SIGN_PASSWORD MACOS_NOTARY_ISSUER_ID MACOS_NOTARY_KEY_ID MACOS_NOTARY_KEY; do
  [[ -n "${!name:-}" ]] || fail "$name is missing for macOS signing"
done
[[ "${MACOS_SIGNING_PROFILE:-}" == company ]] || exit 0

# Inspect only the public certificate; never export the signing private key.
umask 077
signing_tmp="$(mktemp -d)"
trap 'rm -rf "$signing_tmp"' EXIT
printf '%s' "$MACOS_SIGN_P12" | openssl base64 -d -A > "$signing_tmp/identity.p12"
if ! openssl pkcs12 -in "$signing_tmp/identity.p12" -passin env:MACOS_SIGN_PASSWORD \
  -clcerts -nokeys -out "$signing_tmp/cert.pem" 2>/dev/null; then
  # Older exports use RC2, which OpenSSL 3 loads through its legacy provider.
  openssl pkcs12 -legacy -in "$signing_tmp/identity.p12" -passin env:MACOS_SIGN_PASSWORD \
    -clcerts -nokeys -out "$signing_tmp/cert.pem" 2>/dev/null || fail "cannot read signing certificate"
fi
[[ "$(grep -c 'BEGIN CERTIFICATE' "$signing_tmp/cert.pem")" == 1 ]] || fail "export exactly one signing identity"
openssl x509 -in "$signing_tmp/cert.pem" -checkend 0 -noout >/dev/null || fail "signing certificate has expired"
subject="$(openssl x509 -in "$signing_tmp/cert.pem" -noout -subject -nameopt sep_multiline,sname)"
[[ "$(sed -n 's/^ *OU=//p' <<< "$subject")" == "$MACOS_EXPECTED_TEAM_ID" ]] || fail "signing certificate has a different Team ID"
[[ "$(sed -n 's/^ *CN=//p' <<< "$subject")" == "Developer ID Application: CoBrowser Technology GmbH ($MACOS_EXPECTED_TEAM_ID)" ]] || fail "signing certificate is not the company Developer ID Application"
echo "Company certificate matches CoBrowser Technology GmbH and team $MACOS_EXPECTED_TEAM_ID"
