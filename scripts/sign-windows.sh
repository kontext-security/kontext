#!/usr/bin/env bash
# Signs Windows programs and installers in place with jsign.
#
#   scripts/sign-windows.sh FILE...
#
# WINDOWS_SIGNING says how:
#   off, or unset     nothing is signed; the files are left as they are.
#   artifact-signing  Azure Artifact Signing, with a timestamp. Needs
#                     WINDOWS_SIGNING_ENDPOINT (<region>.codesigning.azure.net),
#                     WINDOWS_SIGNING_ACCOUNT, WINDOWS_SIGNING_PROFILE and an
#                     access token in WINDOWS_SIGNING_TOKEN.
#   test              a throwaway certificate, to exercise this path on pull
#                     requests. Needs WINDOWS_SIGNING_TEST_KEYSTORE and
#                     WINDOWS_SIGNING_TEST_PASSWORD. Never for a release.
#
# JSIGN_JAR names the jsign jar. Secrets are read by jsign from the
# environment, so they are on no command line and in no log. Any other value
# of WINDOWS_SIGNING, a missing setting or a failed signature ends with an
# error: a file is either signed as asked or the build stops.
set -euo pipefail

fail() { echo "error: $*" >&2; exit 1; }
need() { for name in "$@"; do [[ -n "${!name:-}" ]] || fail "WINDOWS_SIGNING=$mode needs $name"; done; }

mode="${WINDOWS_SIGNING:-off}"
[[ $# -gt 0 ]] || fail "no file to sign"
for file in "$@"; do [[ -f "$file" ]] || fail "$file is not a file"; done

# Certificates of Azure Artifact Signing live for three days, so a signature
# without a timestamp would stop being valid with them.
timestamp=(--tsaurl http://timestamp.acs.microsoft.com --tsmode RFC3161 --tsretries 5 --tsretrywait 10)
describe=(--name Kontext --url https://kontext.security)

case "$mode" in
  off)
    exit 0
    ;;
  artifact-signing)
    need JSIGN_JAR WINDOWS_SIGNING_ENDPOINT WINDOWS_SIGNING_ACCOUNT WINDOWS_SIGNING_PROFILE WINDOWS_SIGNING_TOKEN
    store=(--storetype TRUSTEDSIGNING
      --keystore "$WINDOWS_SIGNING_ENDPOINT"
      --storepass env:WINDOWS_SIGNING_TOKEN
      --alias "$WINDOWS_SIGNING_ACCOUNT/$WINDOWS_SIGNING_PROFILE")
    ;;
  test)
    need JSIGN_JAR WINDOWS_SIGNING_TEST_KEYSTORE WINDOWS_SIGNING_TEST_PASSWORD
    store=(--storetype PKCS12
      --keystore "$WINDOWS_SIGNING_TEST_KEYSTORE"
      --storepass env:WINDOWS_SIGNING_TEST_PASSWORD
      --alias kontext-test)
    ;;
  *)
    fail "unknown WINDOWS_SIGNING '$mode' (off, artifact-signing or test)"
    ;;
esac

[[ -f "$JSIGN_JAR" ]] || fail "JSIGN_JAR $JSIGN_JAR is not a file"
java -jar "$JSIGN_JAR" sign "${store[@]}" "${timestamp[@]}" "${describe[@]}" --replace "$@"
echo "signed ($mode): $*"
