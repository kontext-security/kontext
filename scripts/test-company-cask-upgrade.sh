#!/usr/bin/env bash
set -euo pipefail

[[ "${GITHUB_ACTIONS:-}" == true ]] || { echo 'Run on a disposable GitHub macOS runner' >&2; exit 1; }
candidate="${1:?candidate artifact directory}"
version="${2:?candidate version}"
team="${MACOS_EXPECTED_TEAM_ID:?company Team ID}"
[[ "$team" =~ ^[A-Z0-9]{10}$ && "$team" != L2LV5YHMJ3 ]]
baseline=1.17.1
name=kontext-company-validation
tap_name=kontext/signing-validation
evidence="$RUNNER_TEMP/company-upgrade-evidence"
baseline_dir="$RUNNER_TEMP/personal-baseline"
mkdir -p "$evidence" "$baseline_dir"
case "$(uname -m)" in
  arm64) arch=arm64 ;;
  x86_64) arch=amd64 ;;
  *) exit 1 ;;
esac

cleanup() {
  launchctl bootout "gui/$(id -u)/security.kontext.signing-validation" 2>/dev/null || true
  brew uninstall --cask "$tap_name/$name" >/dev/null 2>&1 || true
  brew untap "$tap_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$candidate"
shasum -a 256 -c evidence/checksums.txt
gh release download "v$baseline" --repo kontext-security/kontext \
  -p checksums.txt -p "kontext_${baseline}_darwin_${arch}.tar.gz" -D "$baseline_dir"
archive="kontext_${baseline}_darwin_${arch}.tar.gz"
expected="$(awk -v name="$archive" '$2 == name {print $1}' "$baseline_dir/checksums.txt")"
[[ "$expected" =~ ^[a-f0-9]{64}$ ]]
[[ "$(shasum -a 256 "$baseline_dir/$archive" | awk '{print $1}')" == "$expected" ]]

brew tap-new --no-git "$tap_name"
tap="$(brew --repo "$tap_name")"
mkdir -p "$tap/Casks"
repo="${GITHUB_WORKSPACE:?}"
render() {
  local release_version="$1" directory="$2"
  "$repo/scripts/render-homebrew-cask.sh" "$release_version" "$directory/checksums.txt" |
    sed -e "s/^cask \"kontext\" do/cask \"$name\" do/" \
        -e "s/^  binary \"kontext\"$/  binary \"kontext\", target: \"$name\"/" \
        -e "s#https://github.com/kontext-security/kontext/releases/download/v#{version}#file://$directory#g" \
    > "$tap/Casks/$name.rb"
}

verify() {
  local phase="$1" expected_team="$2" expected_version="$3" binary
  binary="$(readlink -f "$(brew --prefix)/bin/$name")"
  codesign --verify --strict --all-architectures \
    -R="identifier kontext and anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$expected_team\"" "$binary"
  codesign -dv --verbose=4 "$binary" > "$evidence/$phase-signature.txt" 2>&1
  codesign -d -r- "$binary" > "$evidence/$phase-requirement.txt" 2>&1
  grep -Fx "TeamIdentifier=$expected_team" "$evidence/$phase-signature.txt"
  if [[ "$expected_team" == "$team" ]]; then
    grep -Fx "Authority=Developer ID Application: CoBrowser Technology GmbH ($team)" "$evidence/$phase-signature.txt"
  fi
  local accepted=false
  for _ in 1 2 3 4 5; do
    if codesign -vvvv -R=notarized --check-notarization "$binary" > "$evidence/$phase-notarization.txt" 2>&1; then
      accepted=true
      break
    fi
    sleep 15
  done
  [[ "$accepted" == true ]]
  if xattr -p com.apple.quarantine "$binary" >/dev/null 2>&1; then
    echo 'Cask left its binary quarantined' >&2
    return 1
  fi
  "$binary" --version | tee "$evidence/$phase-version.txt" | grep -F "kontext version $expected_version "
  shasum -a 256 "$binary" > "$evidence/$phase-binary.sha256"
  brew list --cask --versions "$name" > "$evidence/$phase-cask.txt"
  grep -Fx "$name $expected_version" "$evidence/$phase-cask.txt"

  local plist="$evidence/$phase.plist" out="$evidence/$phase-launchd.out" err="$evidence/$phase-launchd.err"
  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>security.kontext.signing-validation</string>
  <key>ProgramArguments</key><array><string>$binary</string><string>--version</string></array>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$out</string>
  <key>StandardErrorPath</key><string>$err</string>
</dict></plist>
PLIST
  launchctl bootstrap "gui/$(id -u)" "$plist"
  for _ in $(seq 30); do
    if grep -qF "kontext version $expected_version " "$out" 2>/dev/null; then break; fi
    sleep 1
  done
  launchctl bootout "gui/$(id -u)/security.kontext.signing-validation"
  grep -F "kontext version $expected_version " "$out"
  printf 'PASS %s: signature, team, notarization, cask version, quarantine and launchd\n' "$phase" >> "$evidence/results.txt"
}

render "$baseline" "$baseline_dir"
brew install --cask "$tap_name/$name"
verify personal L2LV5YHMJ3 "$baseline"
render "$version" "$candidate/dist"
brew upgrade --cask --no-ask "$tap_name/$name"
verify company "$team" "$version"
# Casks consider any different version outdated, including a controlled rollback.
render "$baseline" "$baseline_dir"
brew upgrade --cask --no-ask "$tap_name/$name"
verify rollback L2LV5YHMJ3 "$baseline"
cmp "$evidence/personal-binary.sha256" "$evidence/rollback-binary.sha256"
cp "$candidate/evidence/source-sha.txt" "$evidence/source-sha.txt"
sw_vers > "$evidence/macos.txt"
uname -m > "$evidence/architecture.txt"
