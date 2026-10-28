#!/usr/bin/env bash
# Self-serve install and update E2E for a clean macOS runner.
#
# Proves, against a loopback stub API and a local copy of the Kontext tap:
#   A. A 1.16.1 cask install whose setup wrote the machine-wide (root) hook
#      files upgrades to the new build: the daemon restarts on it, adds hooks
#      in the home folder without any password prompt, and leaves the root
#      files untouched, so no hook runs twice.
#   B. The new daemon updates itself: a newer cask in the tap is installed by
#      the daemon's own updater and launchd restarts it on that version.
#   C. Self-heal: hooks removed from a home-folder file come back within a
#      minute, and the agent scan follows.
#   D. A fresh cask install plus `kontext setup` asks for no password, writes
#      hooks only in the home folder, and reports Cowork as not governed.
#   E. `hooks install --scope system` writes the same bytes as 1.16.1.
#
# usage: e2e-self-serve.sh <repo checkout> <artifact dir>
set -euo pipefail

repo="$(cd "$1" && pwd)"
art="$(mkdir -p "$2" && cd "$2" && pwd)"
here="$(cd "$(dirname "$0")" && pwd)"
exec > >(tee -a "$art/e2e.log") 2>&1

uid="$(id -u)"
prefix="$(brew --prefix)"
label=security.kontext.managed-observe
mlog="$HOME/Library/Logs/Kontext/managed-observe.log"
old=1.16.1 v1=9.0.1 v2=9.0.2
port=8787

step() { printf '\n== %s (%s)\n' "$*" "$(date -u +%H:%M:%S)"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; exit 1; }
wait_for() { # seconds, description, command...
  local secs="$1" what="$2"; shift 2
  for _ in $(seq "$secs"); do "$@" >/dev/null 2>&1 && { pass "$what"; return 0; }; sleep 1; done
  fail "$what (after ${secs}s)"
}
daemon_version() { grep -o "managed-observe daemon [^ ]* (pid [0-9]*) started" "$mlog" | tail -1 | awk '{print $3}'; }
hash_root() { for f in "/Library/Application Support/ClaudeCode/managed-settings.d/20-kontext.json" "/Library/Application Support/Cursor/hooks.json" /etc/codex/hooks.json; do [ -f "$f" ] && shasum -a 256 "$f"; done; true; }
count_kontext() { local n=0; [ -f "$1" ] && n="$(grep -c "kontext' hook" "$1" || true)"; echo "${n:-0}"; }

step "Stub API, sudo shim and prompt watcher"
# Every sudo a kontext command runs from this shell goes through this shim and
# is logged; the test's own setup steps call /usr/bin/sudo directly.
mkdir -p "$art/shim"
printf '#!/bin/sh\necho "$(date -u +%%H:%%M:%%S) sudo $*" >> "%s/sudo-calls.log"\nexec /usr/bin/sudo "$@"\n' "$art" > "$art/shim/sudo"
chmod +x "$art/shim/sudo"
: > "$art/sudo-calls.log"
export PATH="$art/shim:$PATH"
python3 "$here/stub_api.py" "$port" > "$art/stub-api.log" 2>&1 &
# Admin dialogs, plus sudo aimed at Kontext or agent hook files (the runner
# runs its own sudo jobs, e.g. provjobd, which are not ours).
( while :; do ps -axo pid=,command= | grep -E '(^|[ /])(osascript|security_authtrampoline|SecurityAgent) |(^|[ /])sudo (-v$|.*(kontext|ClaudeCode|Cursor|/etc/codex))' | grep -v grep | sed "s/^/$(date -u +%H:%M:%S) /"; sleep 0.2; done ) >> "$art/prompts.log" 2>/dev/null &
watcher=$!
finish() {
  kill "$watcher" 2>/dev/null || true
  cp "$mlog" "$art/managed-observe.log" 2>/dev/null || true
  "$prefix/bin/kontext" doctor > "$art/doctor-final.txt" 2>&1 || true
}
trap finish EXIT

step "Install Claude Code (native) for real hook calls"
curl -fsSL https://claude.ai/install.sh | bash >/dev/null
claude_bin="$HOME/.local/bin/claude"
"$claude_bin" --version
probes=0
claude_probe() { # label: one real Claude Code session with one Bash call, against the fake model
  probes=$((probes + 1))
  local id="toolu_e2e_$probes" work db n
  work="$(mktemp -d)"
  (cd "$work" && ANTHROPIC_API_KEY=sk-ant-e2e-not-real ANTHROPIC_BASE_URL="http://127.0.0.1:$port" \
    DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    "$claude_bin" -p "Use Bash to list this directory." --model claude-sonnet-4-5 --allowedTools Bash) > "$art/claude-$probes.txt" 2>&1 || true
  sleep 3
  n=0
  while IFS= read -r db; do
    n=$((n + $(sqlite3 -readonly "$db" "select count(*) from authorization_actions where canonical_event_type = 'request.decided' and tool_use_id = '$id'")))
  done < <(find "$HOME/Library/Application Support/Kontext" -name guard.db -print)
  [ "$n" = 1 ] && pass "$1: one real Claude Code tool call, one hook decision ($id)" || fail "$1: $id has $n hook decisions"
}

step "Build $v1 and $v2 from $(git -C "$repo" rev-parse --short HEAD)"
arch="$(uname -m | sed 's/x86_64/amd64/')"
mkdir -p "$art/dist"
: > "$art/dist/checksums.txt"
for v in "$v1" "$v2"; do
  d="$(mktemp -d)"
  (cd "$repo" && CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$v" -o "$d/kontext" ./cmd/kontext)
  tar -C "$d" -czf "$art/dist/kontext_${v}_darwin_$arch.tar.gz" kontext
  (cd "$art/dist" && shasum -a 256 "kontext_${v}_darwin_$arch.tar.gz" >> checksums.txt)
done

render_cask() { # version -> stdout: the real cask template, pointed at the local tarball
  local v="$1" sum sums="$art/dist/cask-$1.sums"
  sum="$(awk -v a="kontext_${v}_darwin_$arch.tar.gz" '$2 == a { print $1 }' "$art/dist/checksums.txt")"
  for p in darwin_arm64 darwin_amd64 linux_arm64 linux_amd64; do echo "$sum  kontext_${v}_$p.tar.gz"; done > "$sums"
  "$repo/scripts/render-homebrew-cask.sh" "$v" "$sums" \
    | sed "s|https://github.com/kontext-security/kontext/releases/download/v#{version}/kontext_#{version}_darwin_[a-z0-9]*.tar.gz|file://$art/dist/kontext_#{version}_darwin_$arch.tar.gz|"
}

step "A0. Install the published $old cask and run its setup (writes root files with sudo, as setups before this change did)"
brew install --cask kontext-security/tap/kontext
"$prefix/bin/kontext" --version | grep -F "$old" || fail "published cask is not $old"
"$prefix/bin/kontext" setup --token e2e-token --cloud-url "http://127.0.0.1:$port" --allow-http-loopback
hash_root > "$art/root-before.txt"
grep -q 20-kontext.json "$art/root-before.txt" || fail "$old setup wrote no Claude drop-in"
grep -q Cursor "$art/root-before.txt" || fail "$old setup wrote no Cursor machine-wide file"
[ -s "$art/sudo-calls.log" ] && pass "positive control: the shim logged $old setup's sudo ($(wc -l < "$art/sudo-calls.log" | tr -d ' ') calls)" || fail "shim saw no sudo from the $old setup"
pass "$old install has root hook files"
# Cursor support arrived in 1.15.0. Drop its machine-wide file, so this Mac
# looks like one set up before Cursor: the update must add Cursor's hooks.
/usr/bin/sudo rm "/Library/Application Support/Cursor/hooks.json"
hash_root > "$art/root-before.txt"

step "Point the tap at a local copy, so the test controls what is newest"
tap="$(brew --repo kontext-security/tap)"
git clone -q --bare "$tap" "$art/tap.git"
git -C "$tap" remote set-url origin "file://$art/tap.git"
publish() { # version
  render_cask "$1" > "$tap/Casks/kontext.rb"
  git -C "$tap" -c user.email=e2e@kontext.invalid -c user.name=e2e commit -qam "kontext $1"
  git -C "$tap" push -q origin HEAD:main 2>/dev/null || git -C "$tap" push -q origin HEAD:master
}

step "A1. Upgrade $old -> $v1"
mark="$(wc -l < "$art/prompts.log")" smark="$(wc -l < "$art/sudo-calls.log")"
publish "$v1"
HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade --cask --no-ask kontext-security/tap/kontext
wait_for 180 "daemon restarted on $v1" sh -c "[ \"\$(grep -o 'managed-observe daemon [^ ]* (pid [0-9]*) started' '$mlog' | tail -1 | awk '{print \$3}')\" = $v1 ]"
wait_for 90 "Cursor hooks added to ~/.cursor/hooks.json without a prompt" sh -c "[ \"\$(grep -c \"kontext' hook\" '$HOME/.cursor/hooks.json')\" -ge 9 ]"
hash_root > "$art/root-after.txt"
diff "$art/root-before.txt" "$art/root-after.txt" && pass "root files untouched"
drop="$(grep -o "'[^']*kontext' hook" "/Library/Application Support/ClaudeCode/managed-settings.d/20-kontext.json" | head -1)"
grep -qF "$drop" "$HOME/.claude/settings.json" && pass "Claude user copy repeats the drop-in's handler ($drop), so each event runs once"
claude_probe "root drop-in plus user file"
wait_for 240 "doctor healthy after the upgrade" "$prefix/bin/kontext" doctor
"$prefix/bin/kontext" doctor | tee "$art/doctor-upgrade.txt"

step "B. The new daemon updates itself to $v2"
publish "$v2"
wait_for 420 "daemon updater upgraded and launchd restarted it on $v2" sh -c "[ \"\$(grep -o 'managed-observe daemon [^ ]* (pid [0-9]*) started' '$mlog' | tail -1 | awk '{print \$3}')\" = $v2 ]"
grep -F "daemon updater: upgraded" "$mlog" | tail -1
cat "$HOME/Library/Application Support/Kontext/update-check.json"; echo

step "C. Self-heal and inventory rescan"
inv="$(find "$HOME/Library/Application Support/Kontext" -name agent-inventory.json -print 2>/dev/null | head -1)"
[ -n "$inv" ] || fail "no agent-inventory.json under ~/Library/Application Support/Kontext"
echo "inventory: $inv"
before="$(stat -f %m "$inv")"
python3 - "$HOME/.codex/hooks.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
d["hooks"] = {k: [g for g in v if "kontext" not in json.dumps(g)] for k, v in d["hooks"].items()}
json.dump(d, open(p, "w"))
PY
[ "$(count_kontext "$HOME/.codex/hooks.json")" = 0 ] || fail "could not remove Codex hooks"
wait_for 90 "removed Codex hooks restored" sh -c "[ \"\$(grep -c \"kontext' hook\" '$HOME/.codex/hooks.json')\" -gt 0 ]"
wait_for 90 "agent scan reran" sh -c "[ \$(stat -f %m '$inv') -gt $before ]"

step "No password prompt since the upgrade"
if tail -n +"$((mark + 1))" "$art/prompts.log" | grep -q .; then tail -n +"$((mark + 1))" "$art/prompts.log"; fail "an admin dialog or Kontext sudo ran"; fi
if tail -n +"$((smark + 1))" "$art/sudo-calls.log" | grep -q .; then tail -n +"$((smark + 1))" "$art/sudo-calls.log"; fail "kontext called sudo"; fi
pass "no admin dialog and no kontext sudo after the $old setup"

step "E. System scope writes the same bytes as $old"
old_bin="$(mktemp -d)/kontext"
curl -fsSL "https://github.com/kontext-security/kontext/releases/download/v$old/kontext_${old}_darwin_$arch.tar.gz" | tar -xz -C "$(dirname "$old_bin")"
sys_bytes() { # binary -> hashes of the system files it writes, as a package installs it
  /usr/bin/sudo install -m 0755 "$1" /usr/local/bin/kontext
  /usr/bin/sudo /usr/local/bin/kontext hooks remove --scope system >/dev/null
  /usr/bin/sudo /usr/local/bin/kontext hooks install --scope system --binary /usr/local/bin/kontext >/dev/null
  for f in "/Library/Application Support/ClaudeCode/managed-settings.d/20-kontext.json" "/Library/Application Support/Cursor/hooks.json" /etc/codex/hooks.json /etc/codex/config.toml; do shasum -a 256 "$f"; done
}
sys_bytes "$old_bin" > "$art/system-old.txt"
sys_bytes "$prefix/bin/kontext" > "$art/system-new.txt"
diff "$art/system-old.txt" "$art/system-new.txt" && pass "system-scope output byte-identical to $old"
/usr/bin/sudo /usr/local/bin/kontext hooks remove --scope system >/dev/null
/usr/bin/sudo rm -f /usr/local/bin/kontext

step "D. Fresh install on a Mac without root files"
"$prefix/bin/kontext" setup --uninstall
brew uninstall --cask kontext
[ -z "$(hash_root)" ] || fail "root files remain before the fresh install"
mark="$(wc -l < "$art/prompts.log")" smark="$(wc -l < "$art/sudo-calls.log")"
brew install --cask kontext-security/tap/kontext
"$prefix/bin/kontext" setup --token e2e-token --cloud-url "http://127.0.0.1:$port" --allow-http-loopback | tee "$art/setup-fresh.txt"
[ -z "$(hash_root)" ] && pass "fresh setup wrote no root file"
for f in .claude/settings.json .codex/hooks.json .cursor/hooks.json; do
  [ "$(count_kontext "$HOME/$f")" -gt 0 ] && pass "hooks in ~/$f"
done
grep -q "Cowork: not governed" "$art/setup-fresh.txt" && pass "setup reports Cowork as not governed"
if tail -n +"$((mark + 1))" "$art/prompts.log" | grep -q .; then tail -n +"$((mark + 1))" "$art/prompts.log"; fail "fresh setup showed an admin dialog"; fi
if tail -n +"$((smark + 1))" "$art/sudo-calls.log" | grep -q .; then tail -n +"$((smark + 1))" "$art/sudo-calls.log"; fail "fresh setup called sudo"; fi
pass "fresh install and setup: no sudo call, no admin dialog"
wait_for 240 "doctor healthy after the fresh setup" "$prefix/bin/kontext" doctor
"$prefix/bin/kontext" doctor | tee "$art/doctor-fresh.txt"
grep -q "auto-update: on (cask" "$art/doctor-fresh.txt" && pass "doctor reports auto-update on"
claude_probe "user file only"

step "ALL PASSED"
