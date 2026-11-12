#!/usr/bin/env bash
# End-to-end check that an organization-managed install governs every agent a
# self-serve install does. It builds kontext, runs its daemon with a managed
# config in a temporary HOME against a local stand-in for the cloud, and checks
# what a managed Mac needs for Antigravity, which reads no machine-wide hooks
# file: the daemon writes the user's hooks, the inventory it sends reports the
# agent wired, doctor flags a missing file, and removal leaves no hook behind.
# macOS only. Needs no sudo and touches no real hook file.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Short: a Unix socket path must fit in 104 bytes.
WORK="$(mktemp -d /tmp/kmh.XXXXXX)"
BIN="${WORK}/bin/kontext"
LOG="${WORK}/daemon.log"
REQUESTS="${WORK}/requests"

cleanup() {
  for pid in "${DAEMON_PID:-}" "${CLOUD_PID:-}"; do
    [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null && wait "${pid}" 2>/dev/null || true
  done
  rm -rf "${WORK}"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  [[ -f "${LOG}" ]] && sed 's/^/  daemon: /' "${LOG}" | tail -20 >&2
  exit 1
}

DROPIN="${WORK}/20-kontext.json"
PKG="github.com/kontext-security/kontext/internal/managedobserve"
echo "==> build kontext; its hooks name ${BIN}, as a package's name /usr/local/bin/kontext"
go build -C "${ROOT}" -o "${BIN}" \
  -ldflags "-X ${PKG}.managedHookBinary=${BIN} -X ${PKG}.managedHookDropIn=${DROPIN}" ./cmd/kontext
# The package's machine-wide Claude hooks, which root writes: the daemon heals
# only while they are in place.
sed "s|<bin>|${BIN}|g" "${ROOT}/internal/hookinstall/testdata/system-pin/Library_Application-Support_ClaudeCode_managed-settings.d_20-kontext.json" >"${DROPIN}"

export HOME="${WORK}/home"
mkdir -p "${HOME}/.gemini/antigravity" "${REQUESTS}"
echo '{}' >"${HOME}/.gemini/antigravity/state.json" # Antigravity is on this Mac
HOOKS="${HOME}/.gemini/config/hooks.json"
unset CODEX_HOME CLAUDE_CONFIG_DIR GEMINI_CLI_HOME

echo "==> the release list names Antigravity's per-user file"
"${BIN}" hooks list --scope system >"${WORK}/list.json"
python3 - "${WORK}/list.json" <<'PY' || fail "hooks list"
import json, sys
agents = {a["agent"]: a["files"] for a in json.load(open(sys.argv[1]))}
assert set(agents) == {"claude_code", "codex", "cursor", "antigravity"}, agents
assert agents["antigravity"] == [{"kind": "antigravity", "path": "~/.gemini/config/hooks.json", "scope": "user"}], agents
PY

echo "==> start a stand-in cloud that records what the daemon sends"
PORT_FILE="${WORK}/port"
python3 - "${REQUESTS}" "${PORT_FILE}" <<'PY' &
import gzip, http.server, os, sys
out, port_file = sys.argv[1], sys.argv[2]
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def reply(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        n = len(os.listdir(out))
        with open(os.path.join(out, "%04d" % n), "wb") as f:
            f.write(self.command.encode() + b" " + self.path.encode() + b"\n" + body)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")
    do_GET = do_POST = do_PUT = reply
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
open(port_file, "w").write(str(server.server_address[1]))
server.serve_forever()
PY
CLOUD_PID=$!
for _ in $(seq 50); do [[ -s "${PORT_FILE}" ]] && break; sleep 0.1; done
[[ -s "${PORT_FILE}" ]] || fail "stand-in cloud did not start"

cat >"${WORK}/managed.json" <<JSON
{
  "version": "managed-install-v1",
  "cloud_url": "http://127.0.0.1:$(cat "${PORT_FILE}")",
  "allow_http_loopback": true,
  "mode": "observe",
  "agent": "claude",
  "credentials": {"install_token_ref": "env:KONTEXT_INSTALL_TOKEN"}
}
JSON
export KONTEXT_MANAGED_CONFIG="${WORK}/managed.json"
export KONTEXT_INSTALL_TOKEN="kmh-e2e-token-0123456789abcdefghijklmnop"
export KONTEXT_INSTALLATION_STATE="${WORK}/installation.json"
export KONTEXT_MANAGED_OBSERVE_SOCKET="${WORK}/k.sock"
export KONTEXT_MANAGED_OBSERVE_DB="${WORK}/guard.db"

echo "==> run the daemon with the managed (non-self-serve) config"
"${BIN}" managed-observe-daemon >"${LOG}" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 100); do [[ -f "${HOOKS}" ]] && break; sleep 0.2; done
[[ -f "${HOOKS}" ]] || fail "the daemon wrote no Antigravity hooks"
python3 - "${HOOKS}" "${BIN}" <<'PY' || fail "Antigravity hooks"
import json, sys
hooks = json.load(open(sys.argv[1]))["kontext"]
commands = [h["command"] for e in hooks.values() for g in e for h in g.get("hooks", [g])]
assert len(commands) == 5 and all(c.startswith("'%s' hook --agent 'antigravity' " % sys.argv[2]) for c in commands), commands
PY
echo "    wrote ${HOOKS#"${WORK}"/}"
for user_file in .claude/settings.json .codex/hooks.json .cursor/hooks.json; do
  [[ ! -e "${HOME}/${user_file}" ]] || fail "the managed daemon wrote a user copy of ${user_file}"
done
echo "    no user copies of Claude Code, Codex or Cursor hooks"

echo "==> the inventory the daemon sends reports Antigravity wired"
wired=""
for _ in $(seq 150); do
  wired="$(python3 - "${REQUESTS}" <<'PY'
import json, os, sys
d = sys.argv[1]
for name in sorted(os.listdir(d), reverse=True):
    head, _, body = open(os.path.join(d, name), "rb").read().partition(b"\n")
    def walk(node):
        if isinstance(node, dict):
            if node.get("id") == "antigravity" and "wired" in node:
                return node["wired"]
            for value in node.values():
                found = walk(value)
                if found: return found
        if isinstance(node, list):
            for value in node:
                found = walk(value)
                if found: return found
    try:
        found = walk(json.loads(body))
    except ValueError:
        continue
    if found:
        print(found); break
PY
)"
  [[ -n "${wired}" ]] && break
  sleep 0.2
done
[[ "${wired}" == "yes" ]] || fail "inventory reports Antigravity wired=${wired:-<no inventory sent>}"
echo "    antigravity wired=${wired}"

echo "==> doctor flags an installed agent whose hooks are gone"
kill "${DAEMON_PID}" && wait "${DAEMON_PID}" 2>/dev/null || true
DAEMON_PID=""
rm "${HOOKS}"
"${BIN}" doctor >"${WORK}/doctor.txt" 2>&1 || true
grep '^Antigravity hooks' "${WORK}/doctor.txt" | sed 's/^/    /'
grep -qF "Antigravity hooks: missing (${HOOKS})" "${WORK}/doctor.txt" || fail "doctor does not flag the missing Antigravity hooks"

echo "==> system removal drops Kontext's hook from the user's file and keeps the other tool's"
printf '{"other-tool":{"Stop":[{"type":"command","command":"/usr/bin/true"}]}}\n' >"${HOOKS}"
"${BIN}" hooks install --scope user --binary "${BIN}" >/dev/null # Kontext's hook beside another tool's
# A real system removal needs root; this checks its plan for the per-user file.
# internal/hookinstall's TestSystemRemovalCleansEveryHome runs the removal.
"${BIN}" hooks remove --scope system --dry-run >"${WORK}/remove.txt"
grep -F "${HOOKS}" "${WORK}/remove.txt" | sed 's/^/    /'
grep -qF "would-write	user	${HOOKS}	owned" "${WORK}/remove.txt" || fail "system removal does not plan the per-user file"
python3 -c 'import json,sys; assert "kontext" in json.load(open(sys.argv[1]))' "${HOOKS}" || fail "the dry run changed the file"

echo "PASS"
