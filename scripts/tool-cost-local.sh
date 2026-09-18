#!/usr/bin/env bash
# Isolated Claude/Codex -> local cloud Cost-page exercise. Requires an enrolled LOCAL
# Kontext profile; reuses its credential reference without printing the token.
set -euo pipefail
umask 077

COST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COST_STATE="$COST_ROOT/.tmp/tool-cost-local"
COST_URL="${KONTEXT_COST_CLOUD_URL:-http://localhost:4107}"
COST_SOCKET="/tmp/kontext-cost-$(id -u)-$(printf '%s' "$COST_ROOT" | cksum | awk '{print $1}')/kontext.sock"

prepare() {
  mkdir -p "$COST_STATE/project/.claude" "$COST_STATE/state"
  python3 - "$COST_STATE" "$COST_URL" "$COST_SOCKET" <<'PY'
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from urllib.parse import urlparse

state, cloud, socket = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
def local_url(value):
    url = urlparse(value)
    return url.scheme in ('http', 'https') and url.hostname in ('localhost', '127.0.0.1', '::1') and not url.username and not url.password
if not local_url(cloud):
    raise SystemExit('KONTEXT_COST_CLOUD_URL must point to a local API.')
profiles = json.loads(subprocess.check_output(['kontext', 'profile', 'ls', '--json']))
active = next((p for p in profiles['profiles'] if p.get('active')), None)
if not active or not local_url(active.get('cloud_url', '')):
    raise SystemExit('Select an enrolled local Kontext profile before running this local test.')
existing_path = state / 'managed.json'
existing = json.loads(existing_path.read_text()) if existing_path.exists() else {}
user_email = os.environ.get('KONTEXT_COST_USER_EMAIL', '').strip() or existing.get('device', {}).get('user_email', '')
if user_email and ('@' not in user_email or len(user_email) > 320):
    raise SystemExit('KONTEXT_COST_USER_EMAIL must be an email address.')
config = {
    'version': 'managed-install-v1', 'cloud_url': cloud.rstrip('/'),
    'mode': 'observe', 'agent': 'claude', 'allow_http_loopback': True,
    'credentials': {'install_token_ref': active['install_token_ref']},
    'device': {'label': 'Tool cost local test', **({'user_email': user_email} if user_email else {})},
}
(state / 'managed.json').write_text(json.dumps(config, indent=2) + '\n')
events = {'SessionStart':'session-start', 'PreToolUse':'pre-tool-use',
          'PostToolUse':'post-tool-use', 'PostToolUseFailure':'post-tool-use-failure',
          'Stop':'stop', 'SubagentStop':'subagent-stop', 'SessionEnd':'session-end'}
hooks = {}
for name, alias in events.items():
    command = shlex.join([str(state/'kontext'), 'hook', alias, '--agent', 'claude', '--mode', 'observe', '--socket', socket])
    hook = {'type': 'command', 'command': command, 'timeout': 20}
    if name in ('SessionStart', 'Stop', 'SubagentStop', 'SessionEnd'):
        hook['async'] = True
    hooks[name] = [{'matcher': '', 'hooks': [hook]}]
(state / 'project/.claude/settings.json').write_text(json.dumps({'hooks': hooks}, indent=2) + '\n')
(state / 'socket-path').write_text(socket)
print('Local workspace:', active.get('organization_name', active['name']))
print('Local API:', cloud)
print('Claude test folder:', state / 'project')
PY
  (cd "$COST_ROOT" && go build -ldflags '-X main.version=dev-tool-cost-local' -o "$COST_STATE/kontext" ./cmd/kontext)
}

configure_observer() {
  python3 - "$COST_STATE" "$COST_SOCKET" "$1" "${2:-claude}" <<'PY'
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
import time

state, socket, action, agent = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
if action == 'observe-all' and (not (state/'kontext').is_file() or not Path(socket).exists() or not stat.S_ISSOCK(Path(socket).stat().st_mode)):
    raise SystemExit('Start the local test collector first.')
path = (Path(os.environ.get('CODEX_HOME', str(Path.home()/'.codex'))) / 'hooks.json' if agent == 'codex' else Path(os.environ.get('CLAUDE_CONFIG_DIR', str(Path.home()/'.claude'))) / 'settings.json')
original = path.read_bytes() if path.exists() else None
settings = json.loads(original) if original is not None else {}
hooks = settings.setdefault('hooks', {})
events = {'PostToolUse':'post-tool-use', 'Stop':'stop'} if agent == 'codex' else {'Stop':'stop', 'SubagentStop':'subagent-stop', 'SessionEnd':'session-end'}
for event, alias in events.items():
    command = 'if [ -S ' + shlex.quote(socket) + ' ]; then ' + shlex.join([
        str(state/'kontext'), 'hook', alias, '--agent', agent, '--mode', 'observe', '--socket', socket,
    ]) + '; fi'
    groups = []
    for group in hooks.get(event, []):
        remaining = [hook for hook in group.get('hooks', []) if hook.get('command') != command]
        if remaining:
            groups.append({**group, 'hooks': remaining})
    if action == 'observe-all':
        groups.append({'matcher':'', 'hooks':[{'type':'command', 'command':command, 'timeout':20, 'async':True}]})
    if groups:
        hooks[event] = groups
    else:
        hooks.pop(event, None)
if not hooks:
    settings.pop('hooks', None)
updated = (json.dumps(settings, indent=2) + '\n').encode()
if original != updated:
    state.mkdir(parents=True, exist_ok=True)
    if original is not None:
        backup = state / (agent + '-settings.backup-' + str(time.time_ns()) + '.json')
        backup.write_bytes(original)
        backup.chmod(0o600)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.cost-settings-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(updated)
        os.chmod(temporary, stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600)
        if (path.read_bytes() if path.exists() else None) != original:
            raise SystemExit('Claude settings changed during update; retry.')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
print('Local cost observer for ' + agent + (' enabled.' if action == 'observe-all' else ' removed.'))
print('Settings:', path)
if action == 'observe-all':
    print('Start a new agent session, finish a tool-using turn, then refresh http://localhost:3107/cost.')
    if agent == 'codex':
        print('Review and trust the two local cost hooks in Codex /hooks before testing.')
PY
}

case "${1:-start}" in
  observe-all|unobserve-all)
    configure_observer "$1"
    ;;
  observe-codex)
    configure_observer observe-all codex
    ;;
  unobserve-codex)
    configure_observer unobserve-all codex
    ;;
  register-codex)
    if [[ ! -S "$COST_SOCKET" || ! -f "$COST_STATE/state/guard.db" ]]; then
      printf 'Start the local collector first.\n' >&2
      exit 1
    fi
    # Explicit recovery for an already-running desktop session whose hooks did
    # not register its source. Never scan/import unrelated session history.
    COST_SESSION="${2:-${CODEX_THREAD_ID:-}}"
    COST_TRANSCRIPT="$(python3 - "$COST_SESSION" <<'PY'
import os, re, sys
from pathlib import Path
session = sys.argv[1]
if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', session):
    raise SystemExit('Pass a Codex session ID, or run inside the target Codex task.')
root = Path(os.environ.get('CODEX_HOME', str(Path.home()/'.codex'))) / 'sessions'
paths = list(root.glob('**/rollout-*-' + session + '.jsonl'))
if len(paths) != 1:
    raise SystemExit('Expected exactly one transcript for the selected session.')
print(paths[0].resolve())
PY
)"
    cd "$COST_ROOT"
    exec go run ./scripts/cost-register-codex "$COST_STATE/state/guard.db" "$COST_TRANSCRIPT" "$COST_SESSION"
    ;;
  probe-codex)
    if [[ ! -S "$COST_SOCKET" ]]; then
      printf 'Start the collector first: bash scripts/tool-cost-local.sh start\n' >&2
      exit 1
    fi
    exec "${KONTEXT_COST_CODEX_BINARY:-codex}" -a never -s read-only exec --skip-git-repo-check -C "$COST_STATE/project" -m gpt-5.6-luna --json \
      'Use exec_command exactly once to execute printf kontext-openai-cost-probe. Do not read files or run other commands. After seeing the output, reply only OK.'
    ;;
  prepare)
    prepare
    ;;
  start)
    if [[ -S "$COST_SOCKET" ]]; then
      printf 'A local test collector socket already exists: %s\nStop the existing test collector before starting another.\n' "$COST_SOCKET" >&2
      exit 1
    fi
    prepare
    export KONTEXT_MANAGED_CONFIG="$COST_STATE/managed.json"
    export KONTEXT_INSTALLATION_STATE="$COST_STATE/state/installation.json"
    export KONTEXT_MANAGED_OBSERVE_DB="$COST_STATE/state/guard.db"
    export KONTEXT_MANAGED_OBSERVE_SOCKET="$COST_SOCKET"
    export KONTEXT_MANAGED_OBSERVE_LAUNCHD_LABEL="security.kontext.cost-local"
    export KONTEXT_MANAGED_STREAM_INTERVAL=2s
    export KONTEXT_EXPECTED_CONFIG_SCOPE=env
    export KONTEXT_NO_DEVICE_KEY=1
    export KONTEXT_NO_UPDATE_CHECK=1
    export KONTEXT_DEBUG=1
    printf 'Collector running. In another terminal: bash scripts/tool-cost-local.sh probe\n'
    exec "$COST_STATE/kontext" managed-observe-daemon --socket "$COST_SOCKET" --db "$COST_STATE/state/guard.db"
    ;;
  probe)
    if [[ ! -S "$COST_SOCKET" ]]; then
      printf 'Start the collector first: bash scripts/tool-cost-local.sh start\n' >&2
      exit 1
    fi
    cd "$COST_STATE/project"
    exec claude -p --output-format json --max-turns 3 \
      --allowedTools 'Bash(printf kontext-cost-local-probe)' \
      -- \
      'Use Bash exactly once to execute: printf kontext-cost-local-probe. Do not read files or run other commands. After seeing the output, reply only OK.'
    ;;
  *)
    printf 'Usage: bash scripts/tool-cost-local.sh [prepare|start|probe|observe-all|unobserve-all|observe-codex|unobserve-codex|probe-codex|register-codex [SESSION_ID]]\n' >&2
    exit 1
    ;;
esac
