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
# KONTEXT_COST_PROFILE names an enrolled local profile without switching the
# machine's active one.
wanted = os.environ.get('KONTEXT_COST_PROFILE', '').strip()
active = next((p for p in profiles['profiles'] if (p.get('name') == wanted if wanted else p.get('active'))), None)
if not active or not local_url(active.get('cloud_url', '')):
    raise SystemExit('Select an enrolled local Kontext profile (or set KONTEXT_COST_PROFILE) before running this local test.')
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
events = {'SessionStart':'session-start', 'UserPromptSubmit':'user-prompt-submit',
          'PreToolUse':'pre-tool-use', 'PostToolUse':'post-tool-use',
          'PostToolUseFailure':'post-tool-use-failure',
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
# UserPromptSubmit mints each turn. Like the completion observers it runs
# async here: these global hooks only observe, and never hold a prompt.
events = ({'UserPromptSubmit':'user-prompt-submit', 'PostToolUse':'post-tool-use', 'Stop':'stop'} if agent == 'codex'
          else {'UserPromptSubmit':'user-prompt-submit', 'Stop':'stop', 'SubagentStop':'subagent-stop', 'SessionEnd':'session-end'})
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
        print('Review and trust the three local cost hooks in Codex /hooks before testing.')
PY
}

# report_turns waits for the collector to upload a session's turns and usage,
# then reads back what the local cloud stored and writes
# .tmp/tool-cost-local/turns-<date>.json. KONTEXT_COST_DATABASE_URL is the local
# API's DATABASE_URL; without psql on PATH the query runs inside the compose
# Postgres container (KONTEXT_COST_POSTGRES_CONTAINER, default kontext-postgres-1).
# KONTEXT_COST_COOKIE, a signed-in browser session's Cookie header, adds the Cost
# summary from the API itself.
report_turns() {
  python3 - "$COST_STATE" "$COST_URL" "$1" <<'PY'
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request

state, cloud, session = Path(sys.argv[1]), sys.argv[2].rstrip('/'), sys.argv[3]
if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', session):
    raise SystemExit('Expected a Claude session ID.')
database = os.environ.get('KONTEXT_COST_DATABASE_URL', '').strip()
if not database:
    raise SystemExit('Set KONTEXT_COST_DATABASE_URL to the local API database URL to read back turns.')

# The collector flushes every 2 s; wait until nothing for the session is pending.
local = sqlite3.connect('file:' + str(state / 'state/guard.db') + '?mode=ro', uri=True)
pending = None
for _ in range(60):
    pending = local.execute(
        'select (select count(*) from turns where session_id = ? and exported = 0),'
        ' (select count(*) from tool_usage_records where session_id = ? and exported = 0)',
        (session, session)).fetchone()
    minted = local.execute('select count(*) from turns where session_id = ?', (session,)).fetchone()[0]
    if minted and pending == (0, 0):
        break
    time.sleep(1)
local_turns = [dict(zip(('id', 'sequence', 'started_at', 'source', 'prompt_mode', 'prompt_chars'), row)) for row in local.execute(
    'select id, sequence, started_at, source, prompt_mode, prompt_chars from turns where session_id = ? order by sequence', (session,))]

def query(sql):
    if shutil.which('psql'):
        command = ['psql', database]
    else:
        command = ['docker', 'exec', '-i', os.environ.get('KONTEXT_COST_POSTGRES_CONTAINER', 'kontext-postgres-1'), 'psql', database]
    out = subprocess.run(command + ['-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1', '-f', '-'],
                         input=sql, text=True, capture_output=True, check=True).stdout.strip()
    return json.loads(out or 'null') or []

# The session ID is validated above, so it is safe to inline.
turns = query(f"""select json_agg(t order by t.sequence) from (
  select local_id as id, sequence, agent, started_at, source, prompt_mode, prompt_chars,
    prompt_truncated, work_type, work_type_confidence, classifier_version
  from hosted_ledger_turns where session_id = '{session}') t;""")
usage = query(f"""select json_agg(u order by u.timestamp) from (
  select usage->>'message_id' as message_id, usage->>'timestamp' as timestamp,
    usage->>'model' as model, usage->>'turn_id' as turn_id
  from hosted_tool_usage where session_id = '{session}') u;""")
summary = None
cookie = os.environ.get('KONTEXT_COST_COOKIE', '').strip()
if cookie:
    request = urllib.request.Request(cloud + '/api/v1/enterprise/dashboard/cost/summary', headers={'Cookie': cookie})
    with urllib.request.urlopen(request, timeout=30) as response:
        summary = json.load(response)

ids = {turn['id'] for turn in turns}
labels = {turn['id']: turn['work_type'] for turn in turns}
by_work_type = {}
for row in usage:
    label = labels.get(row['turn_id']) or 'unclassified'
    by_work_type[label] = by_work_type.get(label, 0) + 1
checks = {
    'two_turns_minted_locally': [t['sequence'] for t in local_turns] == [1, 2],
    'both_turns_stored': len(turns) == 2 and ids == {t['id'] for t in local_turns},
    'usage_after_first_prompt_stamped': bool(usage) and all(row['turn_id'] in ids for row in usage),
    'probe_usage_classified': bool(usage) and 'unclassified' not in by_work_type,
}
artifact = {
    'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'cloud_url': cloud, 'session_id': session, 'pending_after_wait': pending,
    'local_turns': local_turns, 'turns': turns, 'usage': usage,
    'usage_by_work_type': by_work_type, 'checks': checks,
    'cost_summary_by_work_type': summary.get('byWorkType') if summary else None,
    'cost_summary_work_type': summary.get('workType') if summary else None,
}
path = state / ('turns-' + datetime.date.today().isoformat() + '.json')
path.write_text(json.dumps(artifact, indent=2, default=str) + '\n')
print(json.dumps(checks, indent=2))
print('Artifact:', path)
if not (checks['two_turns_minted_locally'] and checks['both_turns_stored'] and checks['usage_after_first_prompt_stamped']):
    raise SystemExit('Turn probe failed; see the artifact.')
if not checks['probe_usage_classified']:
    print('Turns are stored but not classified yet: the classification worker needs WORK_TYPE_CLASSIFICATION_ENABLED=true and an OpenAI key.')
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
    # Two prompts in one session, each its own turn with its own tool call.
    COST_FIRST="$(claude -p --output-format json --max-turns 3 \
      --allowedTools 'Bash(printf kontext-cost-local-probe)' \
      -- \
      'Use Bash exactly once to execute: printf kontext-cost-local-probe. Do not read files or run other commands. After seeing the output, reply only OK.')"
    printf '%s\n' "$COST_FIRST"
    COST_SESSION="$(python3 -c 'import json, sys; print(json.loads(sys.argv[1])["session_id"])' "$COST_FIRST")"
    claude -p --output-format json --max-turns 3 --resume "$COST_SESSION" \
      --allowedTools 'Bash(printf kontext-cost-local-probe-2)' \
      -- \
      'Now use Bash exactly once to execute: printf kontext-cost-local-probe-2. Do not read files or run other commands. Then explain in one sentence what the first output means.'
    report_turns "$COST_SESSION"
    ;;
  report-turns)
    report_turns "${2:?Pass the probe session ID.}"
    ;;
  *)
    printf 'Usage: bash scripts/tool-cost-local.sh [prepare|start|probe|report-turns SESSION_ID|observe-all|unobserve-all|observe-codex|unobserve-codex|probe-codex|register-codex [SESSION_ID]]\n' >&2
    exit 1
    ;;
esac
