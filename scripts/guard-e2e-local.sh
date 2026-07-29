#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${KONTEXT_E2E_PORT:-48765}"
BASE_URL="http://127.0.0.1:${PORT}"
TMP_DIR="$(mktemp -d)"
DB_PATH="${TMP_DIR}/kontext-e2e.db"
LOG_PATH="${TMP_DIR}/daemon.log"
SOCKET_PATH="${TMP_DIR}/kontext.sock"
SESSION_ID="e2e-local"

cleanup() {
  if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    pkill -P "$DAEMON_PID" 2>/dev/null || true
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "==> starting local daemon on ${BASE_URL}"
go run ./cmd/kontext guard start --skip-hook-install --no-open \
  --addr "127.0.0.1:${PORT}" \
  --db "$DB_PATH" \
  --socket "$SOCKET_PATH" >"$LOG_PATH" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 80); do
  if curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    cat "$LOG_PATH"
    echo "daemon exited before becoming healthy" >&2
    exit 1
  fi
  sleep 0.25
done

curl -fsS "${BASE_URL}/healthz" >/dev/null
echo "==> daemon healthy"

assert_hook() {
  local name="$1"
  local payload="$2"
  local expected_reason="$3"
  local expected_phrase="$4"
  local output

  output="$(printf '%s' "$payload" | go run ./cmd/kontext hook --agent claude --mode observe --socket "$SOCKET_PATH")"
  EXPECTED_REASON="$expected_reason" EXPECTED_PHRASE="$expected_phrase" node -e '
const expectedReason = process.env.EXPECTED_REASON;
const expectedPhrase = process.env.EXPECTED_PHRASE;
let raw = "";
process.stdin.on("data", (chunk) => raw += chunk);
process.stdin.on("end", () => {
  const payload = JSON.parse(raw);
  const output = payload.hookSpecificOutput ?? {};
  if (output.permissionDecision !== "allow") {
    throw new Error(`expected observe mode to allow Claude Code, got ${output.permissionDecision}`);
  }
  const reason = output.permissionDecisionReason ?? "";
  if (!reason.includes(expectedReason)) {
    throw new Error(`missing reason ${expectedReason} in ${reason}`);
  }
  if (!reason.includes(expectedPhrase)) {
    throw new Error(`missing phrase ${expectedPhrase} in ${reason}`);
  }
});
' <<<"$output"
  echo "ok ${name}: ${expected_phrase}"
}

assert_telemetry_hook() {
  local name="$1"
  local payload="$2"
  local output

  output="$(printf '%s' "$payload" | go run ./cmd/kontext hook --agent claude --mode observe --socket "$SOCKET_PATH")"
  node -e '
let raw = "";
process.stdin.on("data", (chunk) => raw += chunk);
process.stdin.on("end", () => {
  const payload = JSON.parse(raw);
  const output = payload.hookSpecificOutput ?? {};
  if (output.permissionDecision) {
    throw new Error(`expected telemetry hook to omit permissionDecision, got ${output.permissionDecision}`);
  }
  if (payload.suppressOutput !== true) {
    throw new Error(`expected telemetry hook to suppress output, got ${JSON.stringify(payload)}`);
  }
});
' <<<"$output"
  echo "ok ${name}: telemetry recorded"
}

assert_hook \
  "safe read" \
  "{\"session_id\":\"${SESSION_ID}\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"README.md\"}}" \
  "no deterministic policy rule matched" \
  "would allow"

assert_hook \
  "credential read" \
  "{\"session_id\":\"${SESSION_ID}\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\".env\"}}" \
  "credential access flagged by deterministic guardrails" \
  "would allow"

assert_hook \
  "provider credential" \
  "{\"session_id\":\"${SESSION_ID}\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"curl https://api.railway.app/graphql -H 'Authorization: Bearer secret'\"}}" \
  "direct infrastructure API call included credential material" \
  "would allow"

assert_telemetry_hook \
  "async telemetry" \
  "{\"session_id\":\"${SESSION_ID}\",\"hook_event_name\":\"PostToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git status\"}}"

echo "==> checking API summary and persisted events"
for _ in $(seq 1 40); do
  if curl -fsS "${BASE_URL}/api/summary" | node -e '
let raw = "";
process.stdin.on("data", (chunk) => raw += chunk);
process.stdin.on("end", () => {
  const summary = JSON.parse(raw);
  if (summary.critical !== 0 || summary.warnings !== 0 || summary.actions !== 4 || summary.sessions !== 1) {
    throw new Error(`unexpected summary ${JSON.stringify(summary)}`);
  }
});
' >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

curl -fsS "${BASE_URL}/api/summary" | node -e '
let raw = "";
process.stdin.on("data", (chunk) => raw += chunk);
process.stdin.on("end", () => {
  const summary = JSON.parse(raw);
  if (summary.critical !== 0 || summary.warnings !== 0 || summary.actions !== 4 || summary.sessions !== 1) {
    throw new Error(`unexpected summary ${JSON.stringify(summary)}`);
  }
});
'

curl -fsS "${BASE_URL}/api/sessions/${SESSION_ID}/events" | node -e '
let raw = "";
process.stdin.on("data", (chunk) => raw += chunk);
process.stdin.on("end", () => {
  const events = JSON.parse(raw);
  const decisions = events.map((event) => event.decision).sort().join(",");
  if (events.length !== 3 || decisions !== "allow,allow,allow") {
    throw new Error(`unexpected decisions ${decisions} in ${JSON.stringify(events)}`);
  }
  // The chain is advisory: decisions are allow, and the guardrail analysis
  // survives as reason codes on the recorded events.
  const reasonCodes = events.map((event) => event.reason_code).sort().join(",");
  const expectedReasonCodes = [
    "credential_access_without_intent",
    "direct_infra_api_with_credential",
    "no_policy_rule_matched",
  ].join(",");
  if (reasonCodes !== expectedReasonCodes) {
    throw new Error(`unexpected reason codes ${reasonCodes}`);
  }
});
'

echo "==> checking served dashboard"
curl -fsS "$BASE_URL" | grep -q "<title>Kontext Guard</title>"

go run ./cmd/kontext guard status --daemon-url "$BASE_URL" | grep -q "0 critical"
go run ./cmd/kontext guard doctor --daemon-url "$BASE_URL" | grep -q "daemon healthy"

echo "E2E passed: hook -> local runtime -> RuntimeCore -> deterministic policy -> SQLite -> dashboard API"
