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
go run ./cmd/kontext guard start --skip-hook-install \
  --addr "127.0.0.1:${PORT}" \
  --db "$DB_PATH" \
  --socket "$SOCKET_PATH" >"$LOG_PATH" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 180); do
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

STEP_SAFETY_E2E=1
case "${KONTEXT_STEP_SAFETY_SHADOW:-}" in
  0|false|False|FALSE|f|F) STEP_SAFETY_E2E=0 ;;
esac
if [[ "$STEP_SAFETY_E2E" == "1" ]]; then
  curl -fsS "${BASE_URL}/healthz" | node -e '
let raw = "";
process.stdin.on("data", (chunk) => raw += chunk);
process.stdin.on("end", () => {
  const health = JSON.parse(raw).step_safety ?? {};
  if (health.status !== "ready") {
    throw new Error(`expected real step-safety model to be ready, got ${JSON.stringify(health)}`);
  }
  const candidate = require(process.cwd() + "/internal/guard/stepsafety/model/native/candidate.json");
  if (health.model_version !== candidate.candidate) {
    throw new Error(`unexpected step-safety model ${JSON.stringify(health)}`);
  }
});
'
  echo "ok step safety: real model ready"
else
  curl -fsS "${BASE_URL}/healthz" | node -e '
let raw = "";
process.stdin.on("data", chunk => raw += chunk);
process.stdin.on("end", () => {
  if (JSON.parse(raw).step_safety?.status !== "disabled") {
    throw new Error(`opt-out did not disable Merlin: ${raw}`);
  }
});
'
  echo "ok step safety: explicit opt-out disabled the model"
fi

wait_for_step_safety() {
  local session_id="$1"
  local expected_count="$2"
  for _ in $(seq 1 80); do
    if curl -fsS "${BASE_URL}/api/sessions/${session_id}/step-safety" | EXPECTED_COUNT="$expected_count" node -e '
let raw = "";
process.stdin.on("data", chunk => raw += chunk);
process.stdin.on("end", () => {
  if (JSON.parse(raw).length !== Number(process.env.EXPECTED_COUNT)) process.exit(1);
});
'; then
      return
    fi
    sleep 0.25
  done
  echo "timed out waiting for deferred Merlin records" >&2
  return 1
}

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
  "observed; no local analysis wired" \
  "would allow"

assert_hook \
  "credential read" \
  "{\"session_id\":\"${SESSION_ID}\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\".env\"}}" \
  "observed; no local analysis wired" \
  "would allow"

assert_hook \
  "provider credential" \
  "{\"session_id\":\"${SESSION_ID}\",\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"curl https://api.railway.app/graphql -H 'Authorization: Bearer secret'\"}}" \
  "observed; no local analysis wired" \
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
  // The decided row carries the Decision Fact cause: with no Cedar
  // deployment in this environment, every call records policy_missing.
  const reasonCodes = events.map((event) => event.reason_code).sort().join(",");
  if (reasonCodes !== "policy_missing,policy_missing,policy_missing") {
    throw new Error(`unexpected reason codes ${reasonCodes}`);
  }
});
'

if [[ "$STEP_SAFETY_E2E" == "1" ]]; then
  wait_for_step_safety "$SESSION_ID" 3
  curl -fsS "${BASE_URL}/api/sessions/${SESSION_ID}/step-safety" | node -e '
const candidate = require(process.cwd() + "/internal/guard/stepsafety/model/native/candidate.json");
let raw = "";
process.stdin.on("data", (chunk) => raw += chunk);
process.stdin.on("end", () => {
  const verdicts = JSON.parse(raw);
  if (verdicts.length !== 3) {
    throw new Error(`expected three pre-execution results, got ${JSON.stringify(verdicts)}`);
  }
  for (const verdict of verdicts) {
    if (verdict.tool_name === "Read") {
      if (verdict.unsafe_probability != null || verdict.error_code !== "excluded_tool" || verdict.shadow_decision !== "unavailable") {
        throw new Error(`file tool was not excluded: ${JSON.stringify(verdict)}`);
      }
    } else if (["timeout", "concurrency_timeout"].includes(verdict.error_code)) {
      // The production deadline also applies on slower shared CI runners.
      // A missed deadline must stay unavailable, never a synthetic safe score.
      if (verdict.unsafe_probability != null || verdict.shadow_decision !== "unavailable") {
        throw new Error(`deadline failure was scored: ${JSON.stringify(verdict)}`);
      }
    } else {
      const score = verdict.unsafe_probability;
      if (process.env.KONTEXT_E2E_EXPECT_MERLIN_TIMEOUT === "1" || !Number.isFinite(score) || score < 0 || score > 1 || verdict.error_code || verdict.shadow_decision !== (score >= candidate.threshold ? "unsafe" : "safe")) {
        throw new Error(`unexpected eligible-tool result: ${JSON.stringify(verdict)}`);
      }
    }
    if (verdict.enforced !== false || verdict.model_version !== candidate.candidate || verdict.threshold !== candidate.threshold) {
      throw new Error(`step-safety shadow contract changed: ${JSON.stringify(verdict)}`);
    }
    console.log(`Merlin ${verdict.tool_name}: ${verdict.error_code || verdict.shadow_decision}`);
  }
});
'
  echo "ok step safety: bounded shell assessment, file tools excluded, policy unchanged"

  assert_telemetry_hook \
    "shadow history request" \
    '{"session_id":"e2e-step-history","hook_event_name":"UserPromptSubmit","prompt":"Summarize the search results."}'

  HISTORY_PAYLOAD="$(node -e '
const content = "prefix " + Array.from({length: 600}, (_, i) => `event-token-${String(i).padStart(3, "0")}`).join(" ") + " suffix";
process.stdout.write(JSON.stringify({session_id: "e2e-step-history", hook_event_name: "PostToolUse", tool_name: "search", tool_input: {query: "public docs"}, tool_response: {content, status: "complete"}}));
')"
  assert_telemetry_hook "large supported history" "$HISTORY_PAYLOAD"
  assert_hook \
    "shadow after large history" \
    '{"session_id":"e2e-step-history","hook_event_name":"PreToolUse","tool_name":"summarize","tool_input":{"topic":"public docs"}}' \
    "observed; no local analysis wired" \
    "would allow"

  wait_for_step_safety "e2e-step-history" 1
  curl -fsS "${BASE_URL}/api/sessions/e2e-step-history/step-safety" | node -e '
const candidate = require(process.cwd() + "/internal/guard/stepsafety/model/native/candidate.json");
let raw = "";
process.stdin.on("data", chunk => raw += chunk);
process.stdin.on("end", () => {
  const verdicts = JSON.parse(raw);
  const verdict = verdicts[0];
  if (verdicts.length !== 1 || !verdict.history_present || verdict.enforced !== false || verdict.model_version !== candidate.candidate || verdict.threshold !== candidate.threshold) {
    throw new Error(`large-history advisory contract changed: ${JSON.stringify(verdicts)}`);
  }
  if (["timeout", "concurrency_timeout"].includes(verdict.error_code)) {
    // Inference may expire before reporting token truncation. The captured
    // history must still be present; its result must not become a safe score.
    if (verdict.unsafe_probability != null || verdict.shadow_decision !== "unavailable") {
      throw new Error(`history deadline failure was scored: ${JSON.stringify(verdict)}`);
    }
  } else {
    const score = verdict.unsafe_probability;
    if (process.env.KONTEXT_E2E_EXPECT_MERLIN_TIMEOUT === "1" || !verdict.history_omitted || !Number.isFinite(score) || score < 0 || score > 1 || verdict.error_code || verdict.shadow_decision !== (score >= candidate.threshold ? "unsafe" : "safe")) {
      throw new Error(`unexpected large-history result: ${JSON.stringify(verdict)}`);
    }
  }
  console.log(`Merlin history: ${verdict.error_code || verdict.shadow_decision}`);
});
'
  echo "ok step safety: large history recorded with bounded advisory assessment"
  # Real scoring and exact numerical parity remain mandatory in
  # TestNativeEmbeddedWorksWithoutInstalledFiles and TestCandidateMatchesPython.

  # Ordinary E2E must obtain a real score under the daemon's production
  # deadline. Use a short call in a fresh session so long history and runner
  # variance on larger inputs cannot turn this into an all-unavailable pass.
  assert_hook \
    "production-deadline scoring probe" \
    '{"session_id":"e2e-merlin-score","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"pwd"}}' \
    "observed; no local analysis wired" \
    "would allow"
  wait_for_step_safety "e2e-merlin-score" 1
  curl -fsS "${BASE_URL}/api/sessions/e2e-merlin-score/step-safety" | node -e '
const candidate = require(process.cwd() + "/internal/guard/stepsafety/model/native/candidate.json");
let raw = "";
process.stdin.on("data", chunk => raw += chunk);
process.stdin.on("end", () => {
  const verdicts = JSON.parse(raw);
  const verdict = verdicts[0];
  if (verdicts.length !== 1 || verdict.tool_name !== "Bash" || verdict.enforced !== false || verdict.model_version !== candidate.candidate || verdict.threshold !== candidate.threshold) {
    throw new Error(`scoring probe contract changed: ${JSON.stringify(verdicts)}`);
  }
  if (process.env.KONTEXT_E2E_EXPECT_MERLIN_TIMEOUT === "1") {
    if (!["timeout", "concurrency_timeout"].includes(verdict.error_code) || verdict.unsafe_probability != null || verdict.shadow_decision !== "unavailable") {
      throw new Error(`scoring probe did not preserve the forced deadline: ${JSON.stringify(verdict)}`);
    }
  } else {
    const score = verdict.unsafe_probability;
    if (verdict.error_code || !Number.isFinite(score) || score < 0 || score > 1 || verdict.shadow_decision !== (score >= candidate.threshold ? "unsafe" : "safe")) {
      throw new Error(`ordinary E2E requires a real score within the configured deadline: ${JSON.stringify(verdict)}`);
    }
  }
  console.log(`Merlin scoring probe: ${verdict.error_code || verdict.shadow_decision}, ${verdict.latency_ms} ms`);
});
'
else
  wait_for_step_safety "$SESSION_ID" 0
  echo "ok step safety: opt-out produced no model annotations"
fi

go run ./cmd/kontext guard status --daemon-url "$BASE_URL" | grep -q "0 critical"
go run ./cmd/kontext guard doctor --daemon-url "$BASE_URL" | grep -q "daemon healthy"

echo "E2E passed: hook -> local runtime -> RuntimeCore -> advisory chain -> SQLite -> daemon API"
