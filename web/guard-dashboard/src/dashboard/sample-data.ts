import type { ClassifierVerdict, Event, PolicyProfile, RiskEvent, Session } from "./types";

export const SAMPLE_SESSION_ID = "session-local-guard-preview";
const SAMPLE_POLICY_VERSION = "guard-policy-v1";
const SAMPLE_POLICY_PROFILE = "balanced";
const SAMPLE_RULE_PACK = "guard-default";
const SAMPLE_RISK_POLICY = {
  policy_version: SAMPLE_POLICY_VERSION,
  policy_profile: SAMPLE_POLICY_PROFILE,
  policy_rule_pack: SAMPLE_RULE_PACK,
} satisfies Pick<RiskEvent, "policy_version" | "policy_profile" | "policy_rule_pack">;

export const SAMPLE_POLICY: PolicyProfile = {
  profile: SAMPLE_POLICY_PROFILE,
  recommended_profile: SAMPLE_POLICY_PROFILE,
  version: SAMPLE_POLICY_VERSION,
  rule_pack: SAMPLE_RULE_PACK,
  loaded_at: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
};

export const SAMPLE_SESSIONS: Session[] = [
  {
    session_id: SAMPLE_SESSION_ID,
    actions: 6,
    current: true,
    status: "open",
    mode: "observe",
    created_at: new Date(Date.now() - 8 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 1 * 60 * 1000).toISOString(),
  },
];

export const SAMPLE_EVENTS: Event[] = [
  {
    id: "evt-prod-mutation-001",
    session_id: SAMPLE_SESSION_ID,
    tool_name: "Bash",
    decision: "deny",
    reason_code: "production_mutation",
    reason: "Production mutation blocked by deterministic policy.",
    created_at: new Date(Date.now() - 7 * 60 * 1000).toISOString(),
    risk_event: {
      type: "provider_operation",
      operation: "delete",
      operation_class: "write",
      environment: "production",
      command_summary: "kubectl delete deployment checkout-api -n production",
      signals: ["production", "mutation", "persistent_resource"],
      guard_id: "guard.production_mutation.v1",
      decision_stage: "deterministic_deny",
      ...SAMPLE_RISK_POLICY,
      policy_rule_id: "guard.production_mutation.v1",
      policy_rule_category: "production_mutation",
      policy_signals: ["production", "mutation"],
    },
  },
  {
    id: "evt-credential-read-001",
    session_id: SAMPLE_SESSION_ID,
    tool_name: "Read",
    decision: "deny",
    reason_code: "credential_access_without_intent",
    reason: "Credential access blocked by deterministic policy.",
    created_at: new Date(Date.now() - 6 * 60 * 1000).toISOString(),
    risk_event: {
      type: "credential_access",
      operation: "read",
      environment: "local",
      path_class: "~/.aws/credentials",
      command_summary: "Read local AWS credentials without explicit user intent",
      signals: ["credential_path", "credential_observed"],
      guard_id: "guard.credential_access.v1",
      decision_stage: "deterministic_deny",
      ...SAMPLE_RISK_POLICY,
      policy_rule_id: "guard.credential_access.v1",
      policy_rule_category: "credential_access",
      policy_signals: ["credential_file_path"],
    },
  },
  {
    id: "evt-admin-reindex-001",
    session_id: SAMPLE_SESSION_ID,
    tool_name: "Bash",
    decision: "deny",
    reason_code: "judge_deny",
    reason: "Local judge denied a risky staging admin mutation.",
    created_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    risk_event: {
      type: "normal_tool_call",
      operation: "network_write",
      operation_class: "write",
      environment: "staging",
      command_summary: "curl -X POST $PAYMENTS_ADMIN_URL/reindex",
      signals: ["network_call", "admin_endpoint"],
      decision_stage: "judge_deny",
      ...SAMPLE_RISK_POLICY,
      judge_duration_ms: 284,
      judge_risk_level: "high",
      judge_categories: ["admin_mutation"],
    },
  },
  {
    id: "evt-private-key-decrypt-001",
    session_id: SAMPLE_SESSION_ID,
    tool_name: "Bash",
    decision: "deny",
    reason_code: "unknown_high_risk_command",
    reason: "Unknown high-risk command blocked by deterministic policy.",
    created_at: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
    risk_event: {
      type: "unknown",
      operation: "shell",
      operation_class: "unknown",
      environment: "local",
      command_summary: "openssl rsautl -decrypt -inkey private.pem -in payload.bin",
      signals: ["unknown_high_risk", "credential_observed"],
      guard_id: "guard.unknown_high_risk.v1",
      decision_stage: "deterministic_deny",
      ...SAMPLE_RISK_POLICY,
      policy_rule_id: "guard.unknown_high_risk.v1",
      policy_rule_category: "unknown_high_risk",
      policy_signals: ["unknown_high_risk", "credential_observed"],
    },
  },
  {
    id: "evt-readme-allow-001",
    session_id: SAMPLE_SESSION_ID,
    tool_name: "Read",
    decision: "allow",
    reason_code: "workspace_read",
    reason: "Workspace read permitted by deterministic policy.",
    created_at: new Date(Date.now() - 3.5 * 60 * 1000).toISOString(),
    risk_event: {
      type: "normal_tool_call",
      operation: "read",
      environment: "local",
      path_class: "workspace_file",
      command_summary: "Read README.md",
      signals: ["workspace_file", "documentation_read"],
      guard_id: "guard.workspace_read.v1",
      decision_stage: "deterministic_allow",
      ...SAMPLE_RISK_POLICY,
      policy_rule_id: "guard.workspace_read.v1",
      policy_rule_category: "workspace_read",
      policy_signals: ["workspace_file"],
    },
  },
  {
    id: "evt-bash-allow-001",
    session_id: SAMPLE_SESSION_ID,
    tool_name: "Bash",
    decision: "allow",
    reason_code: "known_safe_command",
    reason: "Local judge allowed a low-risk read-only command.",
    created_at: new Date(Date.now() - 3.2 * 60 * 1000).toISOString(),
    risk_event: {
      type: "normal_tool_call",
      operation: "shell",
      operation_class: "read",
      environment: "local",
      command_summary: "git status --short",
      signals: ["known_safe_command", "local_workspace"],
      decision_stage: "judge_allow",
      ...SAMPLE_RISK_POLICY,
      judge_duration_ms: 142,
      judge_risk_level: "low",
    },
  },
];

const SAMPLE_GUARDRAIL_MODEL = "Qwen/Qwen3-0.6B-GGUF";

// One verdict per intercepted bash command, keyed to the event ids above.
// Covers every pill state: both models risky (high), split verdicts (check),
// LLM unavailable (check on the SVM alone), and both quiet (no pill).
export const SAMPLE_VERDICTS: ClassifierVerdict[] = [
  {
    action_id: "evt-prod-mutation-001",
    command: "kubectl delete deployment checkout-api -n production",
    svm: { verdict: "risky", score: 0.9114, threshold: 0.4, model_version: "svm-v1" },
    llm: { verdict: "risky", raw: "RISKY", model: SAMPLE_GUARDRAIL_MODEL, duration_ms: 212 },
    created_at: new Date(Date.now() - 7 * 60 * 1000).toISOString(),
  },
  {
    action_id: "evt-private-key-decrypt-001",
    command: "openssl rsautl -decrypt -inkey private.pem -in payload.bin",
    svm: { verdict: "not_risky", score: 0.0001, threshold: 0.4, model_version: "svm-v1" },
    llm: { verdict: "risky", raw: "RISKY", model: SAMPLE_GUARDRAIL_MODEL, duration_ms: 187 },
    created_at: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
  },
  {
    action_id: "evt-admin-reindex-001",
    command: "curl -X POST $PAYMENTS_ADMIN_URL/reindex",
    svm: { verdict: "risky", score: 0.6231, threshold: 0.4, model_version: "svm-v1" },
    llm_error: "guardrail request timed out",
    created_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
  },
  {
    action_id: "evt-bash-allow-001",
    command: "git status --short",
    svm: { verdict: "not_risky", score: 0.0003, threshold: 0.4, model_version: "svm-v1" },
    llm: { verdict: "not_risky", raw: "NOT_RISKY", model: SAMPLE_GUARDRAIL_MODEL, duration_ms: 94 },
    created_at: new Date(Date.now() - 3.2 * 60 * 1000).toISOString(),
  },
];
