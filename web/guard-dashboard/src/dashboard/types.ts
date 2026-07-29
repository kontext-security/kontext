export const DECISIONS = ["deny", "allow"] as const;
export type Decision = (typeof DECISIONS)[number];

export const GUARD_MODES = ["observe", "enforce"] as const;
export type GuardMode = (typeof GUARD_MODES)[number];

export type Tab = "all" | Decision;

export const POLICY_PROFILE_IDS = ["relaxed", "balanced", "strict"] as const;
export type PolicyProfileID = (typeof POLICY_PROFILE_IDS)[number];

export function isDecision(value: unknown): value is Decision {
  return typeof value === "string" && (DECISIONS as readonly string[]).includes(value);
}

export function isGuardMode(value: unknown): value is GuardMode {
  return typeof value === "string" && (GUARD_MODES as readonly string[]).includes(value);
}

export function isPolicyProfileID(value: unknown): value is PolicyProfileID {
  return typeof value === "string" && (POLICY_PROFILE_IDS as readonly string[]).includes(value);
}

export const RISK_VERDICTS = ["risky", "not_risky"] as const;
export type RiskVerdict = (typeof RISK_VERDICTS)[number];

export const RISK_FEEDBACK = ["should_allow", "should_block"] as const;
export type RiskFeedback = (typeof RISK_FEEDBACK)[number];

// Both models risky → high, exactly one → check. Ordinary commands get no
// level at all so the risk column stays quiet.
export type RiskLevel = "high" | "check";

export function isRiskVerdict(value: unknown): value is RiskVerdict {
  return typeof value === "string" && (RISK_VERDICTS as readonly string[]).includes(value);
}

export function isRiskFeedback(value: unknown): value is RiskFeedback {
  return typeof value === "string" && (RISK_FEEDBACK as readonly string[]).includes(value);
}

export type SVMVerdict = {
  verdict: RiskVerdict;
  score?: number;
  threshold?: number;
  model_version?: string;
};

export type LLMVerdict = {
  verdict: RiskVerdict;
  raw?: string;
  model?: string;
  duration_ms?: number;
  cached?: boolean;
};

// One observe-mode classifier record per intercepted bash command. This is an
// annotation computed after the decision — it was never part of it, so the UI
// must not present it as an action Guard took. The LLM half is absent when the
// guardrail is off or failed; llm_error says why.
export type ClassifierVerdict = {
  action_id: string;
  command?: string;
  command_truncated?: boolean;
  svm?: SVMVerdict;
  llm?: LLMVerdict;
  llm_error?: string;
  user_feedback?: RiskFeedback;
  created_at?: string;
  feedback_at?: string;
};

// Keyed by action_id, which matches Event.id from the events endpoint.
export type VerdictsByAction = Record<string, ClassifierVerdict>;

export type RiskEvent = {
  type?: string;
  provider?: string;
  provider_category?: string;
  operation?: string;
  operation_class?: string;
  resource_class?: string;
  environment?: string;
  credential_observed?: boolean;
  credential_source?: string;
  direct_api_call?: boolean;
  explicit_user_intent?: boolean;
  command_summary?: string;
  request_summary?: string;
  path_class?: string;
  decision?: Decision;
  reason_code?: string;
  decision_stage?: string;
  signals?: string[];
  guard_id?: string;
  confidence?: number;
  policy_version?: string;
  policy_profile?: string;
  policy_rule_pack?: string;
  policy_rule_id?: string;
  policy_rule_category?: string;
  policy_signals?: string[];
  judge_runtime?: string;
  judge_model?: string;
  judge_duration_ms?: number;
  judge_failure_kind?: string;
  judge_risk_level?: string;
  judge_categories?: string[];
};

export type Event = {
  id: string;
  session_id?: string;
  tool_name?: string;
  decision: Decision;
  reason?: string;
  reason_code?: string;
  created_at?: string;
  risk_event?: RiskEvent;
};

export type Session = {
  session_id: string;
  actions: number;
  latest_at?: string;
  status?: string;
  created_at?: string;
  updated_at?: string;
  closed_at?: string;
  current?: boolean;
  mode?: GuardMode;
};

export type PolicyProfile = {
  profile: PolicyProfileID;
  recommended_profile?: PolicyProfileID;
  version?: string;
  rule_pack?: string;
  rule_pack_version?: string;
  config_digest?: string;
  activation_id?: string;
  source?: string;
  status?: string;
  loaded_at?: string;
};

export type PolicyProfileDef = {
  id: PolicyProfileID;
  label: string;
  lede: string;
  hint: string;
  recommended?: boolean;
};

export type Counts = {
  all: number;
  deny: number;
  allow: number;
};

export type EventGroups = Record<Decision, Event[]>;

export type EventBuckets = {
  counts: Counts;
  groups: EventGroups;
};
