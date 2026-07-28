export const DECISIONS = ["deny", "allow"] as const;
export type Decision = (typeof DECISIONS)[number];

export const GUARD_MODES = ["observe", "enforce"] as const;
export type GuardMode = (typeof GUARD_MODES)[number];

export type Tab = "all" | Decision;


export function isDecision(value: unknown): value is Decision {
  return typeof value === "string" && (DECISIONS as readonly string[]).includes(value);
}

export function isGuardMode(value: unknown): value is GuardMode {
  return typeof value === "string" && (GUARD_MODES as readonly string[]).includes(value);
}


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
