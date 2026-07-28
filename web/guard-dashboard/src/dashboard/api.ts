import { API } from "./config";
import { isDecision, isGuardMode } from "./types";
import type {Decision, Event, GuardMode, RiskEvent, Session} from "./types";

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function responseJSON(r: Response): Promise<unknown> {
  return r.json() as Promise<unknown>;
}

async function ok(r: Response): Promise<unknown> {
  if (r.ok) return responseJSON(r);
  const fallback = `${r.status} ${r.statusText}`.trim();
  const contentType = r.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error(fallback);
  }

  let body: unknown;
  try {
    body = await responseJSON(r);
  } catch (error) {
    throw new Error(`API error response was not valid JSON: ${fallback}; ${errorMessage(error)}`);
  }

  const reason = isObject(body) && typeof body.error === "string" ? body.error : fallback;
  throw new Error(reason);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function optionalBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function optionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stringList(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const strings = value.filter((item): item is string => typeof item === "string");
  return strings.length > 0 ? strings : undefined;
}

function decision(value: unknown): Decision | undefined {
  if (isDecision(value)) return value;
  return undefined;
}


function guardMode(value: unknown): GuardMode | undefined {
  return isGuardMode(value) ? value : undefined;
}

function parseRiskEvent(value: unknown): RiskEvent | undefined {
  if (!isObject(value)) return undefined;
  return {
    type: optionalString(value.type),
    provider: optionalString(value.provider),
    provider_category: optionalString(value.provider_category),
    operation: optionalString(value.operation),
    operation_class: optionalString(value.operation_class),
    resource_class: optionalString(value.resource_class),
    environment: optionalString(value.environment),
    credential_observed: optionalBoolean(value.credential_observed),
    credential_source: optionalString(value.credential_source),
    direct_api_call: optionalBoolean(value.direct_api_call),
    explicit_user_intent: optionalBoolean(value.explicit_user_intent),
    command_summary: optionalString(value.command_summary),
    request_summary: optionalString(value.request_summary),
    path_class: optionalString(value.path_class),
    decision: decision(value.decision),
    reason_code: optionalString(value.reason_code),
    decision_stage: optionalString(value.decision_stage),
    signals: stringList(value.signals),
    guard_id: optionalString(value.guard_id),
    confidence: optionalNumber(value.confidence),
    policy_version: optionalString(value.policy_version),
    policy_profile: optionalString(value.policy_profile),
    policy_rule_pack: optionalString(value.policy_rule_pack),
    policy_rule_id: optionalString(value.policy_rule_id),
    policy_rule_category: optionalString(value.policy_rule_category),
    policy_signals: stringList(value.policy_signals),
    judge_runtime: optionalString(value.judge_runtime),
    judge_model: optionalString(value.judge_model),
    judge_duration_ms: optionalNumber(value.judge_duration_ms),
    judge_failure_kind: optionalString(value.judge_failure_kind),
    judge_risk_level: optionalString(value.judge_risk_level),
    judge_categories: stringList(value.judge_categories),
  };
}

function parseSession(value: unknown): Session | undefined {
  if (
    !isObject(value) ||
    typeof value.session_id !== "string" ||
    typeof value.actions !== "number"
  ) {
    return undefined;
  }
  const mode = guardMode(value.mode);
  if (value.mode !== undefined && !mode) return undefined;
  const current = value.current === true;
  if (current && !mode) return undefined;
  return {
    session_id: value.session_id,
    actions: value.actions,
    latest_at: optionalString(value.latest_at),
    status: optionalString(value.status),
    created_at: optionalString(value.created_at),
    updated_at: optionalString(value.updated_at),
    closed_at: optionalString(value.closed_at),
    current,
    mode,
  };
}

function parseEvent(value: unknown): Event | undefined {
  if (!isObject(value) || typeof value.id !== "string") return undefined;
  const parsedDecision = decision(value.decision);
  if (!parsedDecision) return undefined;
  return {
    id: value.id,
    session_id: optionalString(value.session_id),
    tool_name: optionalString(value.tool_name),
    decision: parsedDecision,
    reason: optionalString(value.reason),
    reason_code: optionalString(value.reason_code),
    created_at: optionalString(value.created_at),
    risk_event: parseRiskEvent(value.risk_event),
  };
}


function parseList<T>(value: unknown, parse: (item: unknown) => T | undefined): T[] {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new Error("invalid API response");
  const items: T[] = [];
  for (const item of value) {
    const parsed = parse(item);
    if (!parsed) throw new Error("invalid API response");
    items.push(parsed);
  }
  return items;
}

export async function fetchSessions(): Promise<Session[]> {
  return parseList(await fetch(`${API}/api/sessions`).then(ok), parseSession);
}

export async function fetchEvents(sessionID: string): Promise<Event[]> {
  return parseList(
    await fetch(`${API}/api/sessions/${encodeURIComponent(sessionID)}/events`).then(ok),
    parseEvent,
  );
}

