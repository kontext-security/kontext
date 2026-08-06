// Kontext managed extension for Prime Agent. Do not edit: `kontext setup`
// owns this file and overwrites it on reinstall.
//
// Maps Prime Agent extension events onto the Kontext hook contract using the
// Claude Code hook-input wire format, and enforces policy decisions at the
// synchronous pre-tool-use boundary (`tool_call`). All other events are
// recorded for the authorization ledger but never hold up the agent.
//
// marker: kontext-managed-prime-agent-extension v1

import { execFile } from "node:child_process";

const KONTEXT_BINARY = "__KONTEXT_BINARY__";
const AGENT = "prime-agent";
// Matches DefaultHookTimeout (20s) in claudemanaged and codexmanaged.
const HOOK_TIMEOUT_MS = 20_000;

type HookOutput = {
  hookSpecificOutput?: {
    hookEventName?: string;
    permissionDecision?: string;
    permissionDecisionReason?: string;
    updatedInput?: Record<string, unknown>;
  };
};

// Reset on session_start so each session gets its own unavailability warning
// even when one Prime Agent process hosts several sessions (reload/resume).
let warnedUnavailable = false;

function runHook(
  eventAlias: string,
  payload: Record<string, unknown>,
  ctx: { ui?: { notify?: (msg: string, level: string) => void } },
): Promise<HookOutput | null> {
  return new Promise((resolve) => {
    const child = execFile(
      KONTEXT_BINARY,
      ["hook", "--agent", AGENT, eventAlias],
      { timeout: HOOK_TIMEOUT_MS },
      (error, stdout) => {
        if (error) {
          // Fail open: never brick the agent when the local runtime is
          // unavailable, but surface it once per session.
          if (!warnedUnavailable) {
            warnedUnavailable = true;
            ctx.ui?.notify?.(
              `Kontext hook unavailable (${String(error.message ?? error).slice(0, 200)}); actions are not being recorded`,
              "warning",
            );
          }
          resolve(null);
          return;
        }
        try {
          resolve(JSON.parse(stdout) as HookOutput);
        } catch {
          resolve(null);
        }
      },
    );
    // Fail open on stream errors too: if the child exits before reading
    // stdin (or spawn fails), the write must not crash the host agent.
    child.stdin?.on("error", () => {});
    child.stdin?.end(JSON.stringify(payload));
  });
}

function basePayload(hookEventName: string, ctx: any): Record<string, unknown> {
  let sessionId = "";
  try {
    sessionId = ctx.sessionManager?.getSessionId?.() ?? "";
  } catch {
    sessionId = "";
  }
  return {
    session_id: sessionId,
    hook_event_name: hookEventName,
    cwd: ctx.cwd ?? "",
  };
}

export default function (pi: any) {
  pi.on("session_start", async (_event: any, ctx: any) => {
    warnedUnavailable = false;
    await runHook("session-start", basePayload("SessionStart", ctx), ctx);
  });

  pi.on("session_shutdown", async (_event: any, ctx: any) => {
    await runHook("session-end", basePayload("SessionEnd", ctx), ctx);
  });

  pi.on("input", async (event: any, ctx: any) => {
    // Recorded for the ledger; prompt submission is observe-only in v1.
    if (event.source === "extension") return { action: "continue" };
    await runHook("user-prompt-submit", {
      ...basePayload("UserPromptSubmit", ctx),
      prompt: event.text ?? "",
    }, ctx);
    return { action: "continue" };
  });

  pi.on("tool_call", async (event: any, ctx: any) => {
    const output = await runHook("pre-tool-use", {
      ...basePayload("PreToolUse", ctx),
      tool_name: event.toolName ?? "",
      tool_input: event.input ?? {},
      tool_use_id: event.toolCallId ?? "",
    }, ctx);

    const decision = output?.hookSpecificOutput;
    if (!decision) return; // fail open

    if (decision.permissionDecision === "deny") {
      return {
        block: true,
        reason: decision.permissionDecisionReason || "Blocked by Kontext access policy.",
      };
    }
    if (
      decision.updatedInput &&
      typeof decision.updatedInput === "object" &&
      event.input &&
      typeof event.input === "object"
    ) {
      for (const key of Object.keys(event.input)) delete event.input[key];
      Object.assign(event.input, decision.updatedInput);
    }
  });

  pi.on("tool_result", async (event: any, ctx: any) => {
    const failed = event.isError === true;
    const payload: Record<string, unknown> = {
      ...basePayload(failed ? "PostToolUseFailure" : "PostToolUse", ctx),
      tool_name: event.toolName ?? "",
      tool_input: event.input ?? {},
      tool_use_id: event.toolCallId ?? "",
      tool_response: { content: event.content ?? [], isError: failed },
    };
    if (failed) payload.error = "tool execution failed";
    await runHook(failed ? "post-tool-use-failure" : "post-tool-use", payload, ctx);
  });

  pi.on("agent_end", async (_event: any, ctx: any) => {
    await runHook("stop", basePayload("Stop", ctx), ctx);
  });
}
