import { Check, TriangleAlert } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { cn } from "@/lib/utils";
import {
  actionSummary,
  dateTime,
  decisionLabel,
  decisionSource,
  decisionTone,
  humanize,
  humanReason,
  prettyTool,
  riskLevel,
  summaryOf,
  technicalExplanation,
} from "./helpers";
import { Dd, DecisionDot, Dt, RiskPill } from "./shared";
import type { ClassifierVerdict, Event, GuardMode, RiskFeedback } from "./types";

export function Inspector({
  event,
  verdict,
  mode,
  onFeedback,
  feedbackPending,
}: {
  event: Event;
  verdict?: ClassifierVerdict;
  mode: GuardMode;
  onFeedback: (actionID: string, feedback: RiskFeedback) => void;
  feedbackPending: boolean;
}) {
  const r = event.risk_event ?? {};
  const tone = decisionTone[event.decision];
  const timestamp = dateTime(event.created_at);
  const judgeResult =
    r.decision_stage === "judge_allow"
      ? "allow"
      : r.decision_stage === "judge_deny"
        ? "deny"
        : r.decision_stage === "judge_fail_open"
          ? "fail open"
          : "";
  const judgeLatency = formatDurationMs(r.judge_duration_ms);

  return (
    <div className="flex h-full min-w-0 flex-col overflow-x-hidden bg-background">
      <SheetHeader className="flex min-w-0 flex-row items-center gap-2 border-b bg-background px-6 py-3.5 pr-14 space-y-0">
        <DecisionDot kind={event.decision} />
        <SheetTitle className={cn("shrink-0 text-[13px] font-medium", tone.text)}>
          {decisionLabel(event.decision, mode)}
        </SheetTitle>
        <span className="ml-2 min-w-0 break-words font-mono text-[12px] text-muted-foreground [overflow-wrap:anywhere]">
          {prettyTool(event.tool_name)}
        </span>
      </SheetHeader>

      <ScrollArea className="min-w-0 flex-1 overflow-x-hidden">
        <div className="min-w-0 max-w-full space-y-7 overflow-x-hidden px-7 py-7">
          <div className="min-w-0 space-y-3">
            <pre className="max-w-full whitespace-pre-wrap break-words font-mono text-[15px] font-medium leading-snug tracking-tight text-foreground [overflow-wrap:anywhere]">
              {summaryOf(event)}
            </pre>
          </div>

          <dl className="grid min-w-0 grid-cols-[120px_minmax(0,1fr)] gap-y-3 text-[13px]">
            <Dt>Operation</Dt>
            <Dd>{r.operation || r.operation_class || "unknown"}</Dd>
            <Dt>Source</Dt>
            <Dd>{decisionSource(event)}</Dd>
            <Dt>Stage</Dt>
            <Dd>{r.decision_stage ? humanize(r.decision_stage) : "unknown"}</Dd>
            <Dt>Environment</Dt>
            <Dd>
              <span className="font-mono text-[12.5px]">{r.environment || "unknown"}</span>
            </Dd>
            {timestamp && (
              <>
                <Dt>Timestamp</Dt>
                <Dd>{timestamp}</Dd>
              </>
            )}
            {r.policy_version && (
              <>
                <Dt>Policy version</Dt>
                <Dd>{r.policy_version}</Dd>
              </>
            )}
            {r.policy_profile && (
              <>
                <Dt>Policy profile</Dt>
                <Dd>{humanize(r.policy_profile)}</Dd>
              </>
            )}
            {r.policy_rule_pack && (
              <>
                <Dt>Rule pack</Dt>
                <Dd>{r.policy_rule_pack}</Dd>
              </>
            )}
            {r.policy_rule_id && (
              <>
                <Dt>Policy rule</Dt>
                <Dd>{r.policy_rule_id}</Dd>
              </>
            )}
            {r.policy_rule_category && (
              <>
                <Dt>Rule category</Dt>
                <Dd>{humanize(r.policy_rule_category)}</Dd>
              </>
            )}
            {judgeResult && (
              <>
                <Dt>Judge result</Dt>
                <Dd>{judgeResult}</Dd>
              </>
            )}
            {r.judge_risk_level && (
              <>
                <Dt>Judge risk</Dt>
                <Dd>{humanize(r.judge_risk_level)}</Dd>
              </>
            )}
            {judgeLatency && (
              <>
                <Dt>Judge latency</Dt>
                <Dd>{judgeLatency}</Dd>
              </>
            )}
          </dl>

          <Section title="Reason">
            <p className="max-w-full break-words text-[13px] leading-relaxed text-foreground/80 [overflow-wrap:anywhere]">
              {humanReason(event)}
            </p>
          </Section>

          <Section title="Analysis">
            <p className="max-w-full break-words text-[13px] leading-relaxed text-foreground/80 [overflow-wrap:anywhere]">
              {technicalExplanation(event)}
            </p>
          </Section>

          <Section title="Command">
            <pre className="max-w-full whitespace-pre-wrap break-words rounded-md border bg-muted/40 px-3 py-2.5 font-mono text-[12px] leading-relaxed text-foreground/90 [overflow-wrap:anywhere]">
              {actionSummary(event)}
            </pre>
          </Section>

          {verdict && (
            <RiskAnnotationSection
              verdict={verdict}
              onFeedback={onFeedback}
              feedbackPending={feedbackPending}
            />
          )}

          {(r.signals ?? []).length > 0 && (
            <Section title="Signals">
              <div className="flex flex-wrap gap-1.5">
                {(r.signals ?? []).map((s) => (
                  <SignalChip key={s} signal={s} toneClass={tone.bg} />
                ))}
              </div>
            </Section>
          )}

          {(r.policy_signals ?? []).length > 0 && (
            <Section title="Policy Signals">
              <div className="flex flex-wrap gap-1.5">
                {(r.policy_signals ?? []).map((s) => (
                  <SignalChip key={s} signal={s} toneClass={tone.bg} />
                ))}
              </div>
            </Section>
          )}

          {event.reason_code && (
            <div className="border-t pt-4 text-[11.5px] text-muted-foreground">
              Decision code · <span className="font-mono text-foreground/70">{event.reason_code}</span>
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}

function formatRiskScore(score?: number): string {
  if (typeof score !== "number" || !Number.isFinite(score)) return "";
  return Number(score.toFixed(4)).toString();
}

// The considered feedback surface: judging a miss usually needs the full
// command, so the classifier's exact (redacted) input sits right above the
// label buttons. Shown for quiet verdicts too — a command both models missed
// can only be labelled should_block from here, and those labels matter most.
function RiskAnnotationSection({
  verdict,
  onFeedback,
  feedbackPending,
}: {
  verdict: ClassifierVerdict;
  onFeedback: (actionID: string, feedback: RiskFeedback) => void;
  feedbackPending: boolean;
}) {
  const level = riskLevel(verdict);
  const svmScore = formatRiskScore(verdict.svm?.score);
  const svmThreshold = formatRiskScore(verdict.svm?.threshold);

  return (
    <Section title="Risk annotation">
      <div className="space-y-3 rounded-md border bg-muted/20 px-3 py-3">
        <div className="flex items-center gap-2">
          {level ? (
            <RiskPill level={level} muted={Boolean(verdict.user_feedback)} />
          ) : (
            <span className="text-[12px] text-muted-foreground">Not flagged</span>
          )}
          <span className="text-[11px] text-muted-foreground/70">
            Annotation only — computed after the decision, it did not affect it.
          </span>
        </div>

        <dl className="grid min-w-0 grid-cols-[64px_minmax(0,1fr)] gap-y-2 text-[12.5px]">
          <Dt>SVM</Dt>
          <Dd>
            {verdict.svm
              ? `${humanize(verdict.svm.verdict)}${svmScore ? ` · score ${svmScore}` : ""}${svmThreshold ? ` (threshold ${svmThreshold})` : ""}`
              : "unavailable"}
          </Dd>
          <Dt>LLM</Dt>
          <Dd>
            {verdict.llm
              ? `${humanize(verdict.llm.verdict)}${verdict.llm.model ? ` · ${verdict.llm.model}` : ""}`
              : verdict.llm_error
                ? `unavailable — ${verdict.llm_error}`
                : "off"}
          </Dd>
        </dl>

        {verdict.command && (
          <pre className="max-w-full whitespace-pre-wrap break-words rounded-md border bg-background/60 px-3 py-2.5 font-mono text-[12px] leading-relaxed text-foreground/90 [overflow-wrap:anywhere]">
            {verdict.command}
            {verdict.command_truncated ? "\n… (truncated)" : ""}
          </pre>
        )}

        <div className="flex flex-wrap items-center gap-2">
          <InspectorFeedbackButton
            kind="should_allow"
            verdict={verdict}
            disabled={feedbackPending}
            onFeedback={onFeedback}
          />
          <InspectorFeedbackButton
            kind="should_block"
            verdict={verdict}
            disabled={feedbackPending}
            onFeedback={onFeedback}
          />
          {verdict.feedback_at && (
            <span className="text-[11px] text-muted-foreground/70">
              Labelled {dateTime(verdict.feedback_at)}
            </span>
          )}
        </div>
      </div>
    </Section>
  );
}

function InspectorFeedbackButton({
  kind,
  verdict,
  disabled,
  onFeedback,
}: {
  kind: RiskFeedback;
  verdict: ClassifierVerdict;
  disabled: boolean;
  onFeedback: (actionID: string, feedback: RiskFeedback) => void;
}) {
  const selected = verdict.user_feedback === kind;
  const allow = kind === "should_allow";
  return (
    <button
      type="button"
      disabled={disabled}
      aria-pressed={selected}
      onClick={() => onFeedback(verdict.action_id, kind)}
      className={cn(
        "inline-flex h-7 items-center gap-1.5 rounded-md border bg-background px-2.5 text-[12px] font-medium text-muted-foreground transition-colors disabled:opacity-50",
        allow ? "hover:border-brand/40 hover:text-brand" : "hover:border-destructive/40 hover:text-destructive",
        selected && (allow
          ? "border-brand/40 bg-brand-light/60 text-brand"
          : "border-destructive/40 bg-destructive/10 text-destructive"),
      )}
    >
      {allow ? <Check className="h-3 w-3" /> : <TriangleAlert className="h-3 w-3" />}
      {allow ? "Fine" : "Should’ve blocked"}
    </button>
  );
}

function SignalChip({ signal, toneClass }: { signal: string; toneClass: string }) {
  return (
    <span className="inline-flex max-w-full min-w-0 items-start gap-1.5 rounded-md border bg-card px-2 py-1 font-mono text-[11px] text-foreground/80 shadow-[inset_0_1px_0_rgba(255,255,255,0.7)]">
      <span className={cn("mt-[0.45em] h-1 w-1 shrink-0 rounded-full", toneClass)} />
      <span className="min-w-0 break-words [overflow-wrap:anywhere]">{humanize(signal)}</span>
    </span>
  );
}

function formatDurationMs(value?: number): string {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "";
  if (value < 1000) return `${Math.round(value)} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 max-w-full space-y-2.5 overflow-x-hidden">
      <h3 className="text-[11.5px] font-medium text-muted-foreground">
        {title}
      </h3>
      {children}
    </div>
  );
}
