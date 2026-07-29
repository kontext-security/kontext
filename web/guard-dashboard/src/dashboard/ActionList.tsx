import { useState } from "react";
import { Check, ChevronDown, Shield, TriangleAlert, X } from "lucide-react";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import {
  decisionLabel,
  decisionSource,
  decisionTone,
  prettyTool,
  riskBreakdown,
  riskLevel,
  summaryOf,
} from "./helpers";
import { DecisionDot, RiskPill } from "./shared";
import { DECISIONS } from "./types";
import type {
  ClassifierVerdict,
  Decision,
  Event,
  EventGroups,
  GuardMode,
  RiskFeedback,
  Tab,
  VerdictsByAction,
} from "./types";

const VISIBLE_KINDS = {
  all: DECISIONS,
  deny: ["deny"],
  allow: ["allow"],
} satisfies Record<Tab, readonly Decision[]>;

export function ActionList({
  tab,
  decisionGroups,
  verdicts,
  openId,
  onOpen,
  onClearFilter,
  mode,
  onFeedback,
  feedbackPendingID,
}: {
  tab: Tab;
  decisionGroups: EventGroups;
  verdicts: VerdictsByAction;
  openId: string | null;
  onOpen: (id: string) => void;
  onClearFilter: () => void;
  mode: GuardMode;
  onFeedback: (actionID: string, feedback: RiskFeedback) => void;
  feedbackPendingID: string | null;
}) {
  const visibleDecisionGroups = VISIBLE_KINDS[tab]
    .map((kind) => ({ kind, items: decisionGroups[kind] }))
    .filter(({ items }) => items.length > 0);
  const decisionCount = DECISIONS.reduce((sum, kind) => sum + decisionGroups[kind].length, 0);
  const filterLabel = tab !== "all" ? decisionLabel(tab, mode) : null;

  return (
    <section className="min-w-0 overflow-hidden rounded-xl border bg-card shadow-[inset_0_1px_0_rgba(255,255,255,0.8),0_1px_2px_rgba(0,0,0,0.04)]">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-3 border-b px-5 py-3">
        <div className="flex min-w-0 items-baseline gap-2">
          <span className="text-[13px] font-medium text-foreground">Decision Log</span>
          <span className="font-mono text-[11px] tabular-nums text-muted-foreground">
            {decisionCount}
          </span>
        </div>

        {filterLabel && (
          <button
            type="button"
            onClick={onClearFilter}
            className="inline-flex h-7 items-center gap-1.5 rounded-md border bg-background px-2.5 text-[12px] text-muted-foreground transition-colors hover:text-foreground"
          >
            <span>Filtered: <span className="text-foreground">{filterLabel}</span></span>
            <X className="h-3 w-3" />
          </button>
        )}
      </div>

      <div className="grid">
        {decisionCount === 0 ? (
          <Empty
            title="No decisions captured yet."
            description="Pre-tool Guard decisions will appear here."
          />
        ) : visibleDecisionGroups.length === 0 ? (
          <Empty
            title={`No ${filterLabel?.toLowerCase() ?? "matching"} decisions.`}
            description="Clear the filter to show all decisions."
          />
        ) : (
          visibleDecisionGroups.map(({ kind, items }, index) => (
            <Group
              key={kind}
              label={decisionLabel(kind, mode)}
              count={items.length}
              separated={index > 0}
            >
              {items.map((e) => (
                <Row
                  key={e.id}
                  event={e}
                  verdict={verdicts[e.id]}
                  active={openId === e.id}
                  onClick={() => onOpen(e.id)}
                  onFeedback={onFeedback}
                  feedbackPending={feedbackPendingID === e.id}
                />
              ))}
            </Group>
          ))
        )}
      </div>
    </section>
  );
}

function Empty({
  title = "No decisions captured yet.",
  description = "Start Claude Code to populate this view.",
}: {
  title?: string;
  description?: string;
}) {
  return (
    <div className="flex min-h-[320px] flex-col items-center justify-center gap-2 px-8 py-16 text-center text-muted-foreground">
      <Shield className="h-5 w-5 text-muted-foreground/50" />
      <p className="text-[13px]">{title}</p>
      <p className="text-[12px] text-muted-foreground/70">{description}</p>
    </div>
  );
}

function Group({
  label,
  count,
  separated = false,
  children,
}: {
  label: string;
  count: number;
  separated?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(true);
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger
        className={cn(
          "flex w-full items-center gap-2 border-b bg-muted/40 px-5 py-2.5 text-left text-[13px] font-medium text-muted-foreground transition-colors hover:bg-muted/40",
          separated && "border-t",
        )}
      >
        <ChevronDown
          className={cn("h-3 w-3 transition-transform", !open && "-rotate-90")}
        />
        <span className="text-foreground">{label}</span>
        <span className="tabular-nums text-[11px] text-muted-foreground">{count}</span>
      </CollapsibleTrigger>
      <CollapsibleContent className="overflow-hidden data-[state=closed]:animate-collapsible-up data-[state=open]:animate-collapsible-down">
        <div>{children}</div>
      </CollapsibleContent>
    </Collapsible>
  );
}

function Row({
  event,
  verdict,
  active,
  onClick,
  onFeedback,
  feedbackPending,
}: {
  event: Event;
  verdict?: ClassifierVerdict;
  active: boolean;
  onClick: () => void;
  onFeedback: (actionID: string, feedback: RiskFeedback) => void;
  feedbackPending: boolean;
}) {
  const target = summaryOf(event);
  const signal = event.risk_event?.signals?.[0]?.replace(/_/g, " ");
  const tone = decisionTone[event.decision];
  const risk = riskLevel(verdict);
  return (
    // A div with button semantics: the row hosts the real feedback <button>s,
    // and interactive elements must not nest.
    <div
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(e) => {
        if (e.target !== e.currentTarget) return;
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onClick();
        }
      }}
      className={cn(
        "group relative grid w-full cursor-pointer grid-cols-[10px_minmax(0,1fr)_auto] items-center gap-4 border-b px-10 py-3 text-left transition-colors last:border-b-0",
        "hover:bg-muted/40",
        active && "bg-accent",
      )}
    >
      {active && <span className="absolute inset-y-0 left-0 w-[2px] bg-brand" />}
      <DecisionDot kind={event.decision} />
      {/* overflow-hidden: when the right cluster squeezes this column away,
          the tool name clips instead of painting over the neighboring cells. */}
      <span className="flex min-w-0 items-baseline gap-2.5 overflow-hidden">
        <span className="text-[12px] font-medium text-foreground">{prettyTool(event.tool_name)}</span>
        <span className="truncate font-mono text-[12px] text-muted-foreground">{target}</span>
      </span>
      <span className="flex items-center gap-3">
        {signal && (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="hidden max-w-[180px] truncate text-[11px] text-muted-foreground md:inline">
                {signal}
              </span>
            </TooltipTrigger>
            <TooltipContent side="top">Primary signal: {signal}</TooltipContent>
          </Tooltip>
        )}
        {risk && verdict && (
          <span className="group/risk flex items-center gap-1.5">
            <Tooltip>
              <TooltipTrigger asChild>
                <RiskPill level={risk} muted={Boolean(verdict.user_feedback)} />
              </TooltipTrigger>
              <TooltipContent side="top">{riskBreakdown(verdict)}</TooltipContent>
            </Tooltip>
            {/* Space stays reserved so revealing the buttons never shifts the
                row; below lg the reservation would starve the summary column,
                so labelling moves to the Inspector alone. */}
            <span className="pointer-events-none hidden items-center gap-1 opacity-0 transition-opacity lg:flex group-hover/risk:pointer-events-auto group-hover/risk:opacity-100 group-focus-within/risk:pointer-events-auto group-focus-within/risk:opacity-100">
              <RiskFeedbackButton
                kind="should_allow"
                verdict={verdict}
                disabled={feedbackPending}
                onFeedback={onFeedback}
              />
              <RiskFeedbackButton
                kind="should_block"
                verdict={verdict}
                disabled={feedbackPending}
                onFeedback={onFeedback}
              />
            </span>
          </span>
        )}
        <span
          className={cn(
            "rounded-md border bg-background/60 px-1.5 py-0.5 font-mono text-[10.5px] font-medium",
            tone.border,
            event.decision === "allow" ? "text-muted-foreground" : tone.text,
          )}
        >
          {decisionSource(event)}
        </span>
        <ChevronDown
          className={cn(
            "h-3 w-3 -rotate-90 text-muted-foreground/0 transition-all group-hover:text-muted-foreground/70",
            active && "text-muted-foreground/70",
          )}
        />
      </span>
    </div>
  );
}

// One-click ground-truth label on the risk annotation: ✓ the flag was fine
// (should_allow) or ⚠ Guard should have blocked this (should_block).
// Relabeling stays possible after a click — the active label just highlights.
function RiskFeedbackButton({
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
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          disabled={disabled}
          aria-label={allow ? "Mark as fine" : "Mark as should have blocked"}
          aria-pressed={selected}
          onClick={(e) => {
            e.stopPropagation();
            onFeedback(verdict.action_id, kind);
          }}
          className={cn(
            "flex h-5 w-5 items-center justify-center rounded-md border bg-background text-muted-foreground transition-colors disabled:opacity-50",
            allow ? "hover:border-brand/40 hover:text-brand" : "hover:border-destructive/40 hover:text-destructive",
            selected && (allow
              ? "border-brand/40 bg-brand-light/60 text-brand"
              : "border-destructive/40 bg-destructive/10 text-destructive"),
          )}
        >
          {allow ? <Check className="h-3 w-3" /> : <TriangleAlert className="h-3 w-3" />}
        </button>
      </TooltipTrigger>
      <TooltipContent side="top">
        {allow ? "Fine — this command was OK" : "Should’ve blocked this"}
      </TooltipContent>
    </Tooltip>
  );
}
