import { forwardRef } from "react";
import { cn } from "@/lib/utils";
import { decisionTone } from "./helpers";
import type { Decision, RiskLevel } from "./types";

export function DecisionDot({ kind, className }: { kind: Decision; className?: string }) {
  const tone = decisionTone[kind];
  return (
    <span
      className={cn("h-2 w-2 shrink-0 rounded-full ring-4", tone.bg, tone.ring, className)}
    />
  );
}

export const riskTone: Record<RiskLevel, { pill: string; dot: string }> = {
  high: { pill: "border-red-200 bg-red-50 text-red-700", dot: "bg-red-500" },
  check: { pill: "border-amber-200 bg-amber-50 text-amber-800", dot: "bg-amber-500" },
};

// The risk annotation pill. Deliberately styled apart from the decision-source
// badge (rounded-full, tinted, sans): the annotation was computed after the
// decision and must not read as an action Guard took. forwardRef so Radix
// `asChild` triggers can attach to it.
export const RiskPill = forwardRef<
  HTMLSpanElement,
  { level: RiskLevel; muted?: boolean; className?: string } & React.HTMLAttributes<HTMLSpanElement>
>(function RiskPill({ level, muted = false, className, ...props }, ref) {
  return (
    <span
      ref={ref}
      {...props}
      className={cn(
        "inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2 py-[3px] text-[10.5px] font-medium leading-none",
        muted ? "border-border bg-muted text-muted-foreground" : riskTone[level].pill,
        className,
      )}
    >
      <span
        className={cn(
          "h-1 w-1 rounded-full",
          muted ? "bg-muted-foreground/50" : riskTone[level].dot,
        )}
      />
      {level}
    </span>
  );
});

export function Block({
  label,
  description,
  children,
}: {
  label?: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mt-8 first:mt-0">
      {(label || description) && (
        <div className="mb-3.5 flex items-baseline gap-3">
          {label && (
            <h2 className="text-[15px] font-semibold tracking-tight">{label}</h2>
          )}
          {description && (
            <span className="text-[12.5px] text-muted-foreground">{description}</span>
          )}
        </div>
      )}
      {children}
    </section>
  );
}

export function Kv({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-2">
      <span className="text-muted-foreground">{k}</span>
      <span className="font-mono">{v}</span>
    </div>
  );
}

export function Dt({ children }: { children: React.ReactNode }) {
  return (
    <dt className="self-center break-words text-[12px] text-muted-foreground [overflow-wrap:anywhere]">
      {children}
    </dt>
  );
}

export function Dd({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <dd className={cn("min-w-0 break-words text-foreground/90 [overflow-wrap:anywhere]", className)}>
      {children}
    </dd>
  );
}
