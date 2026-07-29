import { useEffect, useMemo, useRef, useState } from "react";
import { AlertCircle } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent } from "@/components/ui/sheet";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ActionList } from "@/dashboard/ActionList";
import {
  activatePolicy,
  errorMessage,
  fetchEvents,
  fetchPolicy,
  fetchSessions,
  fetchVerdicts,
  sendVerdictFeedback,
} from "@/dashboard/api";
import { API, USE_SAMPLE_DATA } from "@/dashboard/config";
import { bucket, sameSessions, verdictsByAction } from "@/dashboard/helpers";
import { Inspector } from "@/dashboard/Inspector";
import { PolicyPanel } from "@/dashboard/PolicyPanel";
import {
  SAMPLE_EVENTS,
  SAMPLE_POLICY,
  SAMPLE_SESSION_ID,
  SAMPLE_SESSIONS,
  SAMPLE_VERDICTS,
} from "@/dashboard/sample-data";
import { SessionHeader } from "@/dashboard/SessionHeader";
import { Sidebar } from "@/dashboard/Sidebar";
import { StatRow } from "@/dashboard/StatRow";
import { Block } from "@/dashboard/shared";
import type {
  ClassifierVerdict,
  Event,
  GuardMode,
  PolicyProfile,
  PolicyProfileID,
  RiskFeedback,
  Session,
  Tab,
} from "@/dashboard/types";

export default function App() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedSessionID, setSelectedSessionID] = useState("");
  const [events, setEvents] = useState<Event[]>([]);
  const [verdicts, setVerdicts] = useState<ClassifierVerdict[]>([]);
  const [feedbackPendingID, setFeedbackPendingID] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("all");
  const [riskOnly, setRiskOnly] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [policy, setPolicy] = useState<PolicyProfile | null>(null);
  const [policyPending, setPolicyPending] = useState<PolicyProfileID | null>(null);
  const [policyError, setPolicyError] = useState("");
  const selectedRef = useRef("");
  const useSampleDashboard = USE_SAMPLE_DATA && API === "";

  useEffect(() => {
    refresh();
    loadPolicy();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (selectedSessionID) loadEvents(selectedSessionID);
    selectedRef.current = selectedSessionID;
  }, [selectedSessionID]);

  function selectSession(id: string) {
    if (selectedRef.current !== id) {
      setEvents([]);
      setVerdicts([]);
      setOpenId(null);
    }
    selectedRef.current = id;
    setSelectedSessionID(id);
  }

  function applySessions(next: Session[]): Session[] {
    setSessions((prev) => (sameSessions(prev, next) ? prev : next));
    setError("");
    return next;
  }

  function applyEvents(next: Event[]) {
    setEvents(next);
    setError("");
  }

  function applySamplePolicy(profile?: PolicyProfileID) {
    if (!profile) {
      setPolicy(SAMPLE_POLICY);
      setPolicyError("");
      return;
    }
    setPolicy({ ...SAMPLE_POLICY, profile, loaded_at: new Date().toISOString() });
    setPolicyError("");
  }

  function refresh() {
    if (useSampleDashboard) {
      applySessions(SAMPLE_SESSIONS);
      selectSession(SAMPLE_SESSION_ID);
      applyEvents(SAMPLE_EVENTS);
      return;
    }

    fetchSessions()
      .then((next) => {
        const safe = applySessions(next);
        const current = selectedRef.current;
        const currentSessionID = safe.find((s) => s.current)?.session_id;
        const toLoad = safe.some((s) => s.session_id === current)
          ? current
          : currentSessionID ?? safe[0]?.session_id;
        if (toLoad) {
          if (toLoad !== current) {
            selectSession(toLoad);
          } else {
            loadEvents(toLoad);
          }
        } else {
          selectedRef.current = "";
          setSelectedSessionID("");
          setEvents([]);
          setOpenId(null);
        }
      })
      .catch((e: unknown) => setError(errorMessage(e)));
  }

  function loadEvents(id: string) {
    loadVerdicts(id);
    if (useSampleDashboard && id === SAMPLE_SESSION_ID) {
      applyEvents(SAMPLE_EVENTS);
      return;
    }
    fetchEvents(id)
      .then((next) => {
        if (selectedRef.current !== id) return;
        applyEvents(next);
      })
      .catch((e: unknown) => setError(errorMessage(e)));
  }

  // Verdicts trail their events by design, and the risk column renders
  // nothing until they land — so they load independently of events and
  // failures stay out of the error banner instead of disturbing the log.
  function loadVerdicts(id: string) {
    if (useSampleDashboard && id === SAMPLE_SESSION_ID) {
      setVerdicts(SAMPLE_VERDICTS);
      return;
    }
    fetchVerdicts(id)
      .then((next) => {
        if (selectedRef.current !== id) return;
        setVerdicts(next);
      })
      .catch(() => {});
  }

  function loadPolicy() {
    if (useSampleDashboard) {
      applySamplePolicy();
      return;
    }

    fetchPolicy()
      .then((p) => {
        setPolicy(p);
        setPolicyError("");
      })
      .catch((e: unknown) => {
        setPolicyError(`Couldn't load policy profile. ${errorMessage(e)}`);
      });
  }

  // One label per click, one in flight at a time. The next 3s verdict poll
  // would converge the state anyway; applying the POST response just gets the
  // muted pill there sooner.
  function submitFeedback(actionID: string, feedback: RiskFeedback) {
    if (feedbackPendingID) return;
    if (useSampleDashboard && selectedSessionID === SAMPLE_SESSION_ID) {
      setVerdicts((prev) =>
        prev.map((v) =>
          v.action_id === actionID
            ? { ...v, user_feedback: feedback, feedback_at: new Date().toISOString() }
            : v,
        ),
      );
      return;
    }
    setFeedbackPendingID(actionID);
    sendVerdictFeedback(actionID, feedback)
      .then((next) => {
        setVerdicts((prev) => prev.map((v) => (v.action_id === next.action_id ? next : v)));
      })
      .catch((e: unknown) => setError(errorMessage(e)))
      .finally(() => setFeedbackPendingID(null));
  }

  function activate(id: PolicyProfileID) {
    if (id === policy?.profile || policyPending) return;
    if (useSampleDashboard && selectedSessionID === SAMPLE_SESSION_ID) {
      applySamplePolicy(id);
      return;
    }
    setPolicyPending(id);
    setPolicyError("");
    activatePolicy(id)
      .then(setPolicy)
      .catch((e: unknown) => setPolicyError(`Couldn't update policy profile. ${errorMessage(e)}`))
      .finally(() => setPolicyPending(null));
  }

  const { counts, groups } = useMemo(() => bucket(events), [events]);
  const verdictMap = useMemo(() => verdictsByAction(verdicts), [verdicts]);
  const opened = useMemo(
    () => (openId ? events.find((e) => e.id === openId) ?? null : null),
    [openId, events],
  );
  const selectedSession = useMemo(
    () => sessions.find((s) => s.session_id === selectedSessionID),
    [sessions, selectedSessionID],
  );
  const currentSession = useMemo(
    () => sessions.find((s) => s.current),
    [sessions],
  );
  const sessionMode: GuardMode = selectedSession?.mode ?? "observe";
  const loading = sessions.length === 0 && !error;

  return (
    <TooltipProvider delayDuration={150}>
      <div className="grid h-screen grid-cols-[252px_1fr] bg-background text-foreground">
        <Sidebar
          sessions={sessions}
          currentSession={currentSession}
          selectedID={selectedSessionID}
          onSelect={selectSession}
        />

        <main className="flex min-h-0 min-w-0 flex-col overflow-hidden">
          <SessionHeader
            session={selectedSession}
            loading={loading}
          />

          <ScrollArea className="min-w-0 flex-1">
            <div className="min-w-0 px-10 pb-10 pt-8">
              <PolicyPanel
                profile={policy}
                pending={policyPending}
                error={policyError}
                onActivate={activate}
                onRetry={loadPolicy}
              />

              <Block
                label="Decision Summary"
                description="What Guard decided this session."
              >
                <StatRow
                  counts={counts}
                  active={tab}
                  onSelect={setTab}
                  loading={loading}
                  mode={sessionMode}
                />
              </Block>

              {error && (
                <div className="mt-4 flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-[12px] text-destructive">
                  <AlertCircle className="h-3.5 w-3.5 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <Block
                label="Decision Log"
                description="Pre-tool Guard decisions for this session."
              >
                <ActionList
                  tab={tab}
                  decisionGroups={groups}
                  verdicts={verdictMap}
                  openId={openId}
                  onOpen={setOpenId}
                  onClearFilter={() => setTab("all")}
                  mode={sessionMode}
                  onFeedback={submitFeedback}
                  feedbackPendingID={feedbackPendingID}
                  riskOnly={riskOnly}
                  onToggleRiskOnly={() => setRiskOnly((value) => !value)}
                />
              </Block>
            </div>
          </ScrollArea>
        </main>

        <Sheet open={!!opened} onOpenChange={(open) => !open && setOpenId(null)}>
          <SheetContent
            side="right"
            className="w-[540px] max-w-[92vw] overflow-x-hidden p-0 sm:max-w-[540px]"
          >
            {opened && (
              <Inspector
                event={opened}
                verdict={verdictMap[opened.id]}
                mode={sessionMode}
                onFeedback={submitFeedback}
                feedbackPending={feedbackPendingID === opened.id}
              />
            )}
          </SheetContent>
        </Sheet>
      </div>
    </TooltipProvider>
  );
}
