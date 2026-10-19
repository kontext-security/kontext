#!/usr/bin/env python3
"""ENG-758: replay Databricks PreToolUse events through the installed hook.

Every case goes to the real managed-observe hook (Claude and Codex formats),
then the decision is read back from the local ledger by tool_use_id. Replay
only evaluates: no command here runs, so destructive cases are safe.

The seven presets are expected to be enforced together; each case lists the
presets whose rule must match (DENY). The matched rule ids in the ledger show
which preset fired, so one pass covers all seven. A case passes when the
matched presets equal DENY, the Cedar engine had 0 errors, and in enforce mode
the hook's own answer is deny exactly when DENY is non-empty.

  python3 scripts/e2e/databricks/replay.py [--out DIR] [--filter SUBSTR]
"""
import argparse, json, os, shlex, sqlite3, statistics, subprocess, sys, time, uuid

HOME = os.path.expanduser("~")
HOOK = f"{HOME}/Library/Application Support/KontextManagement/runtime/bin/kontext"
PROFILE = os.environ.get("KONTEXT_E2E_PROFILE", "staging-databricks-s-workspace")
DB = f"{HOME}/Library/Application Support/Kontext/profiles/{PROFILE}/managed-observe/guard.db"
CWD = os.getcwd()
HOST = "https://dbc-2cdbfcdf-fdf4.cloud.databricks.com"
WH = "6153fc85c1218582"
JOB = "662252960783052"
# A Claude Desktop session whose record (claude-code-sessions/…/local_*.json)
# lists the claude.ai connectors below; connector UUIDs resolve through it.
CLAUDE_SESSION = os.environ.get("E2E_CLAUDE_SESSION", "b0e8df28-d60f-460c-bef8-49344569ec2e")
DBX_CONN = "mcp__c2be245b-9fd0-47e8-9a48-80c63e49e3fb__"  # "Databricks" → system.ai.dbsql
WH_CONN = "mcp__e11cba6a-9fed-46c1-9c72-4723f0db93c9__"   # "Warehouse", same URL, neutral name

RO, XSQL, DEL, ADM, SEC, RUN, UNR = (
    "databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion",
    "protect-databricks-administration", "protect-databricks-secrets",
    "protect-databricks-runs-and-deploys", "block-unrecognized-databricks-operations")
PRESETS = [RO, XSQL, DEL, ADM, SEC, RUN, UNR]
BOTH, CLAUDE = ("claude", "codex"), ("claude",)
q = shlex.quote

# SQL forms × every SQL surface. DENY is the same on every surface (parity).
BIG = "SELECT 1 /* " + "x" * (65 << 10) + " */"
SQL = [
    ("select", "SELECT * FROM workspace.kontext_e2e.orders", [RO]),
    ("insert", "INSERT INTO workspace.kontext_e2e.orders VALUES (4, 'e2e', 1.0)", [RO]),
    ("drop table", "DROP TABLE workspace.kontext_e2e.orders", [RO, DEL]),
    ("delete from", "DELETE FROM workspace.kontext_e2e.orders WHERE id = 1", [RO, DEL]),
    ("insert overwrite", "INSERT OVERWRITE workspace.kontext_e2e.orders SELECT * FROM workspace.kontext_e2e.orders", [RO, DEL]),
    ("grant", "GRANT SELECT ON TABLE workspace.kontext_e2e.orders TO `account users`", [RO, ADM]),
    ("revoke", "REVOKE SELECT ON TABLE workspace.kontext_e2e.orders FROM `account users`", [RO, ADM]),
    ("alter owner", "ALTER TABLE workspace.kontext_e2e.orders OWNER TO `someone@example.com`", [RO, ADM]),
    ("secret()", "SELECT secret('kontext-e2e', 'demo-token')", [RO, XSQL, SEC]),
    ("over 64 KiB", BIG, [RO]),
    ("malformed", "SELEC nonsense FRM (((", [RO]),
]


def sql_surfaces(sql):
    body = json.dumps({"warehouse_id": WH, "statement": sql})
    mcp = {"query": sql, "warehouse_id": WH}
    return [
        ("mcp connector uuid", CLAUDE, DBX_CONN + "execute_sql", mcp),
        ("mcp claude_ai_Databricks", CLAUDE, "mcp__claude_ai_Databricks__execute_sql", mcp),
        ("mcp databricks-dbsql", BOTH, "mcp__databricks-dbsql__execute_sql", mcp),
        ("cli aitools query", BOTH, "Bash", f"databricks -p e2e experimental aitools tools query -w {WH} {q(sql)}"),
        ("databricks api", BOTH, "Bash", f"databricks -p e2e api post /api/2.0/sql/statements --json {q(body)}"),
        ("curl", BOTH, "Bash", f'curl -sS -X POST -H "Authorization: Bearer $DATABRICKS_TOKEN" -H "Content-Type: application/json" -d {q(body)} {HOST}/api/2.0/sql/statements'),
    ]


def curl(method, path, body=None):
    data = f" -H 'Content-Type: application/json' -d {q(json.dumps(body))}" if body is not None else ""
    return f'curl -sS -X {method} -H "Authorization: Bearer $DATABRICKS_TOKEN"{data} {HOST}{path}'


SDK = "from databricks.sdk import WorkspaceClient; WorkspaceClient(profile='e2e').jobs.run_now(job_id=%s)" % JOB
# (group, name, agents, tool, input, DENY, note)
OTHER = [
    ("sql", "sql from a file (cli)", BOTH, "Bash", f"databricks -p e2e experimental aitools tools query -w {WH} --file drop.sql", [RO], "unreadable SQL stays write"),
    ("sql", "sql from a file (curl)", BOTH, "Bash", f'curl -sS -X POST -H "Authorization: Bearer $DATABRICKS_TOKEN" -d @stmt.json {HOST}/api/2.0/sql/statements', [RO], "unreadable SQL stays write"),
    ("sql", "poll_sql_result (connector)", CLAUDE, DBX_CONN + "poll_sql_result", {"statement_id": "01f0-e2e"}, [], ""),
    ("sql", "execute_sql_read_only SELECT", BOTH, "mcp__databricks-dbsql__execute_sql_read_only", {"query": "SELECT 1", "warehouse_id": WH}, [], ""),
    ("secrets", "secrets get-secret", BOTH, "Bash", "databricks -p e2e secrets get-secret kontext-e2e demo-token", [SEC], ""),
    ("secrets", "secrets list-scopes", BOTH, "Bash", "databricks -p e2e secrets list-scopes", [SEC], ""),
    ("secrets", "api get secrets/get", BOTH, "Bash", "databricks -p e2e api get '/api/2.0/secrets/get?scope=kontext-e2e&key=demo-token'", [SEC], ""),
    ("secrets", "curl secrets/scopes/list", BOTH, "Bash", curl("GET", "/api/2.0/secrets/scopes/list"), [SEC], ""),
    ("execution", "jobs run-now", BOTH, "Bash", f"databricks -p e2e jobs run-now {JOB}", [RO, XSQL, RUN], ""),
    ("execution", "bundle deploy", BOTH, "Bash", "databricks -p e2e bundle deploy -t dev", [RO, XSQL, ADM, RUN], "deploys can set permissions"),
    ("execution", "bundle run", BOTH, "Bash", "databricks -p e2e bundle run kontext_e2e_job", [RO, XSQL, RUN], ""),
    ("execution", "apps deploy", BOTH, "Bash", "databricks -p e2e apps deploy kontext-e2e-app --source-code-path /Workspace/Users/me/app", [RO, XSQL, ADM, RUN], ""),
    ("execution", "api post jobs/run-now", BOTH, "Bash", f"databricks -p e2e api post /api/2.2/jobs/run-now --json '{{\"job_id\": {JOB}}}'", [RO, XSQL, RUN], ""),
    ("execution", "curl jobs/run-now", BOTH, "Bash", curl("POST", "/api/2.2/jobs/run-now", {"job_id": int(JOB)}), [RO, XSQL, RUN], ""),
    ("execution", "api post apps deployments", BOTH, "Bash", "databricks -p e2e api post /api/2.0/apps/kontext-e2e-app/deployments --json '{\"source_code_path\": \"/Workspace/app\"}'", [RO, XSQL, RUN], "route is execution/write (CLI apps deploy is admin)"),
    ("execution", "curl apps deployments", BOTH, "Bash", curl("POST", "/api/2.0/apps/kontext-e2e-app/deployments", {"source_code_path": "/Workspace/app"}), [RO, XSQL, RUN], ""),
    ("admin", "catalogs update --owner", BOTH, "Bash", "databricks -p e2e catalogs update workspace --owner someone@example.com", [RO, XSQL, ADM], ""),
    ("admin", "api patch catalog owner", BOTH, "Bash", "databricks -p e2e api patch /api/2.1/unity-catalog/catalogs/workspace --json '{\"owner\": \"someone@example.com\"}'", [RO, XSQL, ADM], ""),
    ("admin", "curl patch catalog owner", BOTH, "Bash", curl("PATCH", "/api/2.1/unity-catalog/catalogs/workspace", {"owner": "someone@example.com"}), [RO, XSQL, ADM], ""),
    ("reads", "clusters list", BOTH, "Bash", "databricks -p e2e clusters list", [], ""),
    ("reads", "jobs get", BOTH, "Bash", f"databricks -p e2e jobs get {JOB}", [], ""),
    ("reads", "api get clusters/list", BOTH, "Bash", "databricks -p e2e api get /api/2.1/clusters/list", [], ""),
    ("reads", "curl get jobs/get", BOTH, "Bash", curl("GET", f"/api/2.2/jobs/get?job_id={JOB}"), [], ""),
    ("ai", "genie_ask", BOTH, "mcp__databricks-genie__genie_ask", {"space_id": "01f0bakehouse", "question": "Top 3 products by revenue?"}, [], ""),
    ("ai", "genie_poll_response", BOTH, "mcp__databricks-genie__genie_poll_response", {"conversation_id": "c1", "message_id": "m1"}, [], ""),
    ("ai", "genie_cancel_response", BOTH, "mcp__databricks-genie__genie_cancel_response", {"conversation_id": "c1", "message_id": "m1"}, [RO, XSQL], ""),
    ("ai", "web_search", BOTH, "mcp__databricks-web-search__web_search", {"query": "databricks unity catalog grants"}, [], ""),
    ("ai", "sandbox run_code", BOTH, "mcp__databricks-sandbox__run_code", {"code": "print(1)"}, [RO, XSQL, RUN], ""),
    ("fail-open", "Warehouse connector SELECT", CLAUDE, WH_CONN + "execute_sql", {"query": "SELECT 1", "warehouse_id": WH}, [RO], "neutral name, identified by its URL: classified, not fail-open"),
    ("fail-open", "Warehouse connector DROP", CLAUDE, WH_CONN + "execute_sql", {"query": "DROP TABLE workspace.kontext_e2e.orders", "warehouse_id": WH}, [RO, DEL], "neutral name, identified by its URL"),
    ("fail-open", "claude_ai_Warehouse DROP", CLAUDE, "mcp__claude_ai_Warehouse__execute_sql", {"query": "DROP TABLE workspace.kontext_e2e.orders", "warehouse_id": WH}, [], "no URL, neutral name: fails open"),
    ("fail-open", "unconfigured warehouse server DROP", BOTH, "mcp__warehouse__execute_sql", {"query": "DROP TABLE workspace.kontext_e2e.orders", "warehouse_id": WH}, [], "fails open"),
    ("fail-open", "unknown tool, connector", CLAUDE, DBX_CONN + "run_python", {"code": "print(1)"}, [UNR], "only the opt-in guard"),
    ("fail-open", "unknown tool, databricks-dbsql", BOTH, "mcp__databricks-dbsql__list_warehouses", {}, [UNR], "only the opt-in guard"),
    ("fail-open", "unknown databricks subcommand", BOTH, "Bash", "databricks -p e2e frobnicate everything", [UNR], "only the opt-in guard"),
    ("fail-open", "databricks api unknown route", BOTH, "Bash", "databricks -p e2e api post /api/2.0/not-a-route --json '{}'", [UNR], "only the opt-in guard"),
    ("fail-open", "curl unknown route", BOTH, "Bash", curl("GET", "/api/2.0/not-a-route"), [UNR], "only the opt-in guard"),
    ("fail-open", "python SDK one-liner", BOTH, "Bash", f"python3 -c {q(SDK)}", [], "invisible to the shell projection"),
    ("fail-open", "python SDK script", BOTH, "Bash", "uv run scripts/run_job.py", [], "invisible to the shell projection"),
    ("control", "ls", BOTH, "Bash", "ls -la", [], "non-Databricks shell"),
    ("control", "git status", BOTH, "Bash", "git status --short", [], "non-Databricks shell"),
    ("control", "curl docs.databricks.com", BOTH, "Bash", "curl -sS https://docs.databricks.com/index.html", [], "not a workspace host"),
    ("control", "github MCP", BOTH, "mcp__github__get_me", {}, [], "other provider"),
    ("control", "curl get, literal header", BOTH, "Bash", f"curl -sS -H 'Authorization: Bearer dapi-redacted' '{HOST}/api/2.2/jobs/get?job_id={JOB}'", [], "same call as 'curl get jobs/get' without $VAR"),
    ("control", "over 64 KiB, not Databricks", BOTH, "Bash", "cat > notes.txt <<'EOF'\n" + "x" * (65 << 10) + "\nEOF", [], "a big heredoc must not trip Databricks presets"),
]


def cases():
    out = []
    for name, sql, deny in SQL:
        for surface, agents, tool, inp in sql_surfaces(sql):
            out.append(("sql", f"{name} · {surface}", agents, tool, inp, deny, ""))
    return out + OTHER


def event(agent, tool, inp, tool_use_id, session):
    tool_input = {"command": inp} if tool == "Bash" else inp
    e = {"session_id": session, "cwd": CWD, "hook_event_name": "PreToolUse", "tool_name": tool,
         "tool_input": tool_input, "tool_use_id": tool_use_id}
    if agent == "claude":
        proj = CWD.replace("/", "-").replace(".", "-")
        e.update(transcript_path=f"{HOME}/.claude/projects/{proj}/{session}.jsonl", permission_mode="auto")
    else:
        e.update(transcript_path=None, model="gpt-5.5-codex", permission_mode="default")
    return e


def hook_decision(stdout):
    try:
        out = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return "unparsed"
    if out.get("decision") == "block":
        return "deny"
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision") or "allow"


def ledger_row(con, tool_use_id):
    for _ in range(40):  # the daemon writes the decided row asynchronously
        row = con.execute(
            "select matched_rules_json, decision_result, applied_mode, evaluation_state, context_json "
            "from authorization_actions where tool_use_id = ? and canonical_event_type = 'request.decided' "
            "order by created_at desc limit 1", (tool_use_id,)).fetchone()
        if row:
            return row
        time.sleep(0.05)
    return None


def preset_of(rule_id):
    hits = [p for p in PRESETS if p in rule_id]
    return max(hits, key=len) if hits else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=".")
    ap.add_argument("--filter", default="")
    args = ap.parse_args()
    run = uuid.uuid4().hex[:8]
    codex_session = str(uuid.uuid4())
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    results, lat = [], []
    for i, (group, name, agents, tool, inp, deny, note) in enumerate(cases()):
        if args.filter not in name:
            continue
        for agent in agents:
            tid = f"toolu_e2e758_{run}_{i:03d}_{agent}" if agent == "claude" else f"call_e2e758_{run}_{i:03d}"
            session = CLAUDE_SESSION if agent == "claude" else codex_session
            argv = [HOOK, "hook", "pre-tool-use"] if agent == "claude" else [HOOK, "hook", "--agent", "codex", "pre-tool-use"]
            payload = json.dumps(event(agent, tool, inp, tid, session))
            t0 = time.perf_counter()
            proc = subprocess.run(argv, input=payload, capture_output=True, text=True, timeout=30)
            ms = (time.perf_counter() - t0) * 1000
            lat.append(ms)
            row = ledger_row(con, tid)
            r = {"group": group, "case": name, "agent": agent, "tool": tool, "expected": sorted(deny), "note": note,
                 "hook": hook_decision(proc.stdout), "exit": proc.returncode, "ms": round(ms, 1)}
            if row is None:
                r.update(status="FAIL", why="no ledger row")
            else:
                rules, decision, mode, state, ctx = row
                ev = (json.loads(ctx or "{}").get("policy_evidence") or {})
                matched = json.loads(rules or "[]")
                got = sorted({p for p in map(preset_of, matched) if p})
                errors = ev.get("engine_error_count")
                req = ev.get("cedar_request") or {}
                r.update(matched=matched, actual=got, decision=decision, mode=mode, state=state,
                         engine_errors=errors, tool_id=req.get("tool_id"), tier=req.get("tool"), shell=req.get("shell"))
                why = []
                if got != sorted(deny):
                    why.append(f"presets {got} != {sorted(deny)}")
                if errors or state != "evaluated":
                    why.append(f"engine_errors={errors} state={state}")
                if mode == "enforce" and (r["hook"] == "deny") != bool(deny):
                    why.append(f"hook said {r['hook']}")
                r.update(status="FAIL" if why else "PASS", why="; ".join(why))
            results.append(r)
            print(f"{r['status']} {agent:6} {name[:70]:70} {r.get('actual')} {r.get('why', '')}", flush=True)
    os.makedirs(args.out, exist_ok=True)
    lat.sort()
    summary = {"run": run, "cases": len(results), "pass": sum(r["status"] == "PASS" for r in results),
               "engine_errors": sum(r.get("engine_errors") or 0 for r in results),
               "p50_ms": round(statistics.median(lat), 1), "p95_ms": round(lat[int(0.95 * (len(lat) - 1))], 1),
               "max_ms": round(lat[-1], 1)}
    json.dump({"summary": summary, "results": results}, open(f"{args.out}/results-{run}.json", "w"), indent=1)
    print(json.dumps(summary))
    sys.exit(0 if summary["pass"] == summary["cases"] else 1)


if __name__ == "__main__":
    main()
