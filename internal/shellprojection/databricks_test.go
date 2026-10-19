package shellprojection

import (
	"slices"
	"strings"
	"testing"
)

const (
	dbCat   = FactDatabricksRouteCatalogued
	dbUnk   = FactDatabricksRouteUnrecognized
	dbW     = "databricks/write=true"
	dbD     = "databricks/delete=true"
	dbA     = "databricks/admin=true"
	dbHost  = "https://dbc-1234.cloud.databricks.com"
	dbQuery = "databricks experimental aitools tools query "
)

func dbP(product string) string { return databricksProductFact(product) }

// databricksFacts returns the databricks/ facts of every projection, without
// the command fact, sorted.
func databricksFacts(command string) ([]string, bool) {
	var facts []string
	complete := true
	for _, projection := range Project(command) {
		complete = complete && projection.ParseComplete
		for _, fact := range projection.Facts {
			if strings.HasPrefix(fact, "databricks/") && !strings.HasPrefix(fact, "databricks/command=") {
				facts = append(facts, fact)
			}
		}
	}
	slices.Sort(facts)
	return facts, complete
}

func TestDatabricksShellFacts(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		facts    []string
		complete bool
	}{
		// Generated commands keep the route table's tier.
		{"read", "databricks clusters list", []string{dbCat, dbP("compute")}, true},
		{"write", "databricks clusters create --json @spec.json", []string{dbCat, dbP("compute"), dbW}, true},
		{"delete", "databricks clusters delete 0123-abc", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"owner change is admin", "databricks catalogs update main --owner someone@acme.com", []string{dbCat, dbA, dbP("data"), dbW}, true},
		{"secret read carries the product", "databricks secrets get-secret scope key", []string{dbCat, dbP("secrets")}, true},
		{"account command", "databricks account groups delete 123", []string{dbCat, dbA, dbP("admin"), dbW}, true},
		{"global flags anywhere", "databricks -p prod --debug clusters -o json delete 0123-abc", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"global flag with equals", "databricks --profile=prod clusters delete 0123-abc", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"job run is execution", "databricks jobs run-now 123", []string{dbCat, dbP("execution"), dbW}, true},
		{"pipeline start is execution", "databricks pipelines start-update abc", []string{dbCat, dbP("execution"), dbW}, true},
		{"dynamic argument keeps the tier", `databricks clusters delete "$ID"`, []string{dbD, dbP("compute"), dbUnk, dbW}, false},

		// Hand-written commands.
		{"bundle deploy", "databricks bundle deploy -t prod", []string{dbCat, dbA, dbP("execution"), dbW}, true},
		{"bundle run", "databricks bundle run my_job", []string{dbCat, dbP("execution"), dbW}, true},
		{"bundle destroy deletes and administers", "databricks bundle destroy --auto-approve", []string{dbCat, dbA, dbD, dbP("workloads"), dbW}, true},
		{"bundle validate", "databricks bundle validate", []string{dbCat, dbP("workloads")}, true},
		{"apps deploy", "databricks apps deploy my-app", []string{dbCat, dbA, dbP("execution"), dbW}, true},
		{"fs ls", "databricks fs ls dbfs:/tmp", []string{dbCat, dbP("data")}, true},
		{"fs cp", "databricks fs cp -r ./out dbfs:/tmp/out", []string{dbCat, dbP("data"), dbW}, true},
		{"fs cp overwrite deletes", "databricks fs cp --overwrite a.txt dbfs:/tmp/a.txt", []string{dbCat, dbD, dbP("data"), dbW}, true},
		{"fs rm", "databricks fs rm -r dbfs:/tmp/out", []string{dbCat, dbD, dbP("data"), dbW}, true},
		{"sync mirrors deletions", "databricks sync . /Workspace/Users/me/project", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"workspace import overwrites", "databricks workspace import /Users/me/nb --file nb.py", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"workspace export", "databricks workspace export /Users/me/nb", []string{dbCat, dbP("workspace")}, true},
		{"sandbox create", "databricks sandbox create", []string{dbCat, dbP("execution"), dbW}, true},
		{"psql", "databricks psql my-instance -- -c 'DROP TABLE t'", []string{dbCat, dbP("execution"), dbW}, true},
		{"labs project runs code", "databricks labs ucx migrate-tables", []string{dbCat, dbP("execution"), dbW}, true},
		{"labs list is local", "databricks labs list", []string{dbCat}, true},
		{"auth login is local", "databricks auth login --host https://dbc-1234.cloud.databricks.com", []string{dbCat}, true},
		{"auth token prints a credential", "databricks auth token -p prod", []string{dbCat, dbP("secrets")}, true},
		{"configure is local", "databricks configure --token", []string{dbCat}, true},
		{"aitools install is local", "databricks experimental aitools install", []string{dbCat}, true},
		{"version flag", "databricks --version", []string{dbCat}, true},
		{"genie ask runs SQL", `databricks genie ask "top customers"`, []string{dbCat, dbP("sql"), dbW}, true},

		// SQL entry points: base sql/write, raised by the SQL check.
		{"query select", dbQuery + `"SELECT * FROM t"`, []string{dbCat, dbP("sql"), dbW}, true},
		{"query drop", dbQuery + `"DROP TABLE t"`, []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"query grant", dbQuery + `-w abc "GRANT SELECT ON TABLE t TO users"`, []string{dbCat, dbA, dbP("sql"), dbW}, true},
		{"query drop and grant emits both", dbQuery + `"DROP TABLE t; GRANT SELECT ON TABLE u TO users"`, []string{dbCat, dbA, dbD, dbP("sql"), dbW}, true},
		{"several queries: strictest wins", dbQuery + `--output json "SELECT 1" "DELETE FROM t WHERE x = 1"`, []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"secret() is the secrets product", dbQuery + `"SELECT secret('scope', 'key')"`, []string{dbCat, dbP("secrets"), dbW}, true},
		{"sql file keeps the base tier", dbQuery + "report.sql", []string{dbCat, dbP("sql"), dbW}, true},
		{"--file keeps the base tier", dbQuery + "--file report.sql", []string{dbCat, dbP("sql"), dbW}, true},
		{"stdin keeps the base tier", "cat q.sql | " + dbQuery, []string{dbCat, dbP("sql"), dbW}, true},
		{"unparseable SQL keeps the base tier", dbQuery + `"SELEC frm"`, []string{dbCat, dbP("sql"), dbW}, true},
		{"positional after an unknown flag is still checked", dbQuery + `--future "DROP TABLE t"`, []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"positional after --", dbQuery + `-- "DROP TABLE t"`, []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"text ending in .sql is checked as SQL too", dbQuery + `"DROP TABLE t -- x.sql"`, []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"statement submit", `databricks experimental aitools tools statement submit "TRUNCATE TABLE t"`, []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"statement status is a read", "databricks experimental aitools tools statement status 01ef", []string{dbCat, dbP("sql")}, true},

		{"quoted SQL is checked as the CLI cleans it", dbQuery + `'"DROP TABLE t"'`, []string{dbCat, dbD, dbP("sql"), dbW}, true},

		// Flags that raise a command.
		{"fs cp --overwrite=false stays a write", "databricks fs cp --overwrite=false a.txt dbfs:/tmp/a.txt", []string{dbCat, dbP("data"), dbW}, true},
		{"workspace import-dir --overwrite deletes", "databricks workspace import-dir ./src /Users/me/src --overwrite", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"apps init is local", "databricks apps init --name my-app", []string{dbCat}, true},
		{"apps init --deploy deploys", "databricks apps init --name my-app --deploy", []string{dbCat, dbA, dbP("execution"), dbW}, true},
		{"apps init --run runs", "databricks apps init --name my-app --run=dev-remote", []string{dbCat, dbP("execution"), dbW}, true},
		{"apps import deploys", "databricks apps import --name my-app", []string{dbCat, dbA, dbP("execution"), dbW}, true},
		{"apps import --cleanup deletes", "databricks apps import --name my-app --cleanup", []string{dbCat, dbA, dbD, dbP("execution"), dbW}, true},
		{"sandbox config writes", "databricks sandbox config happy-panda-1234 --no-autostop", []string{dbCat, dbP("execution"), dbW}, true},
		{"bundle generate is a read", "databricks bundle generate job --existing-job-id 1", []string{dbCat, dbP("workloads")}, true},
		{"bundle generate --bind binds", "databricks bundle generate job --existing-job-id 1 -b", []string{dbCat, dbP("workloads"), dbW}, true},
		{"auth describe is local", "databricks auth describe", []string{dbCat}, true},
		{"auth describe --sensitive prints credentials", "databricks auth describe --sensitive", []string{dbCat, dbP("secrets")}, true},
		{"auth docker token prints a credential", "databricks auth docker token", []string{dbCat, dbP("secrets")}, true},

		// databricks api.
		{"api read", "databricks api get /api/2.1/clusters/list", []string{dbCat, dbP("compute")}, true},
		{"api delete", `databricks api post /api/2.1/clusters/delete --json '{"cluster_id":"x"}'`, []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"api sql", `databricks api post /api/2.0/sql/statements --json '{"warehouse_id":"w","statement":"DROP SCHEMA s CASCADE"}'`, []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"api sql body before the method", `databricks api --json '{"statement":"DROP TABLE t"}' post /api/2.0/sql/statements`, []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"api sql body from a file", "databricks api post /api/2.0/sql/statements --json @q.json", []string{dbCat, dbP("sql"), dbW}, true},
		{"api write body from a file keeps the tier", "databricks api post /api/2.1/unity-catalog/catalogs --json @c.json", []string{dbCat, dbP("data"), dbW}, true},
		{"api full url", "databricks api delete https://dbc-1234.cloud.databricks.com/api/2.0/repos/12", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"api file body overridden by a literal one", `databricks api post /api/2.0/sql/statements --json @/dev/null --json '{"statement":"DROP TABLE t"}'`, []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"api unknown route fails open", "databricks api post /api/2.0/not-a-route", []string{dbUnk}, false},

		// Unknown fails open: no tier facts.
		{"unknown group", "databricks frobnicate everything", []string{dbUnk}, false},
		{"unknown verb", "databricks clusters frobnicate 0123-abc", []string{dbUnk}, false},
		{"dynamic command", `databricks "$CMD" 0123-abc`, []string{dbUnk}, false},
		{"dynamic word before the command keeps its tier", `databricks "$FLAGS" clusters delete 0123-abc`, []string{dbD, dbP("compute"), dbUnk, dbW}, false},
		{"unknown experimental tool", "databricks experimental aitools tools frobnicate", []string{dbUnk}, false},

		// curl.
		{"curl read", "curl " + dbHost + "/api/2.1/clusters/list", []string{dbCat, dbP("compute")}, true},
		{"curl delete", "curl -X POST -d '{\"cluster_id\":\"x\"}' " + dbHost + "/api/2.1/clusters/delete", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"curl sql", `curl -X POST --json '{"statement":"DROP TABLE t","warehouse_id":"w"}' ` + dbHost + "/api/2.0/sql/statements", []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"curl sql duplicate key", `curl --json '{"statement":"SELECT 1","statement":"DROP TABLE t"}' ` + dbHost + "/api/2.0/sql/statements", []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"curl sql body from a file", "curl -d @q.json " + dbHost + "/api/2.0/sql/statements", []string{dbCat, dbP("sql"), dbW}, true},
		{"curl split --json body", `curl --json '{"warehouse_id":"w","statement":' --json '"DROP TABLE t"}' ` + dbHost + "/api/2.0/sql/statements", []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"curl split -d body", `curl -d '{"statement":"SELECT 1' -d ' ; DROP TABLE t"}' ` + dbHost + "/api/2.0/sql/statements", []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"curl empty file piece before a literal body", `curl --json @/dev/null --json '{"statement":"DROP TABLE t"}' ` + dbHost + "/api/2.0/sql/statements", []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"curl too many pieces assumes the worst", "curl -d a -d b -d c -d d -d e -d f -d g -d h -d i " + dbHost + "/api/2.0/sql/statements", []string{dbCat, dbA, dbD, dbP("sql"), dbW}, true},
		{"curl secrets read", "curl " + dbHost + "/api/2.0/secrets/get?scope=s&key=k", []string{dbCat, dbP("secrets")}, true},
		{"curl dot segments are resolved", "curl -X POST -d '{}' " + dbHost + "/api/2.1/clusters/list/../delete", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"curl azure", "curl -X DELETE https://adb-1.2.azuredatabricks.net/api/2.0/repos/12", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl custom workspace", "curl -X DELETE https://acme.databricks.com/api/2.0/repos/12", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl unknown route fails open", "curl " + dbHost + "/api/2.0/not-a-route", []string{dbUnk}, false},
		{"curl mcp is unrecognized", `curl -X POST -d '{}' ` + dbHost + "/api/2.0/mcp/sql", []string{dbUnk}, false},
		{"plain http keeps the tier", "curl -X DELETE http://dbc-1234.cloud.databricks.com/api/2.0/repos/12", []string{dbD, dbP("workspace"), dbUnk, dbW}, false},
		{"several urls do not borrow the sql exemption", `curl --json '{"statement":"SELECT 1","cluster_id":"x"}' ` + dbHost + "/api/2.0/sql/statements " + dbHost + "/api/2.1/clusters/delete", []string{dbD, dbP("compute"), dbUnk, dbW}, false},
		{"curl --next keeps each request's method", `curl -X POST -d '{"cluster_id":"x"}' ` + dbHost + "/api/2.1/clusters/delete --next -X GET https://example.com", []string{dbD, dbP("compute"), dbUnk, dbW}, false},
		{"docs host is not a workspace", "curl https://docs.databricks.com/api/2.0/clusters/list", nil, true},

		// Wrappers.
		{"bash -lc", `bash -lc "databricks clusters delete 0123-abc"`, []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"zsh -c chain", `zsh -c "cd x && databricks bundle destroy"`, []string{dbCat, dbA, dbD, dbP("workloads"), dbW}, true},
		{"env and path", "env DATABRICKS_HOST=x /opt/homebrew/bin/databricks fs rm dbfs:/x", []string{dbCat, dbD, dbP("data"), dbW}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts, complete := databricksFacts(test.command)
			slices.Sort(test.facts)
			if !slices.Equal(facts, test.facts) || complete != test.complete {
				t.Fatalf("facts = %v complete = %t, want %v complete = %t", facts, complete, test.facts, test.complete)
			}
		})
	}
}
