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
		{"bundle generate clustered -fb binds", "databricks bundle generate job --existing-job-id 1 -fb", []string{dbCat, dbP("workloads"), dbW}, true},
		{"bundle generate clustered -fb=true binds", "databricks bundle generate job --existing-job-id 1 -fb=true", []string{dbCat, dbP("workloads"), dbW}, true},
		{"bundle generate clustered -fb=false does not bind", "databricks bundle generate job --existing-job-id 1 -fb=false", []string{dbCat, dbP("workloads")}, true},
		{"-- as an option value does not end the flags", "databricks auth describe --log-file -- --sensitive", []string{dbCat, dbP("secrets")}, true},
		{"a profile name is not a bind flag", "databricks bundle generate job --existing-job-id 1 -pabc", []string{dbCat, dbP("workloads")}, true},
		{"a file named like a raise after -- reads as set (over-strict)", "databricks fs cp -- --overwrite dbfs:/tmp/dest", []string{dbCat, dbD, dbP("data"), dbW}, true},
		{"a raise flag counts wherever it stands (over-strict)", "databricks fs cp --log-file --overwrite a.txt dbfs:/tmp/a.txt", []string{dbCat, dbD, dbP("data"), dbW}, true},
		{"an option value does not hide a raise", "databricks apps init --name review-app --description --profile --deploy", []string{dbCat, dbA, dbP("execution"), dbW}, true},
		{"a value-taking --version does not hide a raise", "databricks apps init --name review-app --version -- --deploy --version=latest", []string{dbCat, dbA, dbP("execution"), dbW}, true},
		{"a later =false does not clear a raise", "databricks fs cp --overwrite --overwrite=false a.txt dbfs:/tmp/a.txt", []string{dbCat, dbD, dbP("data"), dbW}, true},
		{"a file name after -- and a local switch does not clear a raise", "databricks fs cp --overwrite --recursive -- --overwrite=false dbfs:/tmp/dest", []string{dbCat, dbD, dbP("data"), dbW}, true},
		{"another option's value does not clear a raise", "databricks apps init --name review-app --deploy --description --deploy=false", []string{dbCat, dbA, dbP("execution"), dbW}, true},
		{"a file name after -- does not cancel a raise", "databricks fs cp --overwrite -- --overwrite=false dbfs:/tmp/dest", []string{dbCat, dbD, dbP("data"), dbW}, true},
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
		{"api relative path", "databricks api delete api/2.0/repos/12", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"api unknown route fails open", "databricks api post /api/2.0/not-a-route", []string{dbUnk}, false},

		// Unknown fails open: no tier facts.
		{"unknown group", "databricks frobnicate everything", []string{dbUnk}, false},
		{"unknown verb", "databricks clusters frobnicate 0123-abc", []string{dbUnk}, false},
		{"dynamic command", `databricks "$CMD" 0123-abc`, []string{dbUnk}, false},
		{"dynamic word before the command is unrecognized", `databricks "$FLAGS" clusters delete 0123-abc`, []string{dbUnk}, false},
		{"dynamic word in a command a flag raises is unrecognized", `databricks auth describe $'--log-file' -- --sensitive`, []string{dbUnk}, false},
		{"dynamic SQL keeps sql/write", dbQuery + `"$SQL"`, []string{dbP("sql"), dbUnk, dbW}, false},
		{"api dynamic path is unrecognized", `databricks api delete "$P"`, []string{dbUnk}, false},
		{"api dynamic body keeps the tier", `databricks api post /api/2.1/clusters/delete --json "$BODY"`, []string{dbD, dbP("compute"), dbUnk, dbW}, false},
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
		{"curl too many pieces keeps the base tier", "curl -d a -d b -d c -d d -d e -d f -d g -d h -d i " + dbHost + "/api/2.0/sql/statements", []string{dbCat, dbP("sql"), dbW}, true},
		{"curl too many pieces still reads each piece", `curl --json '{"statement":"DROP TABLE t"}' --json '' --json '' --json '' --json '' --json '' --json '' --json '' --json '' ` + dbHost + "/api/2.0/sql/statements", []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"curl secrets read", "curl " + dbHost + "/api/2.0/secrets/get?scope=s&key=k", []string{dbCat, dbP("secrets")}, true},
		{"curl dot segments are resolved", "curl -X POST -d '{}' " + dbHost + "/api/2.1/clusters/list/../delete", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"curl azure", "curl -X DELETE https://adb-1.2.azuredatabricks.net/api/2.0/repos/12", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl custom workspace", "curl -X DELETE https://acme.databricks.com/api/2.0/repos/12", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl unknown route fails open", "curl " + dbHost + "/api/2.0/not-a-route", []string{dbUnk}, false},
		{"curl mcp is unrecognized", `curl -X POST -d '{}' ` + dbHost + "/api/2.0/mcp/sql", []string{dbUnk}, false},
		{"plain http keeps the tier", "curl -X DELETE http://dbc-1234.cloud.databricks.com/api/2.0/repos/12", []string{dbD, dbP("workspace"), dbUnk, dbW}, false},
		{"several urls do not borrow the sql exemption", `curl --json '{"statement":"SELECT 1","cluster_id":"x"}' ` + dbHost + "/api/2.0/sql/statements " + dbHost + "/api/2.1/clusters/delete", []string{dbD, dbP("compute"), dbUnk, dbW}, false},
		{"curl --next as an option value is not a separator", "curl -X DELETE --user-agent --next " + dbHost + "/api/2.0/repos/12", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl --next after an unknown option is unrecognized", "curl -X DELETE --frobnicate --next " + dbHost + "/api/2.0/repos/12", []string{dbUnk}, false},
		{"curl --next keeps each request's method", `curl -X POST -d '{"cluster_id":"x"}' ` + dbHost + "/api/2.1/clusters/delete --next -X GET https://example.com", []string{dbD, dbP("compute"), dbUnk, dbW}, false},
		{"curl glob alternatives are unrecognized", "curl -X POST -d '{}' '" + dbHost + "/api/{2.0/repos/list,2.1/clusters/delete}'", []string{dbUnk}, false},
		{"curl glob range is unrecognized", "curl -X POST -d '{}' '" + dbHost + "/api/2.1/clu[s-s]ters/delete'", []string{dbUnk}, false},
		{"curl url without a scheme is plain http", "curl -X DELETE dbc-1234.cloud.databricks.com/api/2.0/repos/12", []string{dbD, dbP("workspace"), dbUnk, dbW}, false},
		{"curl --next resets -X", `curl -X GET https://example.com --next --json '{"cluster_id":"x"}' ` + dbHost + "/api/2.1/clusters/delete", []string{dbD, dbP("compute"), dbUnk, dbW}, false},
		{"curl -X wins over -G", "curl -X DELETE -G " + dbHost + "/api/2.0/repos/12", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl range glob is unrecognized", `curl --json '{"cluster_id":"x"}' '` + dbHost + "/api/2.1/clusters/[a-d]elete'", []string{dbUnk}, false},
		{"curl large glob is unrecognized", "curl '" + dbHost + "/api/2.1/clusters/[a-z][a-z][a-z]'", []string{dbUnk}, false},
		{"curl short option cluster", "curl -sX DELETE " + dbHost + "/api/2.0/repos/12", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl clustered body", `curl -sd'{"cluster_id":"x"}' ` + dbHost + "/api/2.1/clusters/delete", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"curl --request-target is the path requested", "curl --request-target '/api/2.0/secrets/get?scope=s&key=k' " + dbHost + "/api/2.1/clusters/list", []string{dbCat, dbP("secrets")}, true},
		{"curl config file is unrecognized", "curl -K opts.txt " + dbHost + "/api/2.0/repos/12", []string{dbUnk}, false},
		{"curl --no-get cancels -G", `curl -G --no-get --json '{"cluster_id":"x"}' ` + dbHost + "/api/2.1/clusters/delete", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"curl request target per operation", "curl --request-target '/api/2.0/secrets/get?scope=s&key=k' " + dbHost + "/api/2.1/clusters/list --next --request-target /api/2.1/clusters/list " + dbHost + "/api/2.1/clusters/list", []string{dbP("compute"), dbP("secrets"), dbUnk}, false},
		{"curl bodies per operation", `curl --json '{"statement":"SELECT 1"}' ` + dbHost + `/api/2.0/sql/statements --next --json '{"statement":"' --json 'DROP TABLE t"}' ` + dbHost + "/api/2.0/sql/statements", []string{dbD, dbP("sql"), dbUnk, dbW}, false},
		{"curl proto-default and request target on a url without a scheme", "curl --proto-default https --request-target '/api/2.0/secrets/get?scope=s&key=k' dbc-1234.cloud.databricks.com/api/2.1/clusters/list", []string{dbCat, dbP("secrets")}, true},
		{"curl three slashes after the scheme", "curl -X DELETE https:///dbc-1234.cloud.databricks.com/api/2.0/repos/12", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl one slash after the scheme", "curl -X DELETE https:/dbc-1234.cloud.databricks.com/api/2.0/repos/12", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl glob without a scheme is unrecognized", `curl --proto-default https --json '{"cluster_id":"x"}' 'dbc-1234.cloud.databricks.com/api/2.1/clusters/[a-z][a-z]lete'`, []string{dbUnk}, false},
		{"curl empty attached body is a POST", "curl --json= " + dbHost + "/api/2.0/apps/my-app/start", []string{dbCat, dbP("execution"), dbW}, true},
		{"curl repeated slashes are collapsed", "curl -X POST -d '{}' " + dbHost + "/api/2.1//clusters///delete", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"curl known value option takes --next as its value", "curl -X DELETE --proxy --next " + dbHost + "/api/2.0/repos/12", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl value option takes -I as its value", `curl --referer -I --json '{"cluster_id":"x"}' ` + dbHost + "/api/2.1/clusters/delete", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"curl unknown option before -I is unrecognized", `curl --frobnicate -I --json '{"cluster_id":"x"}' ` + dbHost + "/api/2.1/clusters/delete", []string{dbUnk}, false},
		{"curl --proto-default per operation", "curl --proto-default https -X DELETE dbc-1234.cloud.databricks.com/api/2.0/repos/12 --next --proto-default ftp ftp://example.com/file", []string{dbD, dbP("workspace"), dbUnk, dbW}, false},
		{"curl glob in the scheme is not identified as databricks", "curl -X DELETE '{https,https}://dbc-1234.cloud.databricks.com/api/2.0/repos/12'", nil, false},
		{"curl percent-encoded host", "curl -X DELETE 'https://%64bc-1234.cloud.databricks.com/api/2.0/repos/12'", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl output format is not a method", `curl -X POST -w-XGET -d '{"cluster_id":"x"}' ` + dbHost + "/api/2.1/clusters/delete", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"curl request target only for its own operation", "curl '" + dbHost + "/api/2.0/secrets/get?scope=s&key=k' --next --request-target /api/2.1/clusters/list " + dbHost + "/", []string{dbP("compute"), dbP("secrets"), dbUnk}, false},
		{"curl globbed host is not identified as databricks", `curl --json '{"cluster_id":"x"}' 'https://dbc-1234.cloud.databr{icks,icks}.com/api/2.1/clusters/[a-z][a-z]lete'`, nil, false},
		{"curl host glob on another domain", "curl 'https://example.com/[a-z][a-z]'", nil, false},
		{"curl empty -T is no upload", `curl -T '' --json '{"cluster_id":"x"}' ` + dbHost + "/api/2.1/clusters/delete", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"curl -T applies to the first URL only", `curl -T f.json --json '{"cluster_id":"x"}' https://example.com/upload ` + dbHost + "/api/2.1/clusters/delete", []string{dbD, dbP("compute"), dbUnk, dbW}, false},
		{"curl options after -- are URLs", `curl --json '{"cluster_id":"x"}' -- ` + dbHost + "/api/2.1/clusters/delete -G", []string{dbD, dbP("compute"), dbUnk, dbW}, false},
		{"curl --data-urlencode is encoded before the JSON is read", `curl --data-urlencode '{"warehouse_id":"w","statement":"DROP TABLE t -- =\q' --json '"}' ` + dbHost + "/api/2.0/sql/statements", []string{dbCat, dbD, dbP("sql"), dbW}, true},
		{"curl empty -T keeps its URL slot", "curl -T '' -T permissions.json https://example.com " + dbHost + "/api/2.0/permissions/jobs/123", []string{dbA, dbP("admin"), dbUnk, dbW}, false},
		{"curl -T appends its file name to a URL ending in /", "curl -X POST -T delete " + dbHost + "/api/2.1/clusters/", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"curl known switches do not hide the next option", "curl -L -s " + dbHost + "/api/2.0/repos/12", []string{dbP("workspace"), dbUnk}, false},
		{"curl glob after three slashes is unrecognized", `curl --json '{"cluster_id":"x"}' 'https:///dbc-1234.cloud.databricks.com/api/2.1/clusters/[a-z][a-z]lete'`, []string{dbUnk}, false},
		{"curl numbered host glob on another domain", "curl 'https://node[001-300].example.com/file'", nil, false},
		{"curl databricks.com in another host's path", "curl http://example.com/releases/databricks.com/archive.zip", nil, false},
		{"curl dynamic method is unrecognized", `curl -X "$M" ` + dbHost + "/api/2.0/repos/12", []string{dbUnk}, false},
		{"curl -T does not append its name to a --request-target", "curl -X DELETE -T payload.json --request-target /api/2.0/repos/12/ " + dbHost + "/", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl globbed upload name is unrecognized", "curl -X POST -T '[d-z][e-z]lete' " + dbHost + "/api/2.1/clusters/", []string{dbUnk}, false},
		{"curl upload name with a backslash is unrecognized", `curl -X POST -T 'payload\delete' ` + dbHost + "/api/2.1/clusters/", []string{dbUnk}, false},
		{"curl globbed port is not identified as databricks", "curl -X DELETE 'https://dbc-1234.cloud.databr{icks,icks}.com:[4-4]43/api/2.0/repos/12'", nil, false},
		{"curl docs host with a path glob is not databricks", "curl 'https://docs.databricks.com/{en,ja}/dev-tools/cli/index.html'", nil, false},
		{"curl lookalike host with a path glob is not databricks", "curl 'https://databricks.com.example.org/{a,b}'", nil, false},
		{"api computed profile keeps the tier", `databricks api delete /api/2.0/repos/12 --profile "$PROFILE"`, []string{dbD, dbP("workspace"), dbUnk, dbW}, false},
		{"curl docs host without a scheme with a path glob is not databricks", "curl 'docs.databricks.com/{en,ja}/dev-tools/cli/index.html'", nil, false},
		{"curl lookalike host without a scheme with a path glob is not databricks", "curl 'databricks.com.example.org/{a,b}'", nil, false},
		{"curl host:port without a scheme keeps its host", "curl -X DELETE 'dbc-1234.cloud.databricks.com:443/api/2.0/repos/12?next=https://example.org'", []string{dbD, dbP("workspace"), dbUnk, dbW}, false},
		{"curl fragment is not sent", "curl -X DELETE '" + dbHost + "/api/2.0/repos/12#%'", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl unparseable path on a databricks host is unrecognized", "curl -X DELETE '" + dbHost + "/api/2.0/repos/12%'", []string{dbUnk}, false},
		{"curl computed body is opaque", `curl --json "$BODY" ` + dbHost + "/api/2.1/clusters/delete", []string{dbCat, dbD, dbP("compute"), dbW}, true},
		{"curl computed header is opaque", `curl -sS -X POST -H "Authorization: Bearer $DATABRICKS_TOKEN" -H 'Content-Type: application/json' -d '{"job_id":1}' ` + dbHost + "/api/2.2/jobs/run-now", []string{dbCat, dbP("execution"), dbW}, true},
		{"curl computed header on a read", `curl -sS -H "Authorization: Bearer $DATABRICKS_TOKEN" '` + dbHost + "/api/2.2/jobs/get?job_id=1'", []string{dbCat, dbP("workloads")}, true},
		{"curl computed path hides the host (Q1)", `curl -H "Authorization: Bearer $T" -X DELETE ` + dbHost + `/api/2.0/repos/"$ID"`, nil, false},
		{"curl computed method is unrecognized", `curl -H "Authorization: Bearer $T" -X "$M" ` + dbHost + "/api/2.0/repos/12", []string{dbUnk}, false},
		{"curl unquoted computed header can split into options", `curl -H $HDR ` + dbHost + "/api/2.0/repos/12", []string{dbP("workspace"), dbUnk}, false},
		{"curl computed list header can split into options", `curl -H "$@" ` + dbHost + "/api/2.0/repos/12", []string{dbP("workspace"), dbUnk}, false},
		{"curl brace expansion can split into options", `curl -H {X-Test:yes,-X,DELETE} -H "Authorization: Bearer $TOKEN" ` + dbHost + "/api/2.0/repos/12", []string{dbP("workspace"), dbUnk}, false},
		{"curl nested list default can split into options", `curl -H "${ABSENT:-"$@"}" -H "Authorization: Bearer $TOKEN" ` + dbHost + "/api/2.0/repos/12", []string{dbP("workspace"), dbUnk}, false},
		{"curl indirect expansion can split into options", `curl -H "${!ref}" -H "Authorization: Bearer $TOKEN" ` + dbHost + "/api/2.0/repos/12", []string{dbP("workspace"), dbUnk}, false},
		{"curl unquoted URL query with a computed header", `curl -H "Authorization: Bearer $TOKEN" ` + dbHost + "/api/2.2/jobs/get?job_id=1", []string{dbCat, dbP("workloads")}, true},
		{"curl brace expansion before :// can split into options", `curl -H {X-Test,-Kpayload}://opts -H "Authorization: Bearer $TOKEN" ` + dbHost + "/api/2.0/repos/12", []string{dbP("workspace"), dbUnk}, false},
		{"curl quoted scalar forms are one argument", `curl -H "Authorization: Bearer ${TOKENS[0]}" -H "X-Args: $*" ` + dbHost + "/api/2.2/jobs/get", []string{dbCat, dbP("workloads")}, true},
		{"curl quoted array list can split", `curl -H "${HEADERS[@]}" ` + dbHost + "/api/2.2/jobs/get", []string{dbP("workloads"), dbUnk}, false},
		{"xargs keeps curl incomplete", `xargs curl -H "Authorization: Bearer $T" ` + dbHost + "/api/2.2/jobs/get", []string{dbP("workloads"), dbUnk}, false},
		{"curl computed URL is unrecognized", `curl -X DELETE "$URL"`, nil, false},
		{"curl sql and a read keep the sql exemption", `curl --json '{"statement":"SELECT 1"}' ` + dbHost + "/api/2.0/sql/statements --next " + dbHost + "/api/2.1/clusters/list", []string{dbP("compute"), dbP("sql"), dbUnk, dbW}, false},
		{"curl glob in the fragment changes nothing", "curl -X DELETE '" + dbHost + "/api/2.0/repos/12#[1-2]'", []string{dbCat, dbD, dbP("workspace"), dbW}, true},
		{"curl request target not in origin form is unrecognized", "curl -X DELETE --request-target 'api/2.0/repos/12' " + dbHost + "/", []string{dbUnk}, false},
		{"docs host is not a workspace", "curl https://docs.databricks.com/api/2.0/clusters/list", nil, true},

		// A command the projection cannot parse: Databricks gets the
		// strictest facts, anything else none.
		{"oversized databricks query", dbQuery + "'SELECT 1 /* " + strings.Repeat("x", maxCommandBytes) + " */; DROP TABLE t'", []string{dbA, dbD, dbP("execution"), dbP("secrets"), dbUnk, dbW}, false},
		{"oversized curl to a workspace", "curl -X POST -d '{\"statement\":\"DROP TABLE t" + strings.Repeat(" ", maxCommandBytes) + "\"}' " + dbHost + "/api/2.0/sql/statements", []string{dbA, dbD, dbP("execution"), dbP("secrets"), dbUnk, dbW}, false},
		{"databricks syntax error", "databricks clusters delete 0123-abc; (", []string{dbA, dbD, dbP("execution"), dbP("secrets"), dbUnk, dbW}, false},
		{"oversized heredoc is not databricks", "cat > notes.txt <<'EOF'\n" + strings.Repeat("x", maxCommandBytes) + "\nEOF", nil, false},

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
