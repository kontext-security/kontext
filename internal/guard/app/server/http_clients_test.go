package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/risk"
)

// Exercise the hook decision, including Observe's non-enforcing answer.
// go test -json preserves an expected/actual receipt for each request.
func TestHTTPClientPolicyDecisions(t *testing.T) {
	useMCPHome(t)
	const githubWrite = `forbid(principal, action, resource) when { context has shell && context.shell.facts.contains("github/write=true") };`
	const githubForce = `forbid(principal, action, resource) when { context has shell && context.shell.facts.contains("github/operation=force-push") };`
	const githubGuard = `forbid(principal, action, resource) when { context has shell && context.shell.facts.contains("github/route=unrecognized") };`
	const databricksGuard = `forbid(principal, action, resource) when { context has shell && context.shell.facts.contains("databricks/route=unrecognized") };`
	tests := []struct {
		name, command, policy string
		blocked               bool
	}{
		{"httpie shell brace expansion remains opaque", `http -I PATCH https://api.github.com/repos/acme/sandbox/git/re{f,f}s/heads/main sha=abc force:=true`, githubForce + ` @id("fallback-guard") ` + githubGuard, true},
		{"wget shell brace expansion remains opaque", `wget --method=PATCH --body-data='{"sha":"abc","force":true}' https://api.github.com/repos/acme/sandbox/git/re{f,f}s/heads/main`, githubForce + ` @id("fallback-guard") ` + githubGuard, true},
		{"httpie offline preview", `http --offline -I DELETE https://api.github.com/repos/acme/sandbox`, githubWrite + ` @id("fallback-guard") ` + githubGuard, false},
		{"httpie offline computed authorization", `http --offline -I DELETE https://api.github.com/repos/acme/sandbox "Authorization:Bearer $TOKEN"`, githubWrite + ` @id("fallback-guard") ` + githubGuard, false},
		{"httpie offline reset before offline sends request", `http --no-offline --offline -I DELETE https://api.github.com/repos/acme/sandbox`, githubWrite, true},
		{"httpie offline reset sends request", `http --offline --no-offline -I DELETE https://api.github.com/repos/acme/sandbox`, githubWrite, true},
		{"httpie offline nested request still checked", `http --offline -I DELETE https://api.github.com/repos/acme/sandbox "X-Value:$(curl -X DELETE https://api.github.com/repos/acme/sandbox)"`, githubWrite, true},
		{"inner literal pipe replaces inherited input", `printf 'curl https://api.github.com' | bash -c 'printf "" | bash'`, githubGuard, false},
		{"cat can forward inherited code", `printf 'curl https://api.github.com' | bash -c 'cat | bash'`, githubGuard, true},
		{"emitter stdout redirected away", `printf 'curl https://api.github.com' >/dev/null | bash`, githubGuard, false},
		{"emitter stdout sent to file", `printf 'curl https://api.github.com' >preview.txt | bash`, githubGuard, false},
		{"emitter descriptor restored to pipe", `printf 'curl https://api.github.com' 3>&1 >/dev/null 1>&3 | bash`, githubGuard, true},
		{"pipe overridden by empty stdin", `printf 'curl https://api.github.com' | bash </dev/null`, githubGuard, false},
		{"inherited pipe overridden by empty stdin", `printf 'curl https://api.github.com' | bash -c 'bash </dev/null'`, githubGuard, false},
		{"heredoc overridden by empty stdin", `bash <<< 'curl https://api.github.com' </dev/null`, githubGuard, false},
		{"last stdin still executes code", `bash </dev/null <<< 'curl https://api.github.com'`, githubGuard, true},
		{"saved stdin history stays bounded", `printf 'curl https://api.github.com' | bash 3<&0 ` + strings.Repeat(`0</dev/null 0<&3 `, 64), githubGuard, true},
		{"saved stdin restores pipe", `printf 'curl https://api.github.com' | bash 3<&0 0</dev/null 0<&3`, githubGuard, true},
		{"saved inherited stdin restores pipe", `printf 'curl https://api.github.com' | bash -c 'bash 3<&0 0</dev/null 0<&3'`, githubGuard, true},
		{"saved stdin restores heredoc", `bash <<< 'curl https://api.github.com' 3<&0 0</dev/null 0<&3`, githubGuard, true},
		{"final file still replaces saved stdin", `printf 'curl https://api.github.com' | bash 3<&0 0</dev/null 0<&3 </dev/null`, githubGuard, false},
		{"closed stdin replaces pipe", `printf 'curl https://api.github.com' | bash 0<&-`, githubGuard, false},
		{"inner literal pipe replaces outer pipe facts", `printf 'curl https://api.github.com' | { printf '' | bash; }`, githubGuard, false},
		{"stdin self duplication keeps pipe", `printf 'curl https://api.github.com' | bash 0<&0`, githubGuard, true},
		{"nested xargs client target remains unresolved", `bash -c 'printf "%s" "$1" | xargs -IURL http -I DELETE URL' _ https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"custom cat is still a provider script", `./cat https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"custom jq is still a provider script", `/tmp/jq https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"custom formatter is still a provider script", `printf '{"url":"https://api.github.com"}' | ./python3 -m json.tool`, githubGuard, true},
		{"system cat is a local reader", `/bin/cat api.github.com`, githubGuard, false},
		{"homebrew jq is a local formatter", `printf '{"url":"https://api.github.com"}' | /opt/homebrew/bin/jq .url`, githubGuard, false},
		{"homebrew python json formatter", `printf '{"url":"https://api.github.com"}' | /opt/homebrew/bin/python3 -m json.tool`, githubGuard, false},
		{"opaque python JSON input stays conservative", `printf '{"url":"https://api.github.com"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])'`, githubGuard, true},
		{"opaque python can execute input", `printf 'import urllib.request; urllib.request.urlopen("https://api.github.com")' | python3 -c 'import sys; exec(sys.stdin.read())'`, githubGuard, true},
		{"custom mkdir is still a provider script", `/tmp/mkdir https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"relative touch is still a provider script", `./touch https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"wrapped custom mkdir is still a provider script", `env /tmp/mkdir https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"absolute mkdir is a local file operation", `/bin/mkdir -p api.github.com`, githubGuard, false},
		{"absolute touch is a local file operation", `/usr/bin/touch api.github.com`, githubGuard, false},
		{"absolute mkdir with databricks filename", `/bin/mkdir -p dbc-1234.cloud.databricks.com`, databricksPresets["block-unrecognized-databricks-operations"], false},
		{"unknown script with provider filename", `/tmp/cleanup api.github.com`, githubGuard, true},
		{"absolute ripgrep is a local read", `/opt/homebrew/bin/rg -n api.github.com README.md`, githubGuard, false},
		{"httpie nested external target with provider payload", `bash -c 'http -I POST https://example.com/hooks url="$1"' _ https://api.github.com`, githubGuard, false},
		{"httpie nested external target with provider header", `bash -c 'http -I POST https://example.com/hooks "X-Source:$1"' _ https://api.github.com`, githubGuard, false},
		{"httpie nested external target with provider query", `bash -c 'http -I GET https://example.com/hooks url=="$1"' _ https://api.github.com`, githubGuard, false},
		{"wget nested external target with provider payload", `bash -c 'wget --method=POST --body-data="$1" https://example.com/hooks' _ https://api.github.com`, githubGuard, false},
		{"curl computed JSON keeps deletion fallback", `curl --json='{"statement":"SELECT 1",' --json="$TAIL" https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements`, databricksPresets["block-databricks-deletion"] + ` @id("fallback-guard") ` + databricksPresets["block-unrecognized-databricks-operations"], true},
		{"curl computed JSON keeps administration fallback", `curl --json='{"statement":"SELECT 1",' --json="$TAIL" https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements`, databricksPresets["protect-databricks-administration"] + ` @id("fallback-guard") ` + databricksPresets["block-unrecognized-databricks-operations"], true},
		{"httpie computed method and github target", `METHOD=DELETE; OWNER=acme; http -I "$METHOD" "https://api.github.com/repos/$OWNER/sandbox"`, githubGuard, true},
		{"httpie computed method and databricks target", `METHOD=POST; JOBID=123; http -I "$METHOD" "https://dbc-1234.cloud.databricks.com/api/2.2/jobs/delete?job_id=$JOBID"`, databricksPresets["block-unrecognized-databricks-operations"], true},
		{"httpie custom verb retains host", `http -I PURGE https://dbc-1234.cloud.databricks.com/api/2.2/jobs/delete`, databricksPresets["block-unrecognized-databricks-operations"], true},
		{"nested httpie positional target", `bash -c 'http -I DELETE "$1"' _ https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"nested wget positional target", `bash -c 'wget --method=POST "$1"' _ https://dbc-1234.cloud.databricks.com/api/2.2/jobs/delete`, databricksPresets["block-unrecognized-databricks-operations"], true},
		{"nested positional code emitter", `bash -c 'echo "$1"' _ 'curl -X DELETE https://api.github.com/repos/acme/sandbox' | bash`, githubGuard, true},
		{"nested computed positional eval", `bash -c 'eval "$1"' _ "curl -X DELETE -H 'Authorization: Bearer $TOKEN' https://api.github.com/repos/acme/sandbox"`, githubGuard, true},
		{"positional emitter remains local output", `bash -c 'echo "$1"' _ https://api.github.com/repos/acme/sandbox`, githubGuard, false},
		{"positional code emitter formatted as data", `bash -c 'echo "$1"' _ 'curl -X DELETE https://api.github.com/repos/acme/sandbox' | python3 -m json.tool`, githubGuard, false},
		{"nested shell emitter retains host", `bash -c 'echo "curl -X DELETE https://api.github.com/repos/acme/sandbox"' | bash`, githubGuard, true},
		{"nested shell emitter formatted as data", `bash -c 'echo "https://api.github.com"' | python3 -m json.tool`, githubGuard, false},
		{"wget attached short computed output", `wget -O"$OUT" --method=POST --body-data='{"job_id":123}' https://dbc-1234.cloud.databricks.com/api/2.2/jobs/delete`, databricksPresets["block-databricks-deletion"], true},
		{"wget attached combined computed output", `wget -qO"$OUT" --method=POST --body-data='{"job_id":123}' https://dbc-1234.cloud.databricks.com/api/2.2/jobs/delete`, databricksPresets["block-databricks-deletion"], true},
		{"httpie last raw body wins", "http -I POST https://api.github.com/graphql --raw='{\"query\": \"query { viewer { login } }\"}' --raw='{\"query\": \"mutation { updateRef(input: {refId: \\\"R_1\\\", oid: \\\"abc\\\", force: true}) { clientMutationId } }\"}'", githubForce, true},
		{"wget last body data wins", "wget --method=POST --body-data='{\"query\": \"query { viewer { login } }\"}' --body-data='{\"query\": \"mutation { updateRef(input: {refId: \\\"R_1\\\", oid: \\\"abc\\\", force: true}) { clientMutationId } }\"}' https://api.github.com/graphql", githubForce, true},
		{"wget last post data wins", "wget --post-data='{\"query\": \"query { viewer { login } }\"}' --post-data='{\"query\": \"mutation { updateRef(input: {refId: \\\"R_1\\\", oid: \\\"abc\\\", force: true}) { clientMutationId } }\"}' https://api.github.com/graphql", githubForce, true},
		{"wget earlier SQL body does not execute", "wget --method=POST --body-data='{\"statement\": \"DROP TABLE t\"}' --body-data='{\"statement\": \"SELECT 1\"}' https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements", databricksPresets["block-databricks-deletion"], false},
		{"httpie literal URL brackets are data", `http -I GET 'https://dbc-1234.cloud.databricks.com/api/2.0/dbfs/list?path=/tmp/report[1]'`, databricksPresets["block-unrecognized-databricks-operations"], false},
		{"wget literal URL braces are data", `wget 'https://dbc-1234.cloud.databricks.com/api/2.0/dbfs/list?path=/tmp/report{1}'`, databricksPresets["block-unrecognized-databricks-operations"], false},
		{"httpie SQL with literal URL brackets", `http -I POST 'https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements?tag=report[1]' statement='DROP TABLE t'`, databricksPresets["block-databricks-deletion"], true},
		{"wget SQL with literal URL braces", `wget --method=POST --body-data='{"statement":"DROP TABLE t"}' 'https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements?tag=report{1}'`, databricksPresets["block-databricks-deletion"], true},
		{"wget github delete", `wget --method=DELETE --header="Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/acme/sandbox`, githubWrite, true},
		{"wget github read", `wget -qO- https://api.github.com/repos/acme/sandbox`, githubWrite, false},
		{"wget output filename", `wget -qO output.json https://api.github.com/repos/acme/sandbox`, githubGuard, false},
		{"wget databricks delete", `wget --method=POST --body-data='{"job_id":123}' https://dbc-1234.cloud.databricks.com/api/2.2/jobs/delete`, databricksPresets["block-databricks-deletion"], true},
		{"wget SQL body", `wget --method POST --body-data '{"statement":"DROP TABLE t"}' https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements`, databricksPresets["block-databricks-deletion"], true},
		{"wget computed attached body", `wget --method=POST --body-data="$BODY" https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements`, databricksPresets["block-databricks-deletion"], true},
		{"wget computed body overrides readable SELECT", `wget --method POST --body-data='{"statement":"SELECT 1"}' --body-data="$BODY" https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements`, databricksPresets["block-databricks-deletion"], true},
		{"wget computed body overrides readable SELECT for admin", `wget --method POST --body-data='{"statement":"SELECT 1"}' --body-data="$BODY" https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements`, databricksPresets["protect-databricks-administration"], true},
		{"wget computed post data overrides readable SELECT", `wget --post-data='{"statement":"SELECT 1"}' --post-data="$BODY" https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements`, databricksPresets["block-databricks-deletion"], true},
		{"httpie abbreviated option retains target", `http -I --time 10 DELETE https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"httpie abbreviated option retains bare target", `http -I --time 10 DELETE api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"httpie uncertain option keeps field URL as data", `http -I --unknown https://example.com url=https://api.github.com`, githubGuard, false},
		{"httpie unknown option after target keeps payload as data", `http -I https://example.com --unknown https://api.github.com`, githubGuard, false},
		{"absolute jq JSON is data", `/usr/bin/jq -n '{"url":"https://api.github.com"}'`, githubGuard, false},
		{"httpie nested JSON", `http --ignore-stdin POST https://dbc-1234.cloud.databricks.com/api/2.2/jobs/run-now job_parameters[mode]:='"prod"'`, databricksPresets["protect-databricks-runs-and-deploys"], true},
		{"wrapped code emitter", `command printf 'curl -X DELETE https://api.github.com/repos/acme/sandbox' | bash`, githubGuard, true},
		{"JSON formatting provider URL", `printf '{"url":"https://api.github.com"}' | python3 -m json.tool`, githubGuard, false},
		{"HTTPie escaped GraphQL", `http --ignore-stdin POST https://api.github.com/graphql 'query=mutation { updateRef(input\: {refId\: "R_1", oid\: "abc", force\: true}) { clientMutationId } }'`, githubForce, true},
		{"wget computed custom header", `wget --method=POST --header="X-Request-Id: $ID" --body-data='{"job_id":123}' https://dbc-1234.cloud.databricks.com/api/2.2/jobs/delete`, databricksPresets["block-databricks-deletion"], true},
		{"computed code emitter", `printf "%s" "curl -X DELETE https://api.github.com/repos/acme/sandbox -H 'Authorization: Bearer $TOKEN'" | bash`, githubGuard, true},
		{"wget computed URL host", `wget "https://api.github.com/repos/$OWNER/sandbox"`, githubGuard, true},
		{"httpie computed URL host", `http --ignore-stdin GET "https://api.github.com/repos/$OWNER/sandbox"`, githubGuard, true},
		// curl keeps the literal host of a URL with a computed part too.
		{"curl computed URL host", `curl -X DELETE "https://api.github.com/repos/$OWNER/$REPO"`, githubGuard, true},
		{"curl partly computed URL host", `curl -X DELETE "https://api.github.com/repos/acme/$REPO"`, githubGuard, true},
		{"curl unquoted computed URL host", `curl -X DELETE https://api.github.com/repos/$OWNER/sandbox`, githubGuard, true},
		{"curl computed --url host", `curl -X DELETE --url "https://api.github.com/repos/$OWNER/sandbox"`, githubGuard, true},
		{"curl computed attached --url host", `curl -X DELETE --url="https://api.github.com/repos/$OWNER/sandbox"`, githubGuard, true},
		{"curl wholly quoted computed --url host", `curl -X DELETE "--url=https://api.github.com/repos/$OWNER/sandbox"`, githubGuard, true},
		{"curl computed URL after option terminator", `curl -X DELETE -- "https://api.github.com/repos/$OWNER/sandbox"`, githubGuard, true},
		{"curl short cluster before computed URL", `curl -sX DELETE "https://api.github.com/repos/$OWNER/sandbox"`, githubGuard, true},
		{"wrapped curl computed URL host", `env TZ=UTC curl -X DELETE "https://api.github.com/repos/$OWNER/sandbox"`, githubGuard, true},
		{"curl computed Databricks URL host", `curl -X POST "https://dbc-1234.cloud.databricks.com/api/2.2/jobs/$ACTION"`, databricksGuard, true},
		{"curl computed host stays unknown", `curl -X DELETE "https://$HOST/repos/acme/sandbox"`, githubGuard, false},
		{"curl fully computed URL stays unknown", `curl -X DELETE "$URL"`, githubGuard, false},
		{"curl computed body is data", `curl -X POST -d "{\"url\":\"https://api.github.com/$X\"}" https://example.com/hooks`, githubGuard, false},
		{"curl computed header is data", `curl -H "Referer: https://api.github.com/$X" https://example.com`, githubGuard, false},
		{"curl computed output path is data", `curl -o "api.github.com/$X.json" https://example.com/file`, githubGuard, false},
		{"curl computed attached body is data", `curl -d"{\"url\":\"https://api.github.com/$X\"}" https://example.com/hooks`, githubGuard, false},
		{"curl computed attached referer is data", `curl --referer="https://api.github.com/$X" https://example.com`, githubGuard, false},
		{"curl value of an unknown option is data", `curl --noproxy "api.github.com,$X" https://example.com`, githubGuard, false},
		{"curl URL value of an unknown option is data", `curl --doh-url "https://api.github.com/$X" https://example.com`, githubGuard, false},
		{"curl computed scheme names no host", `curl -X DELETE "$SCHEME://api.github.com/repos/acme/sandbox"`, githubGuard, false},
		{"curl provider host in a computed URL's query is data", `curl "$BASE/cb?next=https://api.github.com/$X"`, githubGuard, false},
		{"httpie computed first target keeps a later literal target", `http "$SCHEME://example.com" DELETE http://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"absolute grep", `/usr/bin/grep -n api.github.com README.md`, githubGuard, false},
		{"wget SQL file", `wget --method POST --body-file drop.json https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements`, databricksPresets["block-databricks-deletion"], true},
		{"httpie github delete", `http DELETE https://api.github.com/repos/acme/sandbox`, githubWrite, true},
		{"httpie github read", `https GET api.github.com/repos/acme/sandbox`, githubWrite, false},
		{"httpie inherited stdin", `http https://api.github.com/repos/acme/sandbox/issues`, githubWrite, true},
		{"httpie uppercase computed", `HTTP https://api.github.com/repos/acme/sandbox/issues title="$TITLE"`, githubWrite, true},
		{"httpie computed custom header", `http --ignore-stdin POST https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements X-Test:"$VALUE" statement='DROP TABLE t'`, databricksPresets["block-databricks-deletion"], true},
		{"httpie value option before method", `http --max-redirects 5 DELETE https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"httpie function stdin is opaque", `f(){ http PATCH https://api.github.com/repos/acme/sandbox/git/refs/heads/main; }; printf '%s' "$BODY" | f`, githubGuard, true},
		{"httpie short ignore stdin and response option", `http -I --max-headers 5 GET https://api.github.com/repos/acme/sandbox`, githubGuard, false},
		{"httpie inferred post", `http https://api.github.com/repos/acme/sandbox/issues title=test`, githubWrite, true},
		{"httpie computed post", `http https://api.github.com/repos/acme/sandbox/issues title="$TITLE"`, githubWrite, true},
		{"httpie separator in value", `http https://api.github.com/repos/acme/sandbox/issues title=a==b`, githubWrite, true},
		{"httpie option after URL", `http POST https://dbc-1234.cloud.databricks.com/api/2.2/jobs/delete job_id:=123 --timeout 10`, databricksPresets["block-databricks-deletion"], true},
		{"httpie piped body", `printf '{"title":"test"}' | http https://api.github.com/repos/acme/sandbox/issues`, githubWrite, true},
		{"httpie redirected body", `http https://api.github.com/repos/acme/sandbox/issues < request.json`, githubWrite, true},
		{"httpie group redirected body", `{ http https://api.github.com/repos/acme/sandbox/issues; } < request.json`, githubWrite, true},
		{"httpie multiline SQL", "http POST https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements statement='DROP\nTABLE t'", databricksPresets["block-databricks-deletion"], true},
		{"httpie computed SQL", `http POST https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements statement="$SQL" warehouse_id=w`, databricksPresets["block-databricks-deletion"], true},
		{"redirect without command", `< request.json`, githubGuard, false},
		{"httpie escaped separator", `http --ignore-stdin https://api.github.com/repos/acme/sandbox/issues 'x\==1'`, githubWrite, true},
		{"uppercase literal emitter", `/usr/bin/PRINTF 'curl -X DELETE https://api.github.com/repos/acme/sandbox' | bash`, githubGuard, true},
		{"wget attached computed output", `wget --method=POST --output-document="$OUT" --body-data='{"job_id":123}' https://dbc-1234.cloud.databricks.com/api/2.2/jobs/delete`, databricksPresets["block-databricks-deletion"], true},
		{"wget attached computed timeout", `wget --method=POST --timeout="$TIMEOUT" --body-data='{"job_id":123}' https://dbc-1234.cloud.databricks.com/api/2.2/jobs/delete`, databricksPresets["block-databricks-deletion"], true},
		{"wget referer header is data", `wget --referer https://api.github.com https://example.com`, githubGuard, false},
		{"wget user agent is data", `wget --user-agent https://api.github.com https://example.com`, githubGuard, false},
		{"wget webhook payload is data", `wget --header="Authorization: Bearer $TOKEN" --post-data='{"url":"https://api.github.com"}' https://example.com/hooks`, githubGuard, false},
		{"httpie webhook payload is data", `http POST https://example.com/hooks Authorization:"Bearer $TOKEN" url=https://api.github.com`, githubGuard, false},
		{"wget provider text in path is data", `wget --header="Authorization: Bearer $TOKEN" https://example.com/api.github.com`, githubGuard, false},
		{"JSON formatter module options", `printf '{"url":"https://api.github.com"}' | python3 -m json.tool --sort-keys`, githubGuard, false},
		{"pipeline JSON read", `curl https://api.github.com/repos/acme/sandbox | python3 -m json.tool`, githubGuard, false},
		{"input process substitution", `bash < <(printf 'curl -X DELETE https://api.github.com/repos/acme/sandbox')`, githubGuard, true},
		{"output process substitution is data", `bash > >(printf 'curl -X DELETE https://api.github.com/repos/acme/sandbox')`, githubGuard, false},
		{"dynamic eval names provider", `eval "$CMD https://api.github.com/repos/acme/sandbox"`, githubGuard, true},
		{"shell here string", `bash <<< 'curl -X DELETE https://api.github.com/repos/acme/sandbox'`, githubGuard, true},
		{"piped nested shell", `printf 'curl -X DELETE https://api.github.com/repos/acme/sandbox' | bash -c bash`, githubGuard, true},
		{"httpie ignores stdin", `printf '{}' | http --ignore-stdin https://api.github.com/repos/acme/sandbox`, githubWrite, false},
		{"wget attached computed authorization", `wget --method=POST --header="Authorization: Bearer $TOKEN" --body-data='{"job_id":123}' https://dbc-1234.cloud.databricks.com/api/2.2/jobs/delete`, databricksPresets["block-databricks-deletion"], true},
		{"httpie preserves SQL backslashes for deletion", `http POST https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements "statement=SELECT '\\\\'; DROP TABLE t; -- '"`, databricksPresets["block-databricks-deletion"], true},
		{"httpie preserves SQL backslashes for administration", `http POST https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements "statement=SELECT '\\\\'; GRANT SELECT ON TABLE t TO u; -- '"`, databricksPresets["protect-databricks-administration"], true},
		{"httpie SQL fields", `http POST https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements statement='DROP TABLE t' warehouse_id=w`, databricksPresets["block-databricks-deletion"], true},
		{"httpie raw SQL", `http --raw '{"statement":"DROP TABLE t"}' POST https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements`, databricksPresets["block-databricks-deletion"], true},
		{"httpie file body", `http POST https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements @drop.json`, databricksPresets["block-databricks-deletion"], true},
		{"httpie databricks read", `http GET https://dbc-1234.cloud.databricks.com/api/2.1/jobs/list`, databricksPresets["databricks-read-only"], false},
		{"python github", `python3 -c "import urllib.request; urllib.request.urlopen('https://api.github.com/repos/acme/sandbox')"`, githubGuard, true},
		{"python computed token", `python3 -c "call('https://api.github.com/repos/acme/sandbox', '$TOKEN')"`, githubGuard, true},
		{"wrapped python", `env python3 -c "fetch('https://api.github.com/repos/acme/sandbox')"`, githubGuard, true},
		{"python here string", `python3 <<< "fetch('https://api.github.com/repos/acme/sandbox')"`, githubGuard, true},
		{"piped shell interpreter", `printf "fetch('https://api.github.com/repos/acme/sandbox')" | bash -c 'python3'`, githubGuard, true},
		{"shell heredoc interpreter", "bash -c 'python3' <<'PY'\nfetch('https://api.github.com/repos/acme/sandbox')\nPY", githubGuard, true},
		{"python heredoc", "python3 - <<'PY'\nfetch('https://api.github.com/repos/acme/sandbox')\nPY", githubGuard, true},
		{"node databricks", `node -e "fetch('https://dbc-1234.cloud.databricks.com/api/2.2/jobs/delete')"`, databricksPresets["block-unrecognized-databricks-operations"], true},
		{"literal concatenated host", `./cleanup https://api.git''hub.com/repos/acme/sandbox`, githubGuard, true},
		{"piped interpreter", `printf "fetch('https://api.github.com/repos/acme/sandbox')" | python3`, githubGuard, true},
		{"shell positional host", `bash -c 'python3 -c "fetch("$1")"' _ https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"absolute echo", `/bin/echo https://api.github.com`, githubGuard, false},
		{"absolute printf", `/usr/bin/printf https://api.github.com`, githubGuard, false},
		{"script with host", `./cleanup.sh https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"extensionless script", `./cleanup https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"shell script with host", `bash cleanup.sh https://dbc-1234.cloud.databricks.com`, databricksPresets["block-unrecognized-databricks-operations"], true},
		{"unrelated python", `python3 -c 'print(1)'`, githubGuard, false},
		{"host in read output", `echo https://api.github.com/repos/acme/sandbox`, githubGuard, false},
		{"host in shell output", `bash -c 'echo https://api.github.com/repos/acme/sandbox'`, githubGuard, false},
		{"nested host belongs to echo", `bash -c 'echo https://api.github.com; python3 -c "print(1)"'`, githubGuard, false},
		{"lookalike host", `python3 -c "fetch('https://api.github.com.example.com')"`, githubGuard, false},
		{"opaque wget config", `wget --config request.conf https://api.github.com/repos/acme/sandbox`, githubGuard, true},
		{"opaque httpie session", `http --session session.json https://api.github.com/repos/acme/sandbox`, githubGuard, true},
	}
	for _, tc := range tests {
		for _, mode := range []cedareval.RolloutMode{cedareval.RolloutModeObserve, cedareval.RolloutModeEnforce} {
			t.Run(tc.name+"/"+string(mode), func(t *testing.T) {
				policy := `@id("default-permit") permit(principal, action, resource); @id("test-preset") ` + tc.policy
				deployment := cedarTestDeployment(t, mode, policy)
				provider := newCedarPolicyProvider(staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)
				decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": tc.command}))
				if err != nil {
					t.Fatal(err)
				}
				want := risk.DecisionAllow
				if tc.blocked && mode == cedareval.RolloutModeEnforce {
					want = risk.DecisionDeny
				}
				if decision.Cedar == nil || decision.Cedar.EngineErrorCount != 0 || decision.Cedar.Mapping.EvaluationState != cedareval.EvaluationStateEvaluated {
					t.Fatalf("evaluation failed: %#v", decision.Cedar)
				}
				blocked := decision.Cedar.Mapping.DerivedCedarAction == cedareval.DerivedCedarActionDeny
				receipt, _ := json.Marshal(map[string]any{"mode": mode, "command": tc.command, "expected_block": tc.blocked, "actual_block": blocked, "effective": decision.Decision, "policies": decision.Cedar.Mapping.DeterminingPolicyIDs})
				t.Log(string(receipt))
				if decision.Decision != want || blocked != tc.blocked {
					t.Fatalf("got %s/block=%t, want %s/block=%t", decision.Decision, blocked, want, tc.blocked)
				}
			})
		}
	}
}
