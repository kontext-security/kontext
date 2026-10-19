package toolcatalog

import (
	"strings"
	"testing"
)

func TestClassifyDatabricksSQL(t *testing.T) {
	long := "SELECT " + strings.Repeat("a, ", 1<<17) + "1 FROM t"
	tests := []struct {
		name       string
		sql        string
		access     string
		secrets    bool
		recognized bool
	}{
		// Known write forms stay at the base tier.
		{"select", "SELECT * FROM t", AccessWrite, false, true},
		{"lower case", "select * from t where a = 1", AccessWrite, false, true},
		{"parenthesised union", "(SELECT 1) UNION (SELECT 2)", AccessWrite, false, true},
		{"cte select", "WITH c AS (SELECT 1 AS a) SELECT a FROM c", AccessWrite, false, true},
		{"show", "SHOW GRANTS ON TABLE t", AccessWrite, false, true},
		{"describe", "DESCRIBE HISTORY t", AccessWrite, false, true},
		{"insert into", "INSERT INTO t VALUES (1, 'x')", AccessWrite, false, true},
		{"update", "UPDATE t SET a = 1 WHERE b = 2", AccessWrite, false, true},
		{"merge without delete", "MERGE INTO t USING s ON t.k = s.k WHEN MATCHED THEN UPDATE SET * WHEN NOT MATCHED THEN INSERT *", AccessWrite, false, true},
		{"create", "CREATE TABLE IF NOT EXISTS t (a INT)", AccessWrite, false, true},
		{"create external table", "CREATE EXTERNAL TABLE t (a INT) LOCATION 's3://b/t'", AccessWrite, false, true},
		{"copy into", "COPY INTO t FROM '/Volumes/main/raw/f' FILEFORMAT = CSV", AccessWrite, false, true},
		{"set", "SET spark.sql.ansi.enabled = true", AccessWrite, false, true},
		{"use", "USE CATALOG main", AccessWrite, false, true},
		{"trailing semicolon", "SELECT 1;", AccessWrite, false, true},
		{"replace function", "SELECT replace(a, 'x', 'y') FROM t", AccessWrite, false, true},
		{"mask function", "SELECT mask(ssn) FROM t", AccessWrite, false, true},
		{"aggregate filter", "SELECT count(*) FILTER (WHERE a > 1) FROM t", AccessWrite, false, true},

		// Delete forms.
		{"drop", "DROP TABLE t", AccessDelete, false, true},
		{"commit then drop", "COMMIT; DROP TABLE t", AccessDelete, false, true},
		{"delete", "DELETE FROM t WHERE a = 1", AccessDelete, false, true},
		{"delete inside cte", "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", AccessDelete, false, true},
		{"delete in subquery", "SELECT * FROM (DELETE FROM t)", AccessDelete, false, true},
		{"truncate", "TRUNCATE TABLE t", AccessDelete, false, true},
		{"insert overwrite", "INSERT OVERWRITE t SELECT * FROM s", AccessDelete, false, true},
		{"create or replace", "CREATE OR REPLACE TABLE t AS SELECT 1", AccessDelete, false, true},
		{"vacuum", "VACUUM t RETAIN 0 HOURS", AccessDelete, false, true},
		{"restore", "RESTORE TABLE t TO VERSION AS OF 1", AccessDelete, false, true},
		{"alter drop", "ALTER TABLE t DROP COLUMN c", AccessDelete, false, true},
		{"merge delete", "MERGE INTO t USING s ON t.k = s.k WHEN MATCHED THEN DELETE", AccessDelete, false, true},
		{"merge delete by source", "MERGE INTO t USING s ON t.k = s.k WHEN NOT MATCHED BY SOURCE THEN DELETE", AccessDelete, false, true},
		{"replace where", "INSERT INTO t REPLACE WHERE d = '2026-01-01' SELECT * FROM s", AccessDelete, false, true},
		{"replace using", "INSERT INTO t REPLACE USING (k) SELECT * FROM s", AccessDelete, false, true},
		{"replace on", "INSERT INTO t AS t REPLACE ON t.k = s.k (SELECT * FROM s) AS s", AccessDelete, false, true},
		{"drop inside unknown form", "BEGIN DROP TABLE t; END", AccessDelete, false, true},
		{"explain drop raises", "EXPLAIN DROP TABLE t", AccessDelete, false, true},

		// Admin forms.
		{"grant", "GRANT SELECT ON TABLE t TO `analysts`", AccessAdmin, false, true},
		{"revoke", "REVOKE ALL PRIVILEGES ON SCHEMA s FROM `x`", AccessAdmin, false, true},
		{"deny", "DENY SELECT ON TABLE t TO `x`", AccessAdmin, false, true},
		{"owner to", "ALTER TABLE t OWNER TO `x`", AccessAdmin, false, true},
		{"set owner to", "ALTER SCHEMA s SET OWNER TO `x`", AccessAdmin, false, true},
		{"set tags", "ALTER TABLE t SET TAGS ('pii' = 'true')", AccessAdmin, false, true},
		{"unset column tags", "ALTER TABLE t ALTER COLUMN c UNSET TAGS ('pii')", AccessAdmin, false, true},
		{"set tag on", "SET TAG ON TABLE t pii", AccessAdmin, false, true},
		{"set mask", "ALTER TABLE t ALTER COLUMN ssn SET MASK m", AccessAdmin, false, true},
		{"drop mask", "ALTER TABLE t ALTER COLUMN ssn DROP MASK", AccessAdmin, false, true},
		{"create with mask", "CREATE TABLE t (ssn STRING MASK m)", AccessAdmin, false, true},
		{"set row filter", "ALTER TABLE t SET ROW FILTER f ON (region)", AccessAdmin, false, true},
		{"drop row filter", "ALTER TABLE t DROP ROW FILTER", AccessAdmin, false, true},
		{"create policy", "CREATE POLICY p ON SCHEMA s ROW FILTER f TO `x` FOR TABLES", AccessAdmin, false, true},
		{"create or replace policy", "CREATE OR REPLACE POLICY p ON SCHEMA s COLUMN MASK m TO `x` FOR TABLES", AccessAdmin, false, true},
		{"drop policy", "DROP POLICY p ON SCHEMA s", AccessAdmin, false, true},
		{"storage credential", "CREATE STORAGE CREDENTIAL c WITH (AWS_IAM_ROLE = 'arn')", AccessAdmin, false, true},
		{"external location", "CREATE EXTERNAL LOCATION l URL 's3://b' WITH (CREDENTIAL c)", AccessAdmin, false, true},
		{"connection", "CREATE CONNECTION c TYPE postgresql OPTIONS (host 'h')", AccessAdmin, false, true},
		{"alter group", "ALTER GROUP g ADD USER `u`", AccessAdmin, false, true},

		// Keywords in comments, strings and quoted names do not raise.
		{"line comment", "SELECT 1 -- DROP TABLE t", AccessWrite, false, true},
		{"block comment", "SELECT /* DROP TABLE t; GRANT ALL */ 1", AccessWrite, false, true},
		{"nested comment", "SELECT /* /* DROP */ GRANT */ 1", AccessWrite, false, true},
		{"string", "SELECT 'DROP TABLE t; GRANT ALL ON t TO x'", AccessWrite, false, true},
		{"double-quoted string", `SELECT "DELETE FROM t"`, AccessWrite, false, true},
		{"escaped quote stays in string", `SELECT 'a\' DROP TABLE t --'`, AccessWrite, false, true},
		{"doubled quote", "SELECT 'it''s DROP' FROM t", AccessWrite, false, true},
		{"backtick names", "SELECT `delete`, `drop` FROM `grant`", AccessWrite, false, true},
		{"doubled backtick", "SELECT `a``drop` FROM t", AccessWrite, false, true},
		{"dollar body", "CREATE FUNCTION f() RETURNS STRING LANGUAGE PYTHON AS $$ return 'DROP TABLE t; GRANT' $$", AccessWrite, false, true},

		// Lexer edges where a naive lexer would hide a keyword.
		{"escape ends string", `SELECT 'a\'' DROP TABLE t --'`, AccessDelete, false, true},
		{"raw string has no escapes", `SELECT r'a\' DROP TABLE t --'`, AccessDelete, false, true},
		{"line comment continues past backslash", "SELECT 1 -- a\\\n'\nDROP TABLE t\n--'", AccessDelete, false, true},
		{"hint in comment does not nest", "SELECT 1 /* /*+ */ ; DROP TABLE t; /* */", AccessDelete, false, true},
		{"unclosed nested comment", "SELECT 1 /* /* */ DROP TABLE t", AccessDelete, false, true},
		{"unterminated string", "SELECT 'x; DROP TABLE t", AccessDelete, false, true},
		{"unterminated dollar body", "SELECT $$ x; GRANT ALL ON t TO u", AccessAdmin, false, true},
		{"dotless i spells I", "INSERT OVERWRıTE t SELECT 1", AccessDelete, false, true},
		{"no-break space separates", "DROP TABLE t", AccessDelete, false, true},
		{"comment splits words", "DROP/**/TABLE t", AccessDelete, false, true},

		// Secrets.
		{"secret", "SELECT secret('scope', 'key')", AccessWrite, true, true},
		{"backticked secret", "SELECT `secret`('scope', 'key')", AccessWrite, true, true},
		{"qualified try_secret", "SELECT system.builtin.try_secret('scope', 'key')", AccessWrite, true, true},
		{"secret in cte", "WITH s AS (SELECT secret('a', 'b') AS v) SELECT v FROM s", AccessWrite, true, true},
		{"secret in hint", "SELECT /*+ REPARTITION(secret('a', 'b')) */ * FROM t", AccessWrite, true, true},
		{"list secrets", "SELECT * FROM list_secrets()", AccessWrite, true, true},
		{"secret after comment", "SELECT secret /* x */ ('a', 'b')", AccessWrite, true, true},
		{"secret in unrecognized text", "COMMIT; SELECT secret('a', 'b')", AccessWrite, true, false},
		{"secret in string", "SELECT 'secret(1)'", AccessWrite, false, true},
		{"secret column", "SELECT secret FROM t", AccessWrite, false, true},

		// Unrecognized: the caller keeps write.
		{"execute immediate", "EXECUTE IMMEDIATE 'DROP TABLE t'", AccessWrite, false, false},
		{"call", "CALL system.p()", AccessWrite, false, false},
		{"identifier clause", "SELECT * FROM IDENTIFIER('t')", AccessWrite, false, false},
		{"http_request", "SELECT http_request(conn => 'c', method => 'GET', path => '/')", AccessWrite, false, false},
		{"quoted http_request", `SELECT "http_request"(conn => 'c')`, AccessWrite, false, false},
		{"ai_query", "SELECT ai_query('endpoint', 'hi')", AccessWrite, false, false},
		{"ai function", "SELECT `system`.`ai`.`ai_gen`('hi')", AccessWrite, false, false},
		{"read_files", "SELECT * FROM read_files('s3://bucket/path')", AccessWrite, false, false},
		{"multiple statements", "SELECT 1; SELECT 2", AccessWrite, false, false},
		{"alter outside known forms", "ALTER TABLE t ADD COLUMN c INT", AccessWrite, false, false},
		{"optimize", "OPTIMIZE t ZORDER BY (a)", AccessWrite, false, false},
		{"scripting block", "BEGIN SELECT 1; END", AccessWrite, false, false},
		{"unterminated string alone", "SELECT 'abc", AccessWrite, false, false},
		{"empty", "", AccessWrite, false, false},
		{"blank", " \n\t ", AccessWrite, false, false},
		{"semicolons", ";;", AccessWrite, false, false},
		{"comment only", "-- DROP TABLE t", AccessWrite, false, false},

		{"very long", long, AccessWrite, false, true},
		{"very long then drop", long + "; DROP TABLE t", AccessDelete, false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			access, secrets, recognized := ClassifyDatabricksSQL(test.sql)
			if access != test.access || secrets != test.secrets || recognized != test.recognized {
				t.Fatalf("ClassifyDatabricksSQL() = %q, %v, %v; want %q, %v, %v",
					access, secrets, recognized, test.access, test.secrets, test.recognized)
			}
		})
	}
}
