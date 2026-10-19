package toolcatalog

import (
	"strings"
	"testing"
	"time"
)

func TestClassifyDatabricksSQL(t *testing.T) {
	long := "SELECT " + strings.Repeat("a, ", 1<<17) + "1 FROM t"
	tests := []struct {
		name       string
		sql        string
		deletes    bool
		admin      bool
		secrets    bool
		recognized bool
	}{
		// Known write forms stay at the base tier.
		{"select", "SELECT * FROM t", false, false, false, true},
		{"lower case", "select * from t where a = 1", false, false, false, true},
		{"parenthesised union", "(SELECT 1) UNION (SELECT 2)", false, false, false, true},
		{"cte select", "WITH c AS (SELECT 1 AS a) SELECT a FROM c", false, false, false, true},
		{"show", "SHOW GRANTS ON TABLE t", false, false, false, true},
		{"describe", "DESCRIBE HISTORY t", false, false, false, true},
		{"insert into", "INSERT INTO t VALUES (1, 'x')", false, false, false, true},
		{"update", "UPDATE t SET a = 1 WHERE b = 2", false, false, false, true},
		{"merge without delete", "MERGE INTO t USING s ON t.k = s.k WHEN MATCHED THEN UPDATE SET * WHEN NOT MATCHED THEN INSERT *", false, false, false, true},
		{"create", "CREATE TABLE IF NOT EXISTS t (a INT)", false, false, false, true},
		{"create external table", "CREATE EXTERNAL TABLE t (a INT) LOCATION 's3://b/t'", false, false, false, true},
		{"copy into", "COPY INTO t FROM '/Volumes/main/raw/f' FILEFORMAT = CSV", false, false, false, true},
		{"set", "SET spark.sql.ansi.enabled = true", false, false, false, true},
		{"use", "USE CATALOG main", false, false, false, true},
		{"trailing semicolon", "SELECT 1;", false, false, false, true},
		{"replace function", "SELECT replace(a, 'x', 'y') FROM t", false, false, false, true},
		{"mask function", "SELECT mask(ssn) FROM t", false, false, false, true},
		{"aggregate filter", "SELECT count(*) FILTER (WHERE a > 1) FROM t", false, false, false, true},

		// Delete forms.
		{"drop", "DROP TABLE t", true, false, false, true},
		{"commit then drop", "COMMIT; DROP TABLE t", true, false, false, true},
		{"delete", "DELETE FROM t WHERE a = 1", true, false, false, true},
		{"delete inside cte", "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", true, false, false, true},
		{"delete in subquery", "SELECT * FROM (DELETE FROM t)", true, false, false, true},
		{"truncate", "TRUNCATE TABLE t", true, false, false, true},
		{"insert overwrite", "INSERT OVERWRITE t SELECT * FROM s", true, false, false, true},
		{"create or replace", "CREATE OR REPLACE TABLE t AS SELECT 1", true, true, false, true},
		{"vacuum", "VACUUM t RETAIN 0 HOURS", true, false, false, true},
		{"restore", "RESTORE TABLE t TO VERSION AS OF 1", true, false, false, true},
		{"alter drop", "ALTER TABLE t DROP COLUMN c", true, false, false, true},
		{"merge delete", "MERGE INTO t USING s ON t.k = s.k WHEN MATCHED THEN DELETE", true, false, false, true},
		{"merge delete by source", "MERGE INTO t USING s ON t.k = s.k WHEN NOT MATCHED BY SOURCE THEN DELETE", true, false, false, true},
		{"replace where", "INSERT INTO t REPLACE WHERE d = '2026-01-01' SELECT * FROM s", true, false, false, true},
		{"replace using", "INSERT INTO t REPLACE USING (k) SELECT * FROM s", true, false, false, true},
		{"replace on", "INSERT INTO t AS t REPLACE ON t.k = k2 (SELECT * FROM s)", true, false, false, true},
		// A qualified column before a subquery reads as a UDF call: still delete.
		{"replace on qualified", "INSERT INTO t AS t REPLACE ON t.k = s.k (SELECT * FROM s) AS s", true, false, false, true},
		{"refresh full", "REFRESH STREAMING TABLE sales FULL", true, false, false, true},
		{"refresh where", "REFRESH MATERIALIZED VIEW mv WHERE d < '2026-01-01'", true, false, false, true},
		{"refresh full in block", "BEGIN REFRESH STREAMING TABLE sales FULL; END", true, false, false, true},
		{"refresh where in if", "IF x > 0 THEN REFRESH MATERIALIZED VIEW mv WHERE d < 1; END IF", true, false, false, true},
		{"repair any file privileges", "MSCK REPAIR ANY FILE PRIVILEGES", false, true, false, true},
		{"repair object privileges", "MSCK REPAIR TABLE t PRIVILEGES", false, true, false, true},
		{"repair sync partitions", "MSCK REPAIR TABLE t SYNC PARTITIONS", true, false, false, true},
		{"repair drop partitions", "REPAIR TABLE t DROP PARTITIONS", true, false, false, true},
		{"drop inside unknown form", "BEGIN DROP TABLE t; END", true, false, false, true},
		{"explain drop raises", "EXPLAIN DROP TABLE t", true, false, false, true},

		// Admin forms.
		{"grant", "GRANT SELECT ON TABLE t TO `analysts`", false, true, false, true},
		{"revoke", "REVOKE ALL PRIVILEGES ON SCHEMA s FROM `x`", false, true, false, true},
		{"deny", "DENY SELECT ON TABLE t TO `x`", false, true, false, true},
		{"owner to", "ALTER TABLE t OWNER TO `x`", false, true, false, true},
		{"set owner to", "ALTER SCHEMA s SET OWNER TO `x`", false, true, false, true},
		{"set tags", "ALTER TABLE t SET TAGS ('pii' = 'true')", false, true, false, true},
		{"unset column tags", "ALTER TABLE t ALTER COLUMN c UNSET TAGS ('pii')", false, true, false, true},
		{"set tag on", "SET TAG ON TABLE t pii", false, true, false, true},
		{"set mask", "ALTER TABLE t ALTER COLUMN ssn SET MASK m", false, true, false, true},
		{"drop mask", "ALTER TABLE t ALTER COLUMN ssn DROP MASK", true, true, false, true},
		{"create with mask", "CREATE TABLE t (ssn STRING MASK m)", false, true, false, true},
		{"set row filter", "ALTER TABLE t SET ROW FILTER f ON (region)", false, true, false, true},
		{"drop row filter", "ALTER TABLE t DROP ROW FILTER", true, true, false, true},
		{"create policy", "CREATE POLICY p ON SCHEMA s ROW FILTER f TO `x` FOR TABLES", false, true, false, true},
		{"create or replace policy", "CREATE OR REPLACE POLICY p ON SCHEMA s COLUMN MASK m TO `x` FOR TABLES", true, true, false, true},
		{"drop policy", "DROP POLICY p ON SCHEMA s", true, true, false, true},
		{"storage credential", "CREATE STORAGE CREDENTIAL c WITH (AWS_IAM_ROLE = 'arn')", false, true, false, true},
		{"external location", "CREATE EXTERNAL LOCATION l URL 's3://b' WITH (CREDENTIAL c)", false, true, false, true},
		{"connection", "CREATE CONNECTION c TYPE postgresql OPTIONS (host 'h')", false, true, false, true},
		{"create governed tag", "CREATE GOVERNED TAG pii DESCRIPTION 'x'", false, true, false, true},
		{"alter governed tag", "ALTER GOVERNED TAG pii SET VALUES ('a', 'b')", false, true, false, true},
		{"drop governed tag", "DROP GOVERNED TAG pii", true, true, false, true},
		{"server is a connection", "CREATE SERVER c TYPE POSTGRESQL OPTIONS (host 'db.example', port '5432')", false, true, false, true},
		{"alter server", "ALTER SERVER c OPTIONS (host 'db2')", false, true, false, true},
		{"clean room", "CREATE CLEAN ROOM r COMMENT 'x'", false, true, false, true},
		{"alter group", "ALTER GROUP g ADD USER `u`", false, true, false, true},

		// Admin needs a statement form: the word alone never sets it.
		{"grant alias in delete", "DELETE FROM t WHERE EXISTS (SELECT 1 AS grant)", true, false, false, true},
		{"grant alias", "SELECT 1 AS grant, revoke FROM t", false, false, false, true},
		{"grant in case expression", "SELECT CASE WHEN a THEN grant ELSE deny END FROM t", false, false, false, true},
		{"explain grant", "EXPLAIN GRANT SELECT ON t TO u", false, false, false, true},
		{"mask alias in ctas", "CREATE TABLE t AS SELECT a AS mask, b mask2 FROM s", false, false, false, true},
		{"mask column name", "CREATE TABLE t (mask INT, b STRING)", false, false, false, true},
		{"mask column in view list", "CREATE VIEW v (a, mask) AS SELECT 1, 2", false, false, false, true},
		{"owner to outside alter", "SELECT owner FROM t", false, false, false, true},
		{"mask after parameterised type", "CREATE TABLE t (a DECIMAL(10, 2) MASK m)", false, true, false, true},
		{"mask after identity column", "CREATE TABLE t (id BIGINT GENERATED ALWAYS AS IDENTITY, ssn STRING MASK m)", false, true, false, true},
		{"mask after generated column", "CREATE TABLE t (d DATE GENERATED ALWAYS AS (CAST(ts AS DATE)), ssn STRING MASK m)", false, true, false, true},
		{"or replace() in ctas", "CREATE TABLE t AS SELECT TRUE OR replace('a', 'a', 'b') = 'b' AS flag", false, false, false, true},
		{"or refresh column", "SELECT a OR refresh FROM t WHERE b", false, false, false, true},
		{"refresh column then where", "SELECT refresh FROM t WHERE full = 1", false, false, false, true},
		{"case expression in scripting block", "BEGIN SELECT CASE WHEN true THEN grant ELSE deny END FROM t; END", false, false, false, false},
		{"case expression in if condition", "IF CASE WHEN a THEN grant END = 1 THEN SELECT 1; END IF", false, false, false, false},
		{"scripting case statement", "CASE x WHEN 1 THEN GRANT SELECT ON t TO u; END CASE", false, true, false, true},
		{"grant after expression case in if", "IF CASE WHEN a THEN 1 END = 1 THEN GRANT SELECT ON t TO u; END IF", false, true, false, true},
		{"not atomic block grant", "BEGIN NOT ATOMIC GRANT SELECT ON TABLE t TO u; END", false, true, false, true},
		{"atomic block owner to", "BEGIN ATOMIC ALTER TABLE t OWNER TO u; END", false, true, false, true},
		{"labelled loop in block", "BEGIN l: LOOP GRANT SELECT ON t TO u; END LOOP", false, true, false, true},
		{"handler block grant", "DECLARE EXIT HANDLER FOR SQLEXCEPTION BEGIN GRANT ALL ON t TO u; END", false, true, false, true},
		{"handler statement revoke", "DECLARE CONTINUE HANDLER FOR SQLSTATE VALUE '42000', NOT FOUND REVOKE ALL ON t FROM u", false, true, false, true},
		{"handler on condition name", "DECLARE EXIT HANDLER FOR my_cond, SQLWARNING ALTER TABLE t SET TAGS ('a' = 'b')", false, true, false, true},
		{"declare variable named grant", "DECLARE grant INT DEFAULT 0", false, false, false, false},
		{"variable named begin before grant", "BEGIN DECLARE begin BOOLEAN DEFAULT TRUE; IF begin AND TRUE THEN GRANT SELECT ON TABLE t TO u; END IF; END", false, true, false, true},
		{"if on variable named begin", "IF begin AND TRUE THEN GRANT SELECT ON TABLE t TO u; END IF", false, true, false, true},
		{"loop variable named do", "WHILE do > 0 DO GRANT SELECT ON t TO u; END WHILE", false, true, false, true},
		{"table named returns", "CREATE TABLE returns (ssn STRING MASK m)", false, true, false, true},
		{"schema named as", "CREATE TABLE `as`.t (ssn STRING MASK m)", false, true, false, true},
		{"table named mask", "CREATE TABLE mask USING DELTA AS SELECT 1 AS x", false, false, false, true},
		{"view named mask", "CREATE VIEW mask AS SELECT 1 AS x", false, false, false, true},
		{"ctas subquery alias mask", "CREATE TABLE t AS (SELECT a mask FROM s)", false, false, false, true},
		{"table named column owner to", "ALTER TABLE column OWNER TO u", false, true, false, true},
		{"qualified table named column owner to", "ALTER TABLE s.column OWNER TO u", false, true, false, true},
		{"ctas case on mask column", "CREATE TABLE t AS SELECT (CASE WHEN mask THEN 1 ELSE 0 END) FROM s", false, false, false, true},
		{"labelled handler block", "BEGIN DECLARE EXIT HANDLER FOR DIVIDE_BY_ZERO h: BEGIN GRANT SELECT ON TABLE t TO u; END h; SELECT 1 / 0; END", false, true, false, true},
		{"column named values before mask", "CREATE TABLE t (values INT, ssn STRING MASK m)", false, true, false, true},
		{"table named values", "CREATE TABLE values (ssn STRING MASK m)", false, true, false, true},
		{"column named create or replace()", "SELECT t.create OR replace('a', 'a', 'b') = 'b' FROM t", false, false, false, true},
		{"rename owner column", "ALTER TABLE t RENAME COLUMN owner TO owner_id", false, false, false, false},
		{"rename nested owner field", "ALTER TABLE t RENAME COLUMN s.owner TO owner_id", false, false, false, false},
		{"quoted nested label", "BEGIN `l`: BEGIN GRANT SELECT ON TABLE t TO u; END `l`; END", false, true, false, true},
		{"quoted loop label", "BEGIN `l`: LOOP REVOKE ALL ON t FROM u; END LOOP `l`; END", false, true, false, true},
		{"variable named do in if", "BEGIN DECLARE do BOOLEAN DEFAULT TRUE; IF do THEN GRANT SELECT ON TABLE t TO u; END IF; END", false, true, false, true},
		{"variable named do in while", "WHILE do DO GRANT SELECT ON t TO u; END WHILE", false, true, false, true},
		{"for query with do column", "FOR r AS SELECT do FROM t DO GRANT SELECT ON t TO u; END FOR", false, true, false, true},
		{"variable named loop", "IF loop THEN ALTER TABLE t OWNER TO u; END IF", false, true, false, true},
		{"ctas cast with mask column", "CREATE TABLE t AS SELECT CAST(a + mask AS INT) AS x FROM s", false, false, false, true},
		{"cte ctas with mask column", "CREATE TABLE t AS WITH c AS (SELECT a mask FROM s) SELECT * FROM c", false, false, false, true},
		{"grant in scripting block", "BEGIN GRANT SELECT ON t TO u; END", false, true, false, true},
		{"labelled block revoke", "l: BEGIN REVOKE SELECT ON t FROM u; END", false, true, false, true},
		{"owner to in if", "IF x > 0 THEN ALTER TABLE t OWNER TO u; END IF", false, true, false, true},
		{"set tags in else", "ELSE ALTER TABLE t SET TAGS ('a' = 'b')", false, true, false, true},

		// Keywords in comments, strings and quoted names do not raise.
		{"line comment", "SELECT 1 -- DROP TABLE t", false, false, false, true},
		{"block comment", "SELECT /* DROP TABLE t; GRANT ALL */ 1", false, false, false, true},
		{"nested comment", "SELECT /* /* DROP */ GRANT */ 1", false, false, false, true},
		{"string", "SELECT 'DROP TABLE t; GRANT ALL ON t TO x'", false, false, false, true},
		{"double-quoted string", `SELECT "DELETE FROM t"`, false, false, false, true},
		{"escaped quote stays in string", `SELECT 'a\' DROP TABLE t --'`, false, false, false, true},
		{"doubled quote", "SELECT 'it''s DROP' FROM t", false, false, false, true},
		{"backtick names", "SELECT `delete`, `drop` FROM `grant`", false, false, false, true},
		{"doubled backtick", "SELECT `a``drop` FROM t", false, false, false, true},
		{"dollar body", "CREATE FUNCTION f() RETURNS STRING LANGUAGE PYTHON AS $$ return 'DROP TABLE t; GRANT' $$", false, false, false, true},

		// Lexer edges where a naive lexer would hide a keyword.
		{"escape ends string", `SELECT 'a\'' DROP TABLE t --'`, true, false, false, true},
		{"raw string has no escapes", `SELECT r'a\' DROP TABLE t --'`, true, false, false, true},
		{"line comment continues past backslash", "SELECT 1 -- a\\\n'\nDROP TABLE t\n--'", true, false, false, true},
		{"hint in comment does not nest", "SELECT 1 /* /*+ */ ; DROP TABLE t; /* */", true, false, false, true},
		{"hint in comment either lexer", "SELECT /* /*+ */ ' */ 1; DROP TABLE victim; -- '", true, false, false, true},
		{"hint in comment either lexer single statement", "SELECT /* /*+ */ ' */ 1 FROM t WHERE DROP -- '", true, false, false, true},
		{"quoted secret after ambiguous comment", "SELECT /* /*+ */ */ `secret`('scope', 'key')", false, false, true, false},
		{"double-quoted secret after unterminated quote", `SELECT 'oops\', "secret"(1)`, false, false, true, false},
		{"quoted http_request after ambiguous comment", "SELECT /* /*+ */ */ `http_request`(conn => 'c')", false, false, false, false},
		{"secret with comment before call after ambiguous comment", "SELECT /* /*+ */ */ secret/**/('scope', 'key')", false, false, true, false},
		{"try_secret with line comment after ambiguous comment", "SELECT /* /*+ */ */ try_secret --c\n('scope', 'key')", false, false, true, false},
		{"unclosed nested comment", "SELECT 1 /* /* */ DROP TABLE t", true, false, false, true},
		{"unterminated string", "SELECT 'x; DROP TABLE t", true, false, false, true},
		{"unterminated dollar body", "SELECT $$ x; GRANT ALL ON t TO u", false, true, false, true},
		{"tagged dollar body", "CREATE FUNCTION f() RETURNS STRING LANGUAGE PYTHON AS $py$ return 'DROP; $$ GRANT' $py$", false, false, false, true},
		{"quote in tagged dollar body", "CREATE FUNCTION f() RETURNS STRING LANGUAGE PYTHON AS $py$\n# '\nreturn 'ok'\n$py$;\nDROP TABLE victim;\n-- '", true, false, false, true},
		{"quote in tagged body then grant", "CREATE FUNCTION f() RETURNS INT LANGUAGE PYTHON AS $a1$ # ' $a1$; GRANT ALL ON t TO u -- '", false, true, false, true},
		{"quote in tagged body then secret", "CREATE FUNCTION f() RETURNS INT LANGUAGE PYTHON AS $b$ # ' $b$; SELECT secret('s', 'k') -- '", false, false, true, false},
		{"unicode tag then drop", "CREATE FUNCTION f() RETURNS STRING LANGUAGE PYTHON AS $ı$\n# '\nreturn 'ok'\n$ı$;\nDROP TABLE victim;\n-- '", true, false, false, true},
		{"unicode tag then grant", "CREATE FUNCTION f() RETURNS INT LANGUAGE PYTHON AS $ſ$ # ' $ſ$; GRANT ALL ON t TO u -- '", false, true, false, true},
		{"unicode tag then secret", "CREATE FUNCTION f() RETURNS INT LANGUAGE PYTHON AS $ü$ # ' $ü$; SELECT secret('s', 'k') -- '", false, false, true, false},
		{"unicode tag body", "CREATE FUNCTION f() RETURNS INT LANGUAGE PYTHON AS $ü$ return 'DROP' $ü$", false, false, false, true},
		{"case variant closes tag", "CREATE FUNCTION f() RETURNS INT LANGUAGE PYTHON AS $i$ # ' $ı$; DROP TABLE t; $i$", true, false, false, true},
		{"case variant overlaps close", "CREATE FUNCTION f() RETURNS INT LANGUAGE PYTHON AS $i$ x $I$i$; DROP TABLE t", true, false, false, true},
		{"unterminated tagged body", "SELECT $t$ x; DROP TABLE t", true, false, false, true},
		{"dollar without tag is punctuation", "SELECT $1 FROM t", false, false, false, true},
		{"dotless i spells I", "INSERT OVERWRıTE t SELECT 1", true, false, false, true},
		{"no-break space separates", "DROP TABLE t", true, false, false, true},
		{"comment splits words", "DROP/**/TABLE t", true, false, false, true},

		// Secrets.
		{"secret", "SELECT secret('scope', 'key')", false, false, true, true},
		{"backticked secret", "SELECT `secret`('scope', 'key')", false, false, true, true},
		{"qualified try_secret", "SELECT system.builtin.try_secret('scope', 'key')", false, false, true, true},
		{"secret in cte", "WITH s AS (SELECT secret('a', 'b') AS v) SELECT v FROM s", false, false, true, true},
		{"secret in hint", "SELECT /*+ REPARTITION(secret('a', 'b')) */ * FROM t", false, false, true, true},
		{"list secrets", "SELECT * FROM list_secrets()", false, false, true, true},
		{"secret after comment", "SELECT secret /* x */ ('a', 'b')", false, false, true, true},
		{"secret in unrecognized text", "COMMIT; SELECT secret('a', 'b')", false, false, true, false},
		{"secret in string", "SELECT 'secret(1)'", false, false, false, true},
		{"secret column", "SELECT secret FROM t", false, false, false, true},

		// Unrecognized: the caller keeps write.
		{"execute immediate", "EXECUTE IMMEDIATE 'DROP TABLE t'", false, false, false, false},
		{"call", "CALL system.p()", false, false, false, false},
		{"identifier clause", "SELECT * FROM IDENTIFIER('t')", false, false, false, false},
		{"http_request", "SELECT http_request(conn => 'c', method => 'GET', path => '/')", false, false, false, false},
		{"quoted http_request", `SELECT "http_request"(conn => 'c')`, false, false, false, false},
		{"ai_query", "SELECT ai_query('endpoint', 'hi')", false, false, false, false},
		{"ai function", "SELECT `system`.`ai`.`ai_gen`('hi')", false, false, false, false},
		{"qualified udf", "SELECT main.default.sign_value('x')", false, false, false, false},
		{"backticked qualified udf", "SELECT `main`.`default`.`f`(a) FROM t", false, false, false, false},
		{"table valued udf", "SELECT * FROM main.default.tvf(1)", false, false, false, false},
		{"udf with quoted keyword argument", "SELECT main.default.f(`from`), main.default.g(\"select\") FROM t", false, false, false, false},
		{"udtf with table argument", "SELECT * FROM main.default.udtf(TABLE(t))", false, false, false, false},
		{"udf with quoted select argument", "SELECT main.default.f(`SELECT`) FROM t", false, false, false, false},
		{"udf with doubled backtick name", "SELECT main.default.`f``g`()", false, false, false, false},
		{"create_file", "SELECT create_file('x', '/Volumes/main/default/v/file', 'overwrite')", false, false, false, false},
		{"copy_file overwrite raises", "SELECT copy_file('/Volumes/a', '/Volumes/b', overwrite => true)", true, false, false, true},
		{"try_copy_file", "SELECT try_copy_file('/Volumes/a', '/Volumes/b')", false, false, false, false},
		{"lateral view udtf", "SELECT * FROM t LATERAL VIEW app.external_udtf(c) AS x", false, false, false, false},
		{"qualified view column list", "CREATE VIEW main.default.v (a, b) AS SELECT 1, 2", false, false, false, true},
		{"udf with keyword arguments", "SELECT main.default.f(select => 1), main.default.g(with), main.default.h(from, 1)", false, false, false, false},
		{"list_files", "SELECT * FROM list_files('https://drive.google.com/drive/folders/id', connection => my_conn)", false, false, false, false},
		{"backticked to_file", "SELECT `to_file`('/Volumes/main/default/v/f')", false, false, false, false},
		{"system builtin try_to_file", "SELECT system.builtin.try_to_file('/Volumes/main/default/v/f')", false, false, false, false},
		{"reflect", "SELECT reflect('java.util.UUID', 'randomUUID')", false, false, false, false},
		{"java_method", "SELECT java_method('java.lang.System', 'getenv', 'HOME')", false, false, false, false},
		{"try_reflect", "SELECT try_reflect('java.lang.System', 'setProperty', 'k', 'v')", false, false, false, false},
		{"two-part builtin", "SELECT builtin.side_effect()", false, false, false, false},
		{"quoted two-part builtin", "SELECT `builtin`.`side_effect`()", false, false, false, false},
		{"system builtin under a catalog", "SELECT c.system.builtin.lower(a) FROM t", false, false, false, false},
		{"udf in a schema named builtin", "SELECT main.builtin.lower(a) FROM t", false, false, false, false},
		{"builtin qualified", "SELECT system.builtin.lower(a) FROM t", false, false, false, true},
		{"qualified insert column list", "INSERT INTO main.default.t (a, b) VALUES (1, 2)", false, false, false, true},
		{"qualified create column list", "CREATE TABLE IF NOT EXISTS main.default.t (a INT)", false, false, false, true},
		{"delete with opaque call", "DELETE FROM t; EXECUTE IMMEDIATE 'GRANT ALL ON t TO x'", true, false, false, true},
		{"drop with http_request", "DROP TABLE t; SELECT http_request(conn => 'c')", true, false, false, true},
		{"single raised unknown form", "OPTIMIZE t WHERE DELETE", true, false, false, true},
		{"read_files", "SELECT * FROM read_files('s3://bucket/path')", false, false, false, false},
		{"multiple statements", "SELECT 1; SELECT 2", false, false, false, false},
		{"alter outside known forms", "ALTER TABLE t ADD COLUMN c INT", false, false, false, false},
		{"refresh", "REFRESH STREAMING TABLE sales", false, false, false, false},
		{"create or refresh", "CREATE OR REFRESH STREAMING TABLE protected AS SELECT * FROM STREAM(source)", true, true, false, true},
		{"create or refresh full join", "CREATE OR REFRESH MATERIALIZED VIEW mv AS SELECT * FROM a FULL JOIN b USING (k)", true, true, false, true},
		{"repair add partitions", "MSCK REPAIR TABLE t ADD PARTITIONS", false, false, false, false},
		{"repair sync metadata", "REPAIR TABLE t SYNC METADATA", false, false, false, false},
		{"optimize", "OPTIMIZE t ZORDER BY (a)", false, false, false, false},
		{"scripting block", "BEGIN SELECT 1; END", false, false, false, false},
		{"unterminated string alone", "SELECT 'abc", false, false, false, false},
		{"empty", "", false, false, false, false},
		{"blank", " \n\t ", false, false, false, false},
		{"semicolons", ";;", false, false, false, false},
		{"comment only", "-- DROP TABLE t", false, false, false, false},

		{"very long", long, false, false, false, true},
		{"very long then drop", long + "; DROP TABLE t", true, false, false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deletes, admin, secrets, recognized := ClassifyDatabricksSQL(test.sql)
			if deletes != test.deletes || admin != test.admin || secrets != test.secrets || recognized != test.recognized {
				t.Fatalf("ClassifyDatabricksSQL() = %v, %v, %v, %v; want %v, %v, %v, %v",
					deletes, admin, secrets, recognized, test.deletes, test.admin, test.secrets, test.recognized)
			}
		})
	}
}

// Malformed input must stay linear: each unterminated opener used to rescan
// the rest of the text.
func TestClassifyDatabricksSQLMalformedIsLinear(t *testing.T) {
	for _, unit := range []string{"/*", `'\`, "$a$", "r'", "/* /*+ a.", "a."} {
		sql := strings.Repeat(unit, 1<<17) + " DROP TABLE t"
		start := time.Now()
		if deletes, _, _, _ := ClassifyDatabricksSQL(sql); !deletes {
			t.Errorf("%q x 2^17: deletes = false, want true", unit)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("%q x 2^17 took %v", unit, elapsed)
		}
	}
}
