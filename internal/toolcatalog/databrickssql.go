package toolcatalog

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ClassifyDatabricksSQL reports what a Databricks SQL text does beyond the SQL
// base tier, write, which the caller sets. It only ever adds to that tier.
//
// Each top-level statement is looked up by its leading keywords, after any
// WITH prefix, in databricksStatementTypes, and a few clauses at its top level
// add to that: INSERT OVERWRITE, INSERT … REPLACE WHERE|USING|ON and MERGE …
// THEN DELETE delete; ALTER … OWNER TO, column masks, row filters and tags are
// admin; CREATE OR REPLACE|REFRESH is both, as it drops masks and filters the
// new definition leaves out. Admin comes only from a statement
// type or one of these clauses, never from a stray keyword. The strictest
// statement wins.
//
//   - deletes, admin: what the statements do; a statement type such as DROP
//     POLICY can set both.
//   - touchesSecrets: a secret() call anywhere, recognized or not.
//   - recognized: false means nothing was proven: both flags are false and the
//     caller keeps write. A set flag is proven, and recognized is then true
//     whatever else the text holds. Otherwise it needs every statement to be
//     a listed type, the text lexed to the end, and no dynamic SQL or listed
//     function with outside effects.
//
// Callers (decided in ENG-734): the shell emits databricks/delete=true and
// databricks/admin=true for each flag set. An MCP call carries a single
// context.tool.access, so a statement with both flags reports delete there,
// and protect-databricks-administration does not see its admin side.
//
// ponytail: a statement-type table over a lexer that follows Spark's quoting,
// not a grammar. SQL scripting (BEGIN … END, IF, loops, handlers), EXECUTE
// IMMEDIATE, CALL and unlisted types are unrecognized, so a delete or admin
// change inside them stays write: only the read-only preset catches it.
// Upgrade path: a parser generated from Spark's SqlBaseParser.g4.
func ClassifyDatabricksSQL(sql string) (deletes, admin, touchesSecrets, recognized bool) {
	if len(sql) > databricksSQLMaxLen {
		return false, false, mentionsSecret(sql), false
	}
	// Spark lexers differ on a /*+ inside a comment (newer ones nest it) and
	// on "…" (a string with backslash escapes, or with ANSI double-quoted
	// identifiers a name without them). Where the text can read either way,
	// every reading is classified and the strictest wins.
	known := true
	for _, hintNests := range []bool{false, true} {
		for _, dqIdentifiers := range []bool{false, true} {
			if hintNests && !strings.Contains(sql, "/*+") ||
				dqIdentifiers && !(strings.Contains(sql, `"`) && strings.Contains(sql, `\`)) {
				continue
			}
			d, a, secrets, k := classifyDatabricksTokens(lexDatabricksSQL(sql, hintNests, dqIdentifiers))
			deletes, admin, touchesSecrets, known = deletes || d, admin || a, touchesSecrets || secrets, known && k
		}
	}
	return deletes, admin, touchesSecrets, deletes || admin || known
}

func classifyDatabricksTokens(tokens []sqlToken, complete bool) (deletes, admin, touchesSecrets, known bool) {
	statements := 0
	known = complete
	for len(tokens) > 0 {
		end := len(tokens)
		for i, tok := range tokens {
			if tok.is(";") {
				end = i
				break
			}
		}
		stmt := tokens[:end]
		tokens = tokens[min(end+1, len(tokens)):]
		if len(stmt) == 0 {
			continue
		}
		statements++
		effect, secrets, stmtKnown := classifyDatabricksStatement(stmt)
		deletes = deletes || effect&sqlDeletes != 0
		admin = admin || effect&sqlAdmin != 0
		touchesSecrets = touchesSecrets || secrets
		known = known && stmtKnown
	}
	return deletes, admin, touchesSecrets, known && statements > 0
}

// ponytail: text over 64 KiB is unrecognized unread, so the caller keeps write
// and a hostile statement cannot hold a PreToolUse hook past its ~1s budget.
// touchesSecrets fails closed there: any "secret" in the text sets it. A delete
// or admin change past the cap stays write, like other unrecognized SQL.
// Classification is linear below it; raise the cap if real statements hit it.
const databricksSQLMaxLen = 64 << 10

// mentionsSecret reports whether s contains "secret" in any ASCII case.
func mentionsSecret(s string) bool {
	for i := 0; i+len("secret") <= len(s); i++ {
		if strings.EqualFold(s[i:i+len("secret")], "secret") {
			return true
		}
	}
	return false
}

const (
	sqlDeletes = 1 << iota
	sqlAdmin
	sqlBoth = sqlDeletes | sqlAdmin
)

// databricksStatementTypes maps a statement's leading keywords to what it does
// beyond write, from the statement list of the Databricks SQL language
// reference (https://learn.microsoft.com/azure/databricks/sql/language-manual).
// The longest listed prefix wins; a statement with none is unrecognized.
var databricksStatementTypes = map[string]int{
	// Queries, DML and auxiliary statements: write.
	"SELECT": 0, "VALUES": 0, "FROM": 0, "TABLE": 0, "EXPLAIN": 0, "INSERT": 0, "UPDATE": 0, "MERGE": 0,
	"COPY INTO": 0, "LOAD DATA": 0, "PUT": 0, "GET": 0, "LIST": 0, "SHOW": 0, "DESCRIBE": 0, "DESC": 0,
	"USE": 0, "SET": 0, "RESET": 0, "DECLARE": 0, "ANALYZE": 0, "CACHE": 0, "UNCACHE": 0, "CLEAR CACHE": 0,
	"REFRESH": 0, "OPTIMIZE": 0, "REORG": 0, "CONVERT TO": 0, "GENERATE": 0, "UNDROP": 0, "SYNC": 0,
	"COMMENT ON": 0, "MSCK REPAIR": 0, "REPAIR": 0,
	"CREATE TABLE": 0, "CREATE EXTERNAL TABLE": 0, "CREATE VIEW": 0, "CREATE MATERIALIZED VIEW": 0,
	"CREATE STREAMING TABLE": 0, "CREATE LIVE TABLE": 0, "CREATE SCHEMA": 0, "CREATE DATABASE": 0,
	"CREATE CATALOG": 0, "CREATE FOREIGN CATALOG": 0, "CREATE FUNCTION": 0, "CREATE VOLUME": 0,
	"CREATE EXTERNAL VOLUME": 0, "CREATE BLOOMFILTER INDEX": 0,
	"ALTER TABLE": 0, "ALTER VIEW": 0, "ALTER MATERIALIZED VIEW": 0, "ALTER STREAMING TABLE": 0,
	"ALTER SCHEMA": 0, "ALTER DATABASE": 0, "ALTER CATALOG": 0, "ALTER VOLUME": 0,

	// Deletes.
	"DELETE": sqlDeletes, "TRUNCATE": sqlDeletes, "VACUUM": sqlDeletes, "RESTORE": sqlDeletes,
	"FSCK": sqlDeletes, "REMOVE": sqlDeletes, "DROP": sqlDeletes,

	// Administration: privileges, access policies, governed tags, credentials,
	// connections, external locations, Delta Sharing, clean rooms and groups.
	"GRANT": sqlAdmin, "REVOKE": sqlAdmin, "DENY": sqlAdmin, "SET TAG": sqlAdmin, "UNSET TAG": sqlAdmin,
	"CREATE POLICY": sqlAdmin, "ALTER POLICY": sqlAdmin, "DROP POLICY": sqlBoth,
	"CREATE GOVERNED TAG": sqlAdmin, "ALTER GOVERNED TAG": sqlAdmin, "DROP GOVERNED TAG": sqlBoth,
	"CREATE CREDENTIAL": sqlAdmin, "ALTER CREDENTIAL": sqlAdmin, "DROP CREDENTIAL": sqlBoth,
	"CREATE STORAGE CREDENTIAL": sqlAdmin, "ALTER STORAGE CREDENTIAL": sqlAdmin, "DROP STORAGE CREDENTIAL": sqlBoth,
	"CREATE SERVICE CREDENTIAL": sqlAdmin, "ALTER SERVICE CREDENTIAL": sqlAdmin, "DROP SERVICE CREDENTIAL": sqlBoth,
	"CREATE CONNECTION": sqlAdmin, "ALTER CONNECTION": sqlAdmin, "DROP CONNECTION": sqlBoth,
	"CREATE SERVER": sqlAdmin, "ALTER SERVER": sqlAdmin, "DROP SERVER": sqlBoth,
	"CREATE EXTERNAL LOCATION": sqlAdmin, "ALTER EXTERNAL LOCATION": sqlAdmin, "DROP EXTERNAL LOCATION": sqlBoth,
	"CREATE SHARE": sqlAdmin, "ALTER SHARE": sqlAdmin, "DROP SHARE": sqlBoth,
	"CREATE RECIPIENT": sqlAdmin, "ALTER RECIPIENT": sqlAdmin, "DROP RECIPIENT": sqlBoth,
	"CREATE PROVIDER": sqlAdmin, "ALTER PROVIDER": sqlAdmin, "DROP PROVIDER": sqlBoth,
	"CREATE CLEAN ROOM": sqlAdmin, "ALTER CLEAN ROOM": sqlAdmin, "DROP CLEAN ROOM": sqlBoth,
	"CREATE GROUP": sqlAdmin, "ALTER GROUP": sqlAdmin, "DROP GROUP": sqlBoth, "ALTER METASTORE": sqlAdmin,
}

// Words skipped when reading a statement's type: CREATE OR REPLACE TEMPORARY
// VIEW IF NOT EXISTS is a CREATE VIEW.
var databricksTypeModifiers = setOf("OR", "REPLACE", "REFRESH", "TEMPORARY", "TEMP", "GLOBAL", "IF", "NOT", "EXISTS")

var databricksSecretFunctions = setOf("SECRET", "TRY_SECRET", "LIST_SECRETS")

// Functions that reach outside the warehouse, read or write files, run Java
// or name objects at run time. Every AI_ function calls a model endpoint and
// counts too.
var databricksOpaqueFunctions = setOf("HTTP_REQUEST", "READ_FILES", "READ_KAFKA", "READ_KINESIS",
	"READ_PUBSUB", "READ_PULSAR", "REMOTE_QUERY", "VECTOR_SEARCH", "CLOUD_FILES", "IDENTIFIER",
	"CREATE_FILE", "COPY_FILE", "TRY_COPY_FILE", "LIST_FILES", "TO_FILE", "TRY_TO_FILE",
	"READ_STATESTORE", "READ_STATE_METADATA", "CLOUD_FILES_STATE", "REFLECT", "JAVA_METHOD", "TRY_REFLECT")

// databricksMaskIsName reports whether a MASK after prev is a name (a column,
// alias, table or field) rather than a mask clause. Whatever follows MASK may
// be a function with any name, keywords included.
func databricksMaskIsName(verb string, prev, beforePrev sqlToken) bool {
	keyword := func(t sqlToken, words ...string) bool {
		return t.kind == sqlWord && setOf(words...)[t.text]
	}
	if verb == "ALTER" && keyword(beforePrev, "AFTER") || beforePrev.is(":") { // AFTER other MASK f, :param MASK f
		return false
	}
	return prev.is("(") || prev.is(",") || prev.is(".") || keyword(prev, "AS", "FROM", "JOIN") ||
		keyword(prev, "TABLE", "VIEW") && keyword(beforePrev, "CREATE", "ALTER", "REPLACE", "TEMPORARY", "TEMP",
			"GLOBAL", "MATERIALIZED", "STREAMING", "EXTERNAL", "LIVE") ||
		keyword(prev, "EXISTS") && keyword(beforePrev, "NOT") ||
		keyword(prev, "COLUMN", "COLUMNS", "CONSTRAINT") && keyword(beforePrev, "ADD", "ALTER", "DROP", "RENAME")
}

func classifyDatabricksStatement(stmt []sqlToken) (effect int, secrets, known bool) {
	at := func(i int) sqlToken {
		if i < 0 || i >= len(stmt) {
			return sqlToken{}
		}
		return stmt[i]
	}
	opaque := false
	for i, tok := range stmt {
		// After malformed input a comment may sit between a name and its (,
		// so a listed name counts as called wherever it appears.
		if (at(i+1).is("(") || tok.loose) && (tok.kind == sqlWord || tok.kind == sqlName) {
			name := tok.text[strings.LastIndexByte(tok.text, '.')+1:]
			switch {
			case databricksSecretFunctions[name]:
				secrets = true
			case databricksOpaqueFunctions[name] || strings.HasPrefix(name, "AI_"):
				opaque = true
			}
		}
		if tok.is("EXECUTE") || tok.is("CALL") {
			opaque = true
		}
	}

	start := databricksStatementStart(stmt)
	var words []string
	for i := start; i < len(stmt) && len(words) < 3; i++ {
		if stmt[i].kind == sqlPunct && stmt[i].loose {
			continue // what may be a comment, read as code after malformed input
		}
		if stmt[i].kind != sqlWord {
			break
		}
		if len(words) == 0 || !databricksTypeModifiers[stmt[i].text] {
			words = append(words, stmt[i].text)
		}
	}
	typ := ""
	for n := len(words); n > 0 && typ == ""; n-- {
		if _, ok := databricksStatementTypes[strings.Join(words[:n], " ")]; ok {
			typ = strings.Join(words[:n], " ")
		}
	}
	if typ == "" {
		return 0, secrets, false
	}
	effect = databricksStatementTypes[typ]
	verb := words[0]

	// Clauses at the statement's top level, and column masks at any depth.
	depth, query := 0, false
	takesQuery := verb == "CREATE" || typ == "ALTER VIEW" || typ == "ALTER MATERIALIZED VIEW"
	insert := verb == "INSERT" || verb == "FROM" // FROM s INSERT … is a multi-insert
	for i := start; i < len(stmt); i++ {
		tok, prev, next := stmt[i], at(i-1), at(i+1)
		switch {
		case tok.is("("):
			depth++
		case tok.is(")"):
			depth--
		}
		if tok.kind != sqlWord {
			continue
		}
		// The AS that starts a CREATE's or ALTER VIEW's query; column masks
		// all come before it. Not a name (CREATE TABLE as) or GENERATED … AS.
		// ponytail: a column named mask in a CHECK (…) or a STRUCT<…> reads
		// as a mask, which only over-flags admin.
		query = query || takesQuery && depth == 0 && tok.is("AS") && !next.is(".") && !prev.is(":") &&
			!(prev.kind == sqlWord && setOf("TABLE", "VIEW", "EXISTS", "ALWAYS", "DEFAULT", "AFTER")[prev.text]) && !prev.is(".")
		if depth == 0 {
			switch {
			case verb == "CREATE" && i == start+2 && prev.is("OR") && (tok.is("REPLACE") || tok.is("REFRESH")):
				// Replacing a definition drops any mask or filter it leaves out.
				effect |= sqlBoth
			case insert && tok.is("OVERWRITE") && (prev.is("INSERT") || prev.is("EVOLUTION") && at(i-3).is("WITH") && at(i-4).is("INSERT")),
				(verb == "LOAD" || verb == "PUT") && tok.is("OVERWRITE"),
				insert && tok.is("REPLACE") && (next.is("WHERE") || next.is("USING") || next.is("ON")),
				verb == "MERGE" && tok.is("DELETE") && prev.is("THEN"),
				verb == "ALTER" && (tok.is("DROP") || tok.is("REPLACE") && next.is("COLUMNS")),
				verb == "REFRESH" && (tok.is("FULL") || tok.is("WHERE")),
				(verb == "MSCK" || verb == "REPAIR") && (tok.is("SYNC") || tok.is("DROP")) && next.is("PARTITIONS"):
				effect |= sqlDeletes
			case verb == "ALTER" && tok.is("TO") && prev.is("OWNER") && !databricksRenamesColumn(stmt, i-1),
				verb == "ALTER" && tok.is("MASK") && (prev.is("SET") || prev.is("DROP")),
				verb == "ALTER" && tok.is("FILTER") && prev.is("ROW") && (at(i-2).is("SET") || at(i-2).is("DROP")),
				verb == "ALTER" && (tok.is("TAGS") || tok.is("TAG")) && (prev.is("SET") || prev.is("UNSET")),
				verb == "CREATE" && tok.is("FILTER") && prev.is("ROW") && at(i-2).is("WITH"),
				(verb == "MSCK" || verb == "REPAIR") && tok.is("PRIVILEGES"):
				effect |= sqlAdmin
			case verb == "DECLARE" && (tok.is("HANDLER") || tok.is("CONDITION")):
				opaque = true // SQL scripting, not a session variable
			}
		}
		if verb == "REORG" && tok.is("PURGE") { // REORG TABLE … APPLY (PURGE)
			effect |= sqlDeletes
		}
		// A column mask in a column definition: CREATE … (c t MASK f) or
		// ALTER … ADD [COLUMN] c t MASK f, unless MASK is itself a name.
		// ponytail: a STRUCT<mask …> field or a CTAS alias without AS reads as
		// a mask too, which only over-flags admin.
		if (verb == "CREATE" || verb == "ALTER") && !query && tok.is("MASK") &&
			(next.kind == sqlWord || next.kind == sqlName) && !databricksMaskIsName(verb, prev, at(i-2)) {
			effect |= sqlAdmin
		}
	}
	return effect, secrets, !opaque
}

// databricksStatementStart returns where the statement proper begins: past
// any leading parentheses and one WITH [RECURSIVE] name … AS (query), …
// prefix. In Databricks a CTE body is a query, never a write.
func databricksStatementStart(stmt []sqlToken) int {
	at := func(i int) sqlToken {
		if i < len(stmt) {
			return stmt[i]
		}
		return sqlToken{}
	}
	skipGroup := func(i int) int { // past the parenthesised group at i
		for depth := 0; i < len(stmt); i++ {
			if stmt[i].is("(") {
				depth++
			} else if stmt[i].is(")") {
				if depth--; depth == 0 {
					return i + 1
				}
			}
		}
		return i
	}
	i := 0
	for at(i).is("(") || at(i).kind == sqlPunct && at(i).loose {
		i++
	}
	if !at(i).is("WITH") {
		return i
	}
	i++
	if at(i).is("RECURSIVE") {
		i++
	}
	for i < len(stmt) {
		// The CTE name, any column list or MAX RECURSION LEVEL n, an optional
		// AS, then the body: a group not followed by AS, MAX or another group.
		for i++; i < len(stmt); {
			if at(i).is("(") {
				i = skipGroup(i)
				if !at(i).is("AS") && !at(i).is("MAX") && !at(i).is("(") {
					break
				}
			} else if at(i).is("AS") {
				i++
				if at(i).is("(") {
					i = skipGroup(i)
					break
				}
			} else {
				i++
			}
		}
		if !at(i).is(",") {
			break
		}
		i++
	}
	for at(i).is("(") {
		i++
	}
	return i
}

// databricksRenamesColumn reports whether the OWNER at i is the column of a
// RENAME COLUMN [a.]owner TO …, not an ownership change.
func databricksRenamesColumn(stmt []sqlToken, i int) bool {
	for i >= 2 && stmt[i-1].is(".") {
		i -= 2
	}
	return i >= 2 && stmt[i-1].is("COLUMN") && stmt[i-2].is("RENAME")
}

const (
	sqlWord   = iota + 1 // unquoted word, upper-cased: a keyword or a name
	sqlName              // backtick or double-quoted, upper-cased: never a keyword
	sqlString            // single-quoted, raw or dollar-quoted literal: content dropped
	sqlPunct
)

type sqlToken struct {
	kind  int
	text  string
	loose bool // lexed as plain code after malformed input
}

func (t sqlToken) is(text string) bool {
	return (t.kind == sqlWord || t.kind == sqlPunct) && t.text == text
}

// lexDatabricksSQL splits sql the way Spark's SqlBaseLexer does, dropping
// comments and literal content. complete is false when a quote, comment or
// dollar body never closes; the lexer then reads the rest as plain code, with
// no quotes or comments, so nothing after the opener can hide a keyword or a
// call and the scan stays linear.
func lexDatabricksSQL(sql string, hintNests, dqIdentifiers bool) (tokens []sqlToken, complete bool) {
	complete = true
	for i := 0; i < len(sql); {
		rest := sql[i:]
		r, size := utf8.DecodeRuneInString(rest)
		switch {
		case !complete:
			if isSQLWordRune(r) {
				j := sqlWordEnd(rest)
				tokens = append(tokens, sqlToken{kind: sqlWord, text: strings.ToUpper(rest[:j]), loose: true})
				i += j
			} else {
				// Quotes split words but leave no token, so a quoted
				// `secret`( still reads as a call.
				if r < utf8.RuneSelf && !unicode.IsSpace(r) && !strings.ContainsRune("'\"`", r) {
					tokens = append(tokens, sqlToken{kind: sqlPunct, text: rest[:1], loose: true})
				}
				i += size
			}
		case strings.HasPrefix(rest, "--"):
			i += 2
			for i < len(sql) && sql[i] != '\n' && sql[i] != '\r' {
				if strings.HasPrefix(sql[i:], "\\\n") { // Spark runs the comment on past a backslash-newline.
					i++
				}
				i++
			}
		case strings.HasPrefix(rest, "/*+"):
			i += 3 // A hint is parsed, not ignored: read its body as code.
		case strings.HasPrefix(rest, "/*"):
			end := sqlCommentEnd(rest, hintNests)
			if end < 0 {
				complete = false
				continue
			}
			i += end
		case r == '\'' || r == '"' || r == '`':
			end := sqlQuoteEnd(rest, r == '\'' || r == '"' && !dqIdentifiers)
			if end < 0 {
				complete = false
				continue
			}
			if r == '\'' {
				tokens = append(tokens, sqlToken{kind: sqlString})
			} else {
				q := rest[:1]
				tokens = append(tokens, sqlToken{kind: sqlName, text: strings.ToUpper(strings.ReplaceAll(rest[1:end-1], q+q, q))})
			}
			i += end
		case sqlDollarTag(rest) != "":
			tag := sqlDollarTag(rest)
			end := strings.Index(rest[len(tag):], tag)
			// Spark matches the closing tag on upper-cased characters. If that
			// could close the body anywhere else, read the rest as code.
			if end < 0 || !sqlSameClose(rest[len(tag):len(tag)+end], tag) {
				complete = false
				continue
			}
			tokens = append(tokens, sqlToken{kind: sqlString})
			i += len(tag) + end + len(tag)
		case isSQLWordRune(r):
			j := i + sqlWordEnd(rest)
			word := sql[i:j]
			if (word == "r" || word == "R") && j < len(sql) && (sql[j] == '\'' || sql[j] == '"') {
				// A raw literal: a backslash escapes nothing.
				end := strings.IndexByte(sql[j+1:], sql[j])
				if end < 0 {
					complete = false
					continue
				}
				tokens = append(tokens, sqlToken{kind: sqlString})
				i = j + 1 + end + 1
				continue
			}
			// Spark upper-cases each character to match keywords, so ı and ſ
			// spell I and S; strings.ToUpper folds the same way.
			tokens = append(tokens, sqlToken{kind: sqlWord, text: strings.ToUpper(word)})
			i = j
		case r < utf8.RuneSelf && !unicode.IsSpace(r):
			tokens = append(tokens, sqlToken{kind: sqlPunct, text: rest[:1]})
			i++
		default: // whitespace, and any other character splits words
			i += size
		}
	}
	return tokens, complete
}

// isSQLWordRune is narrower than Spark's identifier characters, which only
// splits words more finely: a keyword is never hidden inside a longer word.
func isSQLWordRune(r rune) bool {
	return r == '_' || r != utf8.RuneError && (unicode.IsLetter(r) || unicode.IsDigit(r))
}

func sqlWordEnd(s string) int {
	for i, r := range s {
		if !isSQLWordRune(r) {
			return i
		}
	}
	return len(s)
}

// sqlDollarTag returns the $$ or $tag$ that opens a dollar-quoted body at the
// start of s, or "". It takes any word as a tag: outside a body, Spark SQL has
// no other use for $, so a wider tag only reads a statement Spark rejects.
func sqlDollarTag(s string) string {
	if !strings.HasPrefix(s, "$") {
		return ""
	}
	end := 1 + sqlWordEnd(s[1:])
	if end < len(s) && s[end] == '$' {
		return s[:end+1]
	}
	return ""
}

// sqlSameClose reports whether no upper-cased variant of tag appears in body
// or overlaps its exact closing tag, so either matching rule closes it there.
func sqlSameClose(body, tag string) bool {
	upper := strings.ToUpper(body)
	return strings.Index(strings.ToUpper(body+tag), strings.ToUpper(tag)) == len(upper)
}

// sqlCommentEnd returns the length of the nested /* */ comment that starts s,
// or -1 if it never closes. A /*+ inside a comment nests only if hintNests,
// as in newer Spark lexers; older ones read it as plain characters.
func sqlCommentEnd(s string, hintNests bool) int {
	depth := 0
	for i := 0; i < len(s); {
		switch {
		case depth > 0 && !hintNests && strings.HasPrefix(s[i:], "/*+"):
			i++
		case strings.HasPrefix(s[i:], "/*"):
			depth++
			i += 2
		case strings.HasPrefix(s[i:], "*/"):
			depth--
			i += 2
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return -1
}

// sqlQuoteEnd returns the length of the quoted token that starts s, or -1 if
// it never closes. A doubled quote is an escaped quote.
func sqlQuoteEnd(s string, backslashEscapes bool) int {
	for i := 1; i < len(s); i++ {
		switch {
		case backslashEscapes && s[i] == '\\', s[i] == s[0] && i+1 < len(s) && s[i+1] == s[0]:
			i++
		case s[i] == s[0]:
			return i + 1
		}
	}
	return -1
}

func setOf(words ...string) map[string]bool {
	set := make(map[string]bool, len(words))
	for _, word := range words {
		set[word] = true
	}
	return set
}
