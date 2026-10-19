package toolcatalog

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ClassifyDatabricksSQL reports what a Databricks SQL text does beyond the SQL
// base tier, write, which the caller sets. It only ever adds to that tier.
//
//   - deletes: a delete form in any statement (DROP, DELETE, TRUNCATE, INSERT
//     OVERWRITE, REPLACE WHERE|USING|ON, VACUUM, RESTORE, MERGE … DELETE, …),
//     found wherever it sits, CTEs and subqueries included.
//   - admin: an administrative statement form (GRANT, REVOKE, DENY, ALTER …
//     OWNER TO, tags, column masks, row filters, policies, credentials,
//     connections, shares, groups, …). Only a recognized form sets it; the
//     same word as an alias, identifier or string never does.
//   - Both: CREATE OR REPLACE and CREATE OR REFRESH, which replace data and
//     drop any mask or filter the new definition leaves out, and DROP POLICY.
//   - touchesSecrets: a secret() call anywhere, recognized or not.
//   - recognized: false means nothing was proven: both flags are false and the
//     caller keeps write. A set flag is proven, and recognized is then true
//     whatever else the text holds. Otherwise it is true only for one
//     statement of a known write form, lexed to the end, that runs no dynamic
//     SQL, no user-defined function and no function with outside effects.
//
// Callers (decided in ENG-734): the shell emits databricks/delete=true and
// databricks/admin=true for each flag set. An MCP call carries a single
// context.tool.access, so a statement with both flags reports delete there,
// and protect-databricks-administration does not see its admin side.
//
// ponytail: a keyword scan over a lexer that follows Spark's, not a grammar.
// A false positive only adds a flag, and admin needs a statement form, not a
// word. A user-defined function called by its bare name reads as a built-in.
// Upgrade path: a parser generated from Spark's SqlBaseParser.g4 and the
// function catalog, if the scan ever needs to prove less.
func ClassifyDatabricksSQL(sql string) (deletes, admin, touchesSecrets, recognized bool) {
	tokens, complete := lexDatabricksSQL(sql)
	statements, known := 0, complete
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
		d, a, secrets, stmtKnown := classifyDatabricksStatement(stmt)
		deletes, admin = deletes || d, admin || a
		touchesSecrets = touchesSecrets || secrets
		known = known && stmtKnown
	}
	return deletes, admin, touchesSecrets, deletes || admin || known && statements == 1
}

// Statement forms that stay at write when nothing else is found.
var databricksWriteForms = setOf("SELECT", "WITH", "VALUES", "SHOW", "DESCRIBE", "DESC", "EXPLAIN",
	"INSERT", "UPDATE", "MERGE", "CREATE", "COPY", "SET", "USE")

// SQL scripting: a statement headed by a script form holds statements of its
// own. One starts after a block word (or a label after one), outside any CASE
// expression, and only with a statement keyword, so a variable named do or
// begin opens nothing. The conditions of DECLARE … HANDLER FOR end one too.
var (
	databricksScriptForms = setOf("BEGIN", "IF", "ELSEIF", "ELSE", "CASE", "WHEN", "FOR", "WHILE", "LOOP",
		"REPEAT", "DECLARE")
	databricksBlockWords = setOf("BEGIN", "ATOMIC", "THEN", "ELSE", "DO", "LOOP", "REPEAT")
	databricksStatements = setOf("SELECT", "WITH", "VALUES", "INSERT", "UPDATE", "DELETE", "MERGE", "COPY",
		"CREATE", "ALTER", "DROP", "TRUNCATE", "VACUUM", "RESTORE", "REFRESH", "MSCK", "REPAIR", "OPTIMIZE",
		"GRANT", "REVOKE", "DENY", "SET", "UNSET", "USE", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "COMMENT",
		"CALL", "EXECUTE", "DECLARE", "BEGIN", "IF", "CASE", "FOR", "WHILE", "LOOP", "REPEAT", "ITERATE",
		"LEAVE", "RETURN", "SIGNAL", "RESIGNAL")
)

// A qualified name before ( is a call unless a table keyword precedes it: a
// column list. A qualified column before a subquery reads as a call too.
var databricksTableKeywords = setOf("INTO", "TABLE", "VIEW", "FUNCTION", "EXISTS")

// Objects whose CREATE, ALTER or DROP is administration: access policies,
// governed tags, credentials, connections, external locations, Delta Sharing,
// clean rooms and workspace groups.
var databricksAdminObjects = setOf("POLICY", "TAG", "CREDENTIAL", "CONNECTION", "SERVER", "LOCATION",
	"SHARE", "CLEAN", "RECIPIENT", "PROVIDER", "GROUP", "METASTORE")

// Words between CREATE, ALTER or DROP and the object kind.
var databricksObjectModifiers = setOf("OR", "REPLACE", "IF", "NOT", "EXISTS", "TEMPORARY", "TEMP",
	"GLOBAL", "EXTERNAL", "STORAGE", "SERVICE", "GOVERNED")

// Words a column or constraint name follows: a MASK after them is that name.
var databricksBeforeColumnName = setOf("COLUMN", "COLUMNS", "CONSTRAINT", "AS")

var databricksSecretFunctions = setOf("SECRET", "TRY_SECRET", "LIST_SECRETS")

// Functions that reach outside the warehouse, read or write files, run Java
// or name objects at run time. Every AI_ function calls a model endpoint and
// counts too.
var databricksOpaqueFunctions = setOf("HTTP_REQUEST", "READ_FILES", "READ_KAFKA", "READ_KINESIS",
	"READ_PUBSUB", "READ_PULSAR", "REMOTE_QUERY", "VECTOR_SEARCH", "CLOUD_FILES", "IDENTIFIER",
	"CREATE_FILE", "COPY_FILE", "TRY_COPY_FILE", "LIST_FILES", "TO_FILE", "TRY_TO_FILE",
	"READ_STATESTORE", "READ_STATE_METADATA", "CLOUD_FILES_STATE", "REFLECT", "JAVA_METHOD", "TRY_REFLECT")

func classifyDatabricksStatement(stmt []sqlToken) (deletes, admin, secrets, known bool) {
	at := func(i int) sqlToken {
		if i < 0 || i >= len(stmt) {
			return sqlToken{}
		}
		return stmt[i]
	}
	first := 0
	for first < len(stmt)-1 && stmt[first].is("(") {
		first++
	}
	// a scripting label, not a parameter marker as in SELECT :id
	if at(first+1).is(":") && !databricksStatements[at(first).text] && databricksScriptForms[at(first+2).text] {
		first += 2
	}
	// head is the form of the statement being read: the first word, or in a
	// scripting block the statement keyword that opens a nested statement.
	head, headAt, opaque, refresh, repair, adding := "", -1, false, false, false, false
	depth, caseDepth, handlerStart := 0, 0, -1
	columns, grouped, angle := false, false, 0 // inside column definitions; STRUCT<…> depth
	// whenNext[i]: the next WHEN or THEN after i is a WHEN. A CASE opens an
	// expression only then; IF case THEN reads a variable named case.
	whenNext, when := make([]bool, len(stmt)), false
	for i := len(stmt) - 1; i >= 0; i-- {
		whenNext[i] = when
		if stmt[i].is("WHEN") || stmt[i].is("THEN") {
			when = stmt[i].is("WHEN")
		}
	}
	for i, tok := range stmt {
		prev, next := at(i-1), at(i+1)
		block := prev // the word before this one, past any label
		if prev.is(":") && (at(i-2).kind == sqlWord || at(i-2).kind == sqlName) {
			block = at(i - 3)
		}
		atHead := tok.kind == sqlWord && (i == first || i == handlerStart ||
			databricksScriptForms[head] && caseDepth == 0 && databricksStatements[tok.text] &&
				block.kind == sqlWord && databricksBlockWords[block.text])
		if atHead {
			head, headAt, depth, columns, grouped, adding, angle = tok.text, i, 0, false, false, false, 0
		}
		if depth == 0 && tok.is("AS") && !prev.is(".") && !next.is(".") {
			grouped = true // a CREATE's query follows AS: no column definitions after it
		}
		switch {
		case tok.is("("):
			// A CREATE's column definitions are its first top-level group.
			columns = columns || depth == 0 && head == "CREATE" && !grouped
			grouped = grouped || depth == 0
			depth++
		case tok.is(")"):
			depth--
			columns = columns && depth > 0
		case tok.is("<") && (prev.is("STRUCT") || prev.is("ARRAY") || prev.is("MAP")):
			angle++
		case tok.is(">") && angle > 0:
			angle--
		case tok.is("CASE") && !atHead && whenNext[i]:
			caseDepth++
		case tok.is("END") && caseDepth > 0:
			caseDepth--
		}
		// After malformed input a comment may sit between a name and its (,
		// so a listed name counts as called wherever it appears.
		if (next.is("(") || tok.loose) && (tok.kind == sqlWord || tok.kind == sqlName) {
			name := tok.text[strings.LastIndexByte(tok.text, '.')+1:]
			switch {
			case databricksSecretFunctions[name]:
				secrets = true
			case databricksOpaqueFunctions[name] || strings.HasPrefix(name, "AI_"):
				opaque = true
			}
			builtin := at(i-2).text == "BUILTIN" && at(i-3).is(".") && at(i-4).text == "SYSTEM" && !at(i-5).is(".")
			if next.is("(") && prev.is(".") && !builtin {
				start := i - 2 // a qualified call is a user-defined function
				for at(start - 1).is(".") {
					start -= 2
				}
				columnList := at(start-1).kind == sqlWord && databricksTableKeywords[at(start-1).text] &&
					!(at(start-1).text == "VIEW" && at(start-2).is("LATERAL"))
				if !columnList {
					opaque = true
				}
			}
		}
		if tok.kind != sqlWord {
			continue
		}
		ddl := head == "ALTER" || head == "CREATE"
		switch tok.text {
		case "GRANT", "REVOKE", "DENY":
			admin = admin || atHead
		case "DELETE", "TRUNCATE", "OVERWRITE", "VACUUM", "RESTORE", "PURGE", "REMOVE":
			deletes = true
		case "REPLACE": // CREATE OR REPLACE, INSERT … REPLACE WHERE|USING|ON; not replace()
			if !next.is("(") {
				deletes = true
			}
			// CREATE OR REPLACE drops any mask or filter the new definition
			// leaves out.
			admin = admin || prev.is("OR") && head == "CREATE" && headAt == i-2
		case "REFRESH":
			if prev.is("OR") && head == "CREATE" && headAt == i-2 { // as CREATE OR REPLACE
				deletes, admin = true, true
			}
			refresh = refresh || atHead
		case "ADD": // ALTER TABLE … ADD COLUMN(S) may define a column mask
			adding = adding || head == "ALTER" && depth == 0
		case "MASK": // SET|DROP MASK, or a column mask in a column definition
			nameNext := next.kind == sqlWord || next.kind == sqlName
			definesColumn := nameNext && !prev.is("(") && !prev.is(",") && !databricksBeforeColumnName[prev.text]
			definesColumn = definesColumn && angle == 0 // not a STRUCT field named mask
			admin = admin || head == "ALTER" && (prev.is("SET") || prev.is("DROP")) ||
				columns && depth == 1 && definesColumn || adding && definesColumn
		case "FILTER": // SET|DROP|WITH ROW FILTER
			admin = admin || ddl && prev.is("ROW") && (at(i-2).is("SET") || at(i-2).is("DROP") || at(i-2).is("WITH"))
		case "TO":
			if head == "ALTER" && prev.is("OWNER") {
				start := i - 1 // not RENAME COLUMN [a.]owner TO …
				for at(start - 1).is(".") {
					start -= 2
				}
				admin = admin || !(at(start-1).is("COLUMN") && at(start-2).is("RENAME"))
			}
		case "TAG", "TAGS": // ALTER … SET|UNSET TAGS, SET|UNSET TAG ON
			admin = admin || (head == "ALTER" || head == "SET" || head == "UNSET") && (prev.is("SET") || prev.is("UNSET"))
		case "FULL", "WHERE": // REFRESH … FULL truncates; REFRESH … WHERE deletes the rows it matches
			deletes = deletes || refresh
		case "REPAIR":
			repair = repair || atHead || prev.is("MSCK")
		case "PRIVILEGES": // MSCK REPAIR … PRIVILEGES revokes grants
			admin = admin || repair && (head == "MSCK" || head == "REPAIR")
		case "SYNC": // MSCK REPAIR TABLE … SYNC PARTITIONS drops stale partitions
			deletes = deletes || repair && next.is("PARTITIONS")
		case "FOR": // DECLARE … HANDLER FOR conditions, then the handler's statement
			if prev.is("HANDLER") && head == "DECLARE" {
				j := i + 1
				for {
					switch {
					case at(j).is("NOT") && at(j+1).is("FOUND"):
						j += 2
					case at(j).is("SQLSTATE") && at(j+1).is("VALUE"):
						j += 3
					case at(j).is("SQLSTATE"):
						j += 2
					default: // SQLEXCEPTION, SQLWARNING or a condition name, maybe dotted
						j++
						for at(j).is(".") {
							j += 2
						}
					}
					if !at(j).is(",") {
						break
					}
					j++
				}
				if at(j + 1).is(":") { // a labelled handler block
					j += 2
				}
				handlerStart = j
			}
		case "EXECUTE", "CALL":
			opaque = true
		case "CREATE", "ALTER", "DROP":
			deletes = deletes || tok.text == "DROP"
			if atHead {
				j := i + 1
				for at(j).kind == sqlWord && databricksObjectModifiers[at(j).text] {
					j++
				}
				admin = admin || at(j).kind == sqlWord && databricksAdminObjects[at(j).text]
			}
		}
	}
	known = at(first).kind == sqlWord && databricksWriteForms[at(first).text] && !opaque
	return deletes, admin, secrets, known
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
func lexDatabricksSQL(sql string) (tokens []sqlToken, complete bool) {
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
					tokens = append(tokens, sqlToken{kind: sqlPunct, text: rest[:1]})
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
			end := sqlCommentEnd(rest)
			if end < 0 {
				complete = false
				continue
			}
			i += end
		case r == '\'' || r == '"' || r == '`':
			end := sqlQuoteEnd(rest, r != '`')
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
// or -1 if it never closes. A /*+ inside a comment nests in newer Spark lexers
// and not in older ones, so it returns -1 there too: the rest reads as code.
func sqlCommentEnd(s string) int {
	depth := 0
	for i := 0; i < len(s); {
		switch {
		case depth > 0 && strings.HasPrefix(s[i:], "/*+"):
			return -1
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
