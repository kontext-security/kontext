package toolcatalog

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ClassifyDatabricksSQL raises the tier of a Databricks SQL text above the
// SQL base tier, write. It never lowers it: access is write or a delete or
// admin form found in any statement, and the caller applies it as is.
//
// recognized is true only when access is exact: one statement of a known
// form, lexed to the end, that runs no dynamic SQL, no user-defined function
// and no function with outside effects. When it is false, access is a lower
// bound; with nothing raised it is write, the base tier the caller keeps.
// touchesSecrets reports a secret() call anywhere, recognized or not.
//
// ponytail: a keyword scan over a lexer that follows Spark's, not a grammar,
// so a false positive can only raise a tier. A user-defined function called by
// its bare name reads as a built-in. Upgrade path: a parser generated from
// Spark's SqlBaseParser.g4 and the function catalog, if a tier ever needs
// lowering.
func ClassifyDatabricksSQL(sql string) (access string, touchesSecrets bool, recognized bool) {
	tokens, complete := lexDatabricksSQL(sql)
	tier, statements, known := sqlTierWrite, 0, complete
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
		stmtTier, secrets, stmtKnown := classifyDatabricksStatement(stmt)
		tier = max(tier, stmtTier)
		touchesSecrets = touchesSecrets || secrets
		known = known && stmtKnown
	}
	return sqlTiers[tier], touchesSecrets, known && statements == 1
}

const (
	sqlTierWrite = iota
	sqlTierDelete
	sqlTierAdmin
)

var sqlTiers = [...]string{AccessWrite, AccessDelete, AccessAdmin}

// Statement forms whose tier the scan decides. The scan raises any statement
// wherever a delete or admin form sits; raiseForms are known only once raised.
var (
	databricksWriteForms = setOf("SELECT", "WITH", "VALUES", "SHOW", "DESCRIBE", "DESC", "EXPLAIN",
		"INSERT", "UPDATE", "MERGE", "CREATE", "COPY", "SET", "USE")
	databricksRaiseForms = setOf("DROP", "DELETE", "TRUNCATE", "VACUUM", "RESTORE", "REMOVE",
		"GRANT", "REVOKE", "DENY", "ALTER", "REFRESH")
)

// A qualified name before ( is a call unless a table keyword precedes it: a
// column list. A qualified column before a subquery reads as a call too.
var databricksTableKeywords = setOf("INTO", "TABLE", "VIEW", "FUNCTION", "EXISTS")

// Objects whose CREATE, ALTER or DROP is administration: access policies,
// governed tags, credentials, external locations, Delta Sharing, clean rooms and workspace
// groups.
var databricksAdminObjects = setOf("POLICY", "TAG", "CREDENTIAL", "CONNECTION", "LOCATION", "SHARE", "CLEAN",
	"RECIPIENT", "PROVIDER", "GROUP", "METASTORE")

// Words between CREATE, ALTER or DROP and the object kind.
var databricksObjectModifiers = setOf("OR", "REPLACE", "IF", "NOT", "EXISTS", "TEMPORARY", "TEMP",
	"GLOBAL", "EXTERNAL", "STORAGE", "SERVICE", "GOVERNED")

var databricksSecretFunctions = setOf("SECRET", "TRY_SECRET", "LIST_SECRETS")

// Functions that reach outside the warehouse, write files or name objects at
// run time. Every AI_ function calls a model endpoint and counts too.
var databricksOpaqueFunctions = setOf("HTTP_REQUEST", "READ_FILES", "READ_KAFKA", "READ_KINESIS",
	"READ_PUBSUB", "READ_PULSAR", "REMOTE_QUERY", "VECTOR_SEARCH", "CLOUD_FILES", "IDENTIFIER",
	"CREATE_FILE", "COPY_FILE", "TRY_COPY_FILE", "REFLECT", "JAVA_METHOD", "TRY_REFLECT")

func classifyDatabricksStatement(stmt []sqlToken) (tier int, secrets, known bool) {
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
	opaque, refresh := false, false
	raise := func(to int) { tier = max(tier, to) }
	for i, tok := range stmt {
		prev, next := at(i-1), at(i+1)
		if next.is("(") && (tok.kind == sqlWord || tok.kind == sqlName) {
			name := tok.text[strings.LastIndexByte(tok.text, '.')+1:]
			switch {
			case databricksSecretFunctions[name]:
				secrets = true
			case databricksOpaqueFunctions[name] || strings.HasPrefix(name, "AI_"):
				opaque = true
			}
			builtin := at(i-2).text == "BUILTIN" && at(i-3).is(".") && at(i-4).text == "SYSTEM" && !at(i-5).is(".")
			if prev.is(".") && !builtin {
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
		switch tok.text {
		case "GRANT", "REVOKE", "DENY":
			raise(sqlTierAdmin)
		case "DELETE", "TRUNCATE", "OVERWRITE", "VACUUM", "RESTORE", "PURGE", "REMOVE":
			raise(sqlTierDelete)
		case "REPLACE": // CREATE OR REPLACE, INSERT … REPLACE WHERE|USING|ON; not replace()
			if !next.is("(") {
				raise(sqlTierDelete)
			}
		case "MASK": // a column mask; not the mask() function
			if !next.is("(") {
				raise(sqlTierAdmin)
			}
		case "FILTER":
			if prev.is("ROW") {
				raise(sqlTierAdmin)
			}
		case "TO":
			if prev.is("OWNER") {
				raise(sqlTierAdmin)
			}
		case "TAG", "TAGS":
			if prev.is("SET") || prev.is("UNSET") {
				raise(sqlTierAdmin)
			}
		case "REFRESH": // not CREATE OR REFRESH
			refresh = refresh || !prev.is("OR")
		case "FULL", "WHERE": // REFRESH … FULL truncates; REFRESH … WHERE deletes the rows it matches
			if refresh {
				raise(sqlTierDelete)
			}
		case "EXECUTE", "CALL":
			opaque = true
		case "CREATE", "ALTER", "DROP":
			if tok.text == "DROP" {
				raise(sqlTierDelete)
			}
			j := i + 1
			for at(j).kind == sqlWord && databricksObjectModifiers[at(j).text] {
				j++
			}
			if at(j).kind == sqlWord && databricksAdminObjects[at(j).text] {
				raise(sqlTierAdmin)
			}
		}
	}
	head := stmt[first]
	known = head.kind == sqlWord && (databricksWriteForms[head.text] || tier > sqlTierWrite && databricksRaiseForms[head.text])
	return tier, secrets, known && !opaque
}

const (
	sqlWord   = iota + 1 // unquoted word, upper-cased: a keyword or a name
	sqlName              // backtick or double-quoted, upper-cased: never a keyword
	sqlString            // single-quoted, raw or dollar-quoted literal: content dropped
	sqlPunct
)

type sqlToken struct {
	kind int
	text string
}

func (t sqlToken) is(text string) bool {
	return (t.kind == sqlWord || t.kind == sqlPunct) && t.text == text
}

// lexDatabricksSQL splits sql the way Spark's SqlBaseLexer does, dropping
// comments and literal content. complete is false when a quote, comment or
// dollar body never closes; the lexer then reads the rest as plain code, with
// no quotes or comments, so nothing after the opener can hide a keyword and
// the scan stays linear.
func lexDatabricksSQL(sql string) (tokens []sqlToken, complete bool) {
	complete = true
	for i := 0; i < len(sql); {
		rest := sql[i:]
		r, size := utf8.DecodeRuneInString(rest)
		switch {
		case !complete:
			if isSQLWordRune(r) {
				j := sqlWordEnd(rest)
				tokens = append(tokens, sqlToken{kind: sqlWord, text: strings.ToUpper(rest[:j])})
				i += j
			} else {
				if r < utf8.RuneSelf && !unicode.IsSpace(r) {
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
			if end < 0 {
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
// start of s, or "".
func sqlDollarTag(s string) string {
	if !strings.HasPrefix(s, "$") {
		return ""
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '$':
			return s[:i+1]
		case c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || i > 1 && '0' <= c && c <= '9':
		default:
			return ""
		}
	}
	return ""
}

// sqlCommentEnd returns the length of the nested /* */ comment that starts s,
// or -1 if it never closes. As in Spark, /*+ inside a comment does not nest.
func sqlCommentEnd(s string) int {
	depth := 0
	for i := 0; i < len(s); {
		switch {
		case strings.HasPrefix(s[i:], "/*") && (depth == 0 || !strings.HasPrefix(s[i:], "/*+")):
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
