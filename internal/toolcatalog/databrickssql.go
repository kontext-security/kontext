package toolcatalog

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ClassifyDatabricksSQL raises the tier of a Databricks SQL text above the
// SQL base tier, write. It never lowers it.
//
// A delete or admin form found in any statement raises access, and recognized
// is then true: the tier is proven whatever else the text holds. Otherwise
// recognized is true only for a single statement of a known write form that
// runs no dynamic SQL and no function with outside effects. When it is false,
// access is write and the caller keeps its base tier. touchesSecrets reports
// a secret() call anywhere, recognized or not.
//
// ponytail: a keyword scan over a lexer that follows Spark's, not a grammar,
// so a false positive can only raise a tier. Upgrade path: a parser generated
// from Spark's SqlBaseParser.g4, if a tier ever needs lowering.
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
	if tier > sqlTierWrite {
		return sqlTiers[tier], touchesSecrets, true
	}
	return AccessWrite, touchesSecrets, known && statements == 1
}

const (
	sqlTierWrite = iota
	sqlTierDelete
	sqlTierAdmin
)

var sqlTiers = [...]string{AccessWrite, AccessDelete, AccessAdmin}

// Statement forms that stay at write. Delete and admin forms are found by the
// scan wherever they sit, so they need no entry.
var databricksWriteForms = setOf("SELECT", "WITH", "VALUES", "SHOW", "DESCRIBE", "DESC", "EXPLAIN",
	"INSERT", "UPDATE", "MERGE", "CREATE", "COPY", "SET", "USE")

// Objects whose CREATE, ALTER or DROP is administration: access policies,
// credentials, external locations, Delta Sharing and workspace groups.
var databricksAdminObjects = setOf("POLICY", "CREDENTIAL", "CONNECTION", "LOCATION", "SHARE",
	"RECIPIENT", "PROVIDER", "GROUP", "METASTORE")

// Words between CREATE, ALTER or DROP and the object kind.
var databricksObjectModifiers = setOf("OR", "REPLACE", "IF", "NOT", "EXISTS", "TEMPORARY", "TEMP",
	"GLOBAL", "EXTERNAL", "STORAGE", "SERVICE")

var databricksSecretFunctions = setOf("SECRET", "TRY_SECRET", "LIST_SECRETS")

// Functions that reach outside the warehouse or name objects at run time.
// Every AI_ function calls a model endpoint and counts too.
var databricksOpaqueFunctions = setOf("HTTP_REQUEST", "READ_FILES", "READ_KAFKA", "READ_KINESIS",
	"READ_PUBSUB", "READ_PULSAR", "REMOTE_QUERY", "VECTOR_SEARCH", "CLOUD_FILES", "IDENTIFIER")

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
	known = stmt[first].kind == sqlWord && databricksWriteForms[stmt[first].text]
	raise := func(to int) { tier = max(tier, to) }
	for i, tok := range stmt {
		prev, next := at(i-1), at(i+1)
		if next.is("(") && (tok.kind == sqlWord || tok.kind == sqlName) {
			name := tok.text[strings.LastIndexByte(tok.text, '.')+1:]
			switch {
			case databricksSecretFunctions[name]:
				secrets = true
			case databricksOpaqueFunctions[name] || strings.HasPrefix(name, "AI_"):
				known = false
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
		case "EXECUTE", "CALL":
			known = false
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
	return tier, secrets, known
}

const (
	sqlWord   = iota + 1 // unquoted word, upper-cased: a keyword or a name
	sqlName              // backtick or double-quoted, upper-cased: never a keyword
	sqlString            // single-quoted, raw or $$ literal: content dropped
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
// comments and literal content. complete is false when a quote or comment
// never closes; the lexer then reads past its opener as code, so a keyword
// hidden behind an unterminated quote is still seen.
func lexDatabricksSQL(sql string) (tokens []sqlToken, complete bool) {
	complete = true
	for i := 0; i < len(sql); {
		rest := sql[i:]
		r, size := utf8.DecodeRuneInString(rest)
		switch {
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
				end = 2
			}
			i += end
		case r == '\'' || r == '"' || r == '`':
			end := sqlQuoteEnd(rest, r != '`')
			if end < 0 {
				complete = false
				i++
				continue
			}
			if r == '\'' {
				tokens = append(tokens, sqlToken{kind: sqlString})
			} else {
				tokens = append(tokens, sqlToken{kind: sqlName, text: strings.ToUpper(rest[1 : end-1])})
			}
			i += end
		case strings.HasPrefix(rest, "$$"):
			end := strings.Index(rest[2:], "$$")
			if end < 0 {
				complete = false
				i += 2
				continue
			}
			tokens = append(tokens, sqlToken{kind: sqlString})
			i += 2 + end + 2
		case isSQLWordRune(r):
			j := i
			for j < len(sql) {
				wr, n := utf8.DecodeRuneInString(sql[j:])
				if !isSQLWordRune(wr) {
					break
				}
				j += n
			}
			word := sql[i:j]
			if (word == "r" || word == "R") && j < len(sql) && (sql[j] == '\'' || sql[j] == '"') {
				// A raw literal: a backslash escapes nothing.
				end := strings.IndexByte(sql[j+1:], sql[j])
				if end < 0 {
					complete = false
					i = j + 1
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
// it never closes. A doubled quote reads as two adjacent tokens, which covers
// the same text.
func sqlQuoteEnd(s string, backslashEscapes bool) int {
	for i := 1; i < len(s); i++ {
		switch {
		case backslashEscapes && s[i] == '\\':
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
