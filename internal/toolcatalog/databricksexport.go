package toolcatalog

import (
	"net/url"
	"path"
	"strings"
)

// DatabricksSQLExports identifies explicit storage destinations. It shares
// the SQL lexer so comments and quoted content never become SQL clauses.
// Storage ownership is unknown locally: external storage URIs count. SQL
// whose effects cannot be read may export too, so the export control fails closed.
func DatabricksSQLExports(query string) bool {
	// Oversized SQL cannot be vouched for within the hook budget.
	if len(query) > databricksSQLMaxLen {
		return true
	}
	for _, hintNests := range []bool{false, true} {
		for _, dqIdentifiers := range []bool{false, true} {
			tokens, complete := lexDatabricksSQL(query, hintNests, dqIdentifiers)
			if _, _, _, known := classifyDatabricksTokens(tokens, complete); !known {
				return true
			}
			for len(tokens) > 0 {
				end := len(tokens)
				for i, token := range tokens {
					if token.is(";") {
						end = i
						break
					}
				}
				stmt := tokens[:end]
				tokens = tokens[min(end+1, len(tokens)):]
				if databricksStatementExports(stmt) {
					return true
				}
			}
		}
	}
	return false
}

func databricksStatementExports(stmt []sqlToken) bool {
	start := databricksStatementStart(stmt)
	if start >= len(stmt) || !setOf("CREATE", "ALTER", "INSERT", "REPLACE", "MERGE", "UPDATE", "FROM", "COPY")[stmt[start].text] {
		return false
	}
	ddl := stmt[start].is("CREATE") || stmt[start].is("ALTER") || stmt[start].is("REPLACE")
	destination := !stmt[start].is("FROM")
	depth, optionsDepth := 0, 0
	directoryTarget, viewDefinition, objectSeen := false, false, false
	targetStart, targetEnd := -1, -1
	at := func(i int) sqlToken {
		if i >= 0 && i < len(stmt) {
			return stmt[i]
		}
		return sqlToken{}
	}
	for i := start; i < len(stmt); i++ {
		token := stmt[i]
		if token.is("(") {
			depth++
		}
		if token.is(")") {
			if optionsDepth == depth {
				optionsDepth = 0
			}
			depth--
			continue
		}
		if optionsDepth > 0 && depth == optionsDepth && (at(i-1).is("(") || at(i-1).is(",")) {
			key, j := token.text, i+1
			for {
				if strings.ContainsRune(key, '\\') {
					return true // An escaped option name may hide path or url.
				}
				if strings.EqualFold(key, "path") || strings.EqualFold(key, "url") {
					if at(j).is("=") {
						j++
					}
					if exportSQLDestination(stmt, j, directoryTarget) {
						return true
					}
					break
				}
				if (token.kind != sqlString && token.kind != sqlName) || len(key) >= 4 || (at(j).kind != sqlString && at(j).kind != sqlName) {
					break
				}
				key += at(j).text
				j++
			}
		}
		if depth != 0 {
			continue
		}
		// FROM-first multi-insert can have a source subquery and several
		// SELECT clauses. Only each INSERT opens another destination.
		if ddl && !objectSeen && (token.is("TABLE") || token.is("VIEW") || token.is("VOLUME") || token.is("CATALOG") || token.is("SCHEMA") || token.is("DATABASE") || token.is("FUNCTION")) {
			objectSeen, viewDefinition = true, token.is("VIEW")
			targetStart = i + 1
			if at(targetStart).is("IF") && at(targetStart+1).is("NOT") && at(targetStart+2).is("EXISTS") {
				targetStart += 3
			} else if at(targetStart).is("IF") && at(targetStart+1).is("EXISTS") {
				targetStart += 2
			}
			targetEnd = targetStart
			for at(targetEnd+1).is(".") && targetEnd+2 < len(stmt) {
				targetEnd += 2
			}
		}
		// Consume the whole target name before interpreting its components
		// as clauses: VALUES, AS and other keywords can be identifiers.
		if i >= targetStart && i <= targetEnd && targetStart >= 0 {
			if i == targetStart && !viewDefinition && exportSQLDataSource(stmt, i) {
				return true
			}
			continue
		}
		// LIKE and CLONE read a source table. Its qualified components may
		// be clause keywords; destination clauses begin after that name.
		if ddl && (token.is("LIKE") || token.is("CLONE")) {
			i++
			for at(i+1).is(".") && i+2 < len(stmt) {
				i += 2
			}
			continue
		}
		next := at(i + 1)
		directoryOperand := next.kind == sqlString || next.kind == sqlName || next.is("USING") || next.is(":") || next.is("?") ||
			next.kind == sqlWord && !setOf("SELECT", "VALUES", "WITH", "FROM", "TABLE", "PARTITION", "BY")[next.text] && (at(i+2).is("(") || at(i+2).is("USING"))
		if token.is("DIRECTORY") && (at(i-1).is("LOCAL") && at(i-2).is("OVERWRITE") || at(i-1).is("OVERWRITE") && directoryOperand) {
			directoryTarget = true
			if at(i - 1).is("LOCAL") {
				return true // LOCAL writes the driver filesystem.
			}
		}
		if token.is("INSERT") {
			destination, ddl, directoryTarget = true, false, false
		}
		queryAS := token.is("AS") && ddl && (at(i+1).is("SELECT") || at(i+1).is("WITH") || at(i+1).is("VALUES") || at(i+1).is("TABLE") || at(i+1).is("FROM") || at(i+1).is("("))
		queryBoundary := (token.is("SELECT") || token.is("VALUES")) && !at(i-1).is("CLONE") && !at(i-1).is("LIKE") && !at(i-1).is(".") && !at(i+1).is(".")
		if queryAS || queryBoundary || token.is("USING") && stmt[start].is("MERGE") {
			destination = false
		}
		if !destination {
			continue
		}
		// ALTER column names are not table/partition storage clauses.
		locationClause := !stmt[start].is("ALTER") || at(i-1).is("SET") || at(i-1).is("MANAGED") || at(i-1).is(")")
		if ddl && token.is("LOCATION") && locationClause && exportSQLDestination(stmt, i+1, false) {
			return true
		}
		if token.is("DIRECTORY") && directoryTarget && !at(i+1).is("USING") && exportSQLDestination(stmt, i+1, true) {
			return true
		}
		if token.is("OPTIONS") && (ddl && !viewDefinition || directoryTarget) && at(i+1).is("(") {
			optionsDepth = depth + 1
		}
		// A direct data-source table path is a destination only immediately
		// after the target introducer, never after FROM, JOIN, USING or CLONE.
		target := at(i-1).is("UPDATE") || at(i-1).is("INTO") || at(i-1).is("OVERWRITE") || at(i-1).is("TABLE") && (ddl || at(i-2).is("OVERWRITE") || at(i-2).is("INTO"))
		if target && !viewDefinition && exportSQLDataSource(stmt, i) {
			return true
		}
	}
	return false
}

var databricksFileFormats = setOf("DELTA", "PARQUET", "CSV", "JSON", "ORC", "AVRO", "TEXT", "BINARYFILE", "XML", "ICEBERG", "JDBC", "LIBSVM", "IMAGE")

func exportSQLDataSource(stmt []sqlToken, i int) bool {
	if i+2 >= len(stmt) || !stmt[i+1].is(".") || i+3 < len(stmt) && stmt[i+3].is(".") {
		return false
	}
	target := stmt[i+2]
	if target.kind != sqlString && target.kind != sqlName {
		return false
	}
	// A colon alone is valid in a quoted catalog object name. Unknown
	// providers need a path-like target before treating it as storage.
	if !databricksFileFormats[strings.ToUpper(stmt[i].text)] && !strings.ContainsAny(target.text, "/\\") {
		return false
	}
	return exportSQLDestination(stmt, i+2, false)
}

// Spark 4.1 concatenates adjacent literals in destination values. Start at
// the value so an OPTIONS string key remains separate from its value.
func exportSQLDestination(stmt []sqlToken, i int, directory bool) bool {
	if i < 0 || i >= len(stmt) {
		return false
	}
	token := stmt[i]
	if (token.kind == sqlString || token.kind == sqlName) && i+1 < len(stmt) && (stmt[i+1].kind == sqlString || stmt[i+1].kind == sqlName) {
		var value strings.Builder
		value.WriteString(token.text)
		for i+1 < len(stmt) && (stmt[i+1].kind == sqlString || stmt[i+1].kind == sqlName) {
			i++
			value.WriteString(stmt[i].text)
		}
		token.text = value.String()
	}
	if i+1 < len(stmt) && (stmt[i+1].is("|") || stmt[i+1].is("+")) {
		return true // A constant expression can build an external URI.
	}
	return exportDestination(token, directory)
}

func exportDestination(token sqlToken, directory bool) bool {
	if token.kind != sqlString && token.kind != sqlName {
		// Bound markers, variables and expressions leave the destination
		// unreadable; they may name external storage.
		return token.kind != 0
	}
	// SQL escapes can change both the scheme and internal path membership.
	if strings.ContainsRune(token.text, '\\') {
		return true
	}
	value := strings.ToLower(strings.TrimSpace(token.text))
	cleaned := path.Clean(value)
	internal := strings.HasPrefix(value, "dbfs:") || strings.HasPrefix(cleaned, "/volumes/") || strings.HasPrefix(cleaned, "/dbfs/volumes/")
	externalURI := false
	if colon := strings.IndexByte(value, ':'); colon >= 0 {
		// Hadoop permits raw percent characters in the path. Parsing only
		// the scheme keeps those paths from losing their external class.
		uri, err := url.Parse(value[:colon+1])
		externalURI = err == nil && uri.Scheme != ""
	}
	return !internal && (externalURI || directory && value != "")
}
