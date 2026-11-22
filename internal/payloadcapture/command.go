package payloadcapture

import (
	"slices"
	"strings"
)

// Command rules read passwords in a client's arguments (mysql -pSECRET,
// sshpass -p SECRET, redis-cli -a SECRET, REDISCLI_AUTH=SECRET) by the
// client's own option grammar, which no regular expression gets right: the
// same letter means something else to another program (ssh -p is a port),
// quotes and escapes change where a word ends, and a command nests in
// another ($(…), bash -c "…", a JSON string). A small shell word lexer splits
// the text into commands and words; every word whose name is a client's is
// read as that client's command line, up to the end of its command.
//
// The lexer reads only what argv needs: words with their quotes, escapes,
// $'…' strings, parameters and command substitutions, and the operators
// that end a command. It never fails: an unterminated quote or substitution
// runs to the end of the text. What it cannot read statically it masks: a
// value holding a parameter or substitution is masked whole, and so is a word
// that holds a client's name past the nesting limit. Text that only looks
// like a command (a log line, a comment, prose) is read the same way, which
// over-redacts rather than leak.
//
// The same algorithm runs in kontext-cloud's command-redaction.ts, and both
// are pinned by testdata/command-redaction-vectors.json, byte span for byte
// span.

type commandRuleset struct {
	MaxDepth  int              `json:"maxDepth"`
	Programs  []commandProgram `json:"programs"`
	SecretEnv []string         `json:"secretEnv"`
}

type commandProgram struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Names       []string `json:"names"`
	// NamePrefixes match any name that starts with one (mariadb-dump).
	NamePrefixes []string `json:"namePrefixes"`
	// OptionsAnywhere reads options after operands too (mysql db -pX);
	// otherwise the first operand ends the options (sshpass -p X ssh -p 22).
	OptionsAnywhere bool `json:"optionsAnywhere"`
	// ShortNoArg are the short options that may come before a secret one
	// in a group (-vpSECRET); ShortWithArg take the next word when nothing
	// follows them in their group. Any other letter ends its group.
	ShortNoArg   string           `json:"shortNoArg"`
	ShortWithArg string           `json:"shortWithArg"`
	ShortSecrets []commandSecret  `json:"shortSecrets"`
	LongSecrets  []commandSecret  `json:"longSecrets"`
	Positional   []commandKeyword `json:"positionalSecrets"`
}

// commandSecret is a flag whose value is a secret: glued to a short flag
// (-pX), after = on a long one (--password=X), or the next word (-p X).
// A long flag also matches its prefixes of at least MinPrefix letters, as
// getopt_long abbreviations do.
type commandSecret struct {
	Flag      string `json:"flag"`
	MinPrefix int    `json:"minPrefix,omitempty"`
	Attached  bool   `json:"attached"`
	Next      bool   `json:"next"`
}

// commandKeyword is a first operand after which every word is a secret
// (redis-cli AUTH [user] password), compared without case.
type commandKeyword struct {
	Word string `json:"word"`
}

var (
	commandRules   commandRuleset
	commandNeedles []string
)

func compileCommandRules(rules commandRuleset) {
	commandRules = rules
	commandNeedles = nil
	for _, program := range rules.Programs {
		for _, name := range append(slices.Clone(program.Names), program.NamePrefixes...) {
			commandNeedles = append(commandNeedles, fold(strings.TrimSuffix(name, "-")))
		}
	}
	for _, name := range rules.SecretEnv {
		commandNeedles = append(commandNeedles, fold(name))
	}
}

// commandSpans returns the byte ranges of text that command rules mask, in
// order, apart, and none of them only a placeholder already.
func commandSpans(text string) []Span {
	if len(commandRules.Programs) == 0 || !containsAny(fold(text), commandNeedles) {
		return nil
	}
	spans := lexSpans(text, func(i int) (int, int) { return i, i + 1 })
	if strings.IndexByte(text, '\\') >= 0 {
		// A command inside a JSON string: read it unescaped as well, and mask
		// what either reading masks.
		view, from, to := jsonUnescaped(text)
		for _, span := range lexSpans(view, func(i int) (int, int) { return from[i], to[i] }) {
			spans = append(spans, span)
		}
	}
	merged := mergeCommandSpans(spans)
	out := merged[:0]
	for _, span := range merged {
		if text[span.Start:span.End] != RedactedPlaceholder {
			out = append(out, span)
		}
	}
	return out
}

// argvSpans is what the command rules mask in an argument vector
// (["mysql", "-pX"], or a {"command", "args"} pair): each element is one word
// as it is, and the spans are byte ranges of each element.
func argvSpans(argv []string) [][]Span {
	if len(commandRules.Programs) == 0 || !containsAny(fold(strings.Join(argv, " ")), commandNeedles) {
		return nil
	}
	var src strings.Builder
	words := make([]word, len(argv))
	for i, arg := range argv {
		start := src.Len()
		w := word{start: start, end: start + len(arg), argv: true}
		for k := 0; k < len(arg); k++ {
			w.add(arg[k], start+k, start+k+1, -1, false)
		}
		words[i] = w
		src.WriteString(arg)
		src.WriteByte(' ')
	}
	l := &lexer{src: src.String(), limit: src.Len()}
	l.read(words)
	out := make([][]Span, len(argv))
	for _, m := range mergeCommandSpans(l.masks) {
		for i := range words {
			start, end := max(m.Start, words[i].start), min(m.End, words[i].end)
			if start < end {
				out[i] = append(out[i], Span{start - words[i].start, end - words[i].start})
			}
		}
	}
	return out
}

// lexSpans lexes text and returns its masks, mapped through source (which
// gives the original range of a byte of text).
func lexSpans(text string, source func(int) (int, int)) []Span {
	l := &lexer{src: text, limit: len(text)}
	l.commands(0)
	var spans []Span
	add := func(start, end int) {
		if start < end {
			from, _ := source(start)
			_, to := source(end - 1)
			spans = append(spans, Span{from, to})
		}
	}
	for _, m := range l.masks {
		add(m.Start, m.End)
	}
	return spans
}

func mergeCommandSpans(spans []Span) []Span {
	slices.SortFunc(spans, func(a, b Span) int {
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		return a.End - b.End
	})
	var merged []Span
	for _, span := range spans {
		if n := len(merged); n > 0 && span.Start < merged[n-1].End {
			merged[n-1].End = max(merged[n-1].End, span.End)
			continue
		}
		merged = append(merged, span)
	}
	return merged
}

// jsonUnescaped is text with JSON string escapes read (\" \\ \/ \n \t \r \b
// \f and ASCII \u00XX), and the original range of each of its bytes.
func jsonUnescaped(text string) (string, []int, []int) {
	var out strings.Builder
	var from, to []int
	emit := func(c byte, start, end int) {
		out.WriteByte(c)
		from, to = append(from, start), append(to, end)
	}
	for i := 0; i < len(text); {
		c := text[i]
		if c == '\\' && i+1 < len(text) {
			if r, ok := jsonEscapes[text[i+1]]; ok {
				emit(r, i, i+2)
				i += 2
				continue
			}
			if text[i+1] == 'u' && i+6 <= len(text) && text[i+2] == '0' && text[i+3] == '0' {
				if v, ok := hexByte(text[i+4], text[i+5]); ok && v < 0x80 {
					emit(v, i, i+6)
					i += 6
					continue
				}
			}
		}
		emit(c, i, i+1)
		i++
	}
	return out.String(), from, to
}

var jsonEscapes = map[byte]byte{'"': '"', '\\': '\\', '/': '/', 'n': '\n', 't': '\t', 'r': '\r', 'b': '\b', 'f': '\f'}

func hexByte(a, b byte) (byte, bool) {
	hi, ok1 := hexDigit(a)
	lo, ok2 := hexDigit(b)
	return hi<<4 | lo, ok1 && ok2
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// word is one shell word: its source range, its cooked text (quotes
// removed, escapes read, a NUL for each parameter or substitution), and for
// each cooked byte the source range it came from and the quoted part it is
// in.
type word struct {
	start, end int
	cooked     []byte
	from, to   []int
	// quote is the source start of the quoted part a cooked byte is in, or
	// -1; first marks the first cooked byte of its quoted part.
	quote []int
	first []bool
	// redirect marks a redirection target (> file), which is not an
	// argument.
	redirect bool
	// dynamic marks a word with a parameter or substitution in it.
	dynamic bool
	// opaque marks a word holding text the lexer did not read (${…}).
	opaque bool
	// argv marks an argument vector element, which is read as commands
	// whenever it names a client (bash -c "mysql -pX"), quoted or not.
	argv bool
}

func (w *word) add(c byte, from, to, quote int, first bool) {
	w.cooked = append(w.cooked, c)
	w.from = append(w.from, from)
	w.to = append(w.to, to)
	w.quote = append(w.quote, quote)
	w.first = append(w.first, first)
}

// valueStart is where a value that starts at cooked byte k starts in the
// source: there for unquoted text, at the opening quote for the first byte of
// a quoted part, and at the word's start inside a quoted part (-p and its
// value in one pair of quotes are masked together).
func (w *word) valueStart(k int) int {
	switch {
	case w.quote[k] < 0:
		return w.from[k]
	case w.first[k]:
		return w.quote[k]
	default:
		return w.start
	}
}

type lexer struct {
	src   string
	i     int
	limit int
	depth int
	// blind lexers only find where their input ends, reading nothing.
	blind bool
	masks []Span
	// words, when set, collects the source range of every argument word
	// (the differential test against mvdan.cc/sh reads it).
	words *[]Span
}

func (l *lexer) child(start, limit int) *lexer {
	return &lexer{src: l.src, i: start, limit: limit, depth: l.depth + 1, blind: l.blind, words: l.words}
}

// tooDeep reports a nesting level past the ruleset's limit.
func (l *lexer) tooDeep() bool {
	return l.depth+1 > commandRules.MaxDepth
}

func (l *lexer) mask(start, end int) {
	if start < end {
		l.masks = append(l.masks, Span{start, end})
	}
}

// commands lexes commands until the end of the input or, when term is ')'
// or '`', the unnested term that closes a substitution, and reads each.
func (l *lexer) commands(term byte) {
	var command []word
	flush := func() {
		if l.words != nil {
			for _, w := range command {
				if !w.redirect {
					*l.words = append(*l.words, Span{w.start, w.end})
				}
			}
		}
		if len(command) > 0 && !l.blind {
			l.read(command)
		}
		command = nil
	}
	defer flush()
	parens, redirect := 0, false
	for l.i < l.limit {
		c := l.src[l.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			l.i++
		case c == '\\' && l.i+1 < l.limit && l.src[l.i+1] == '\n':
			l.i += 2
		case c == '\\' && l.i+2 < l.limit && l.src[l.i+1] == '\r' && l.src[l.i+2] == '\n':
			l.i += 3
		case c == '\n' || c == ';' || c == '&' || c == '|':
			flush()
			redirect = false
			l.i++
		case c == '(':
			flush()
			parens++
			l.i++
		case c == ')':
			flush()
			l.i++
			if parens == 0 && term == ')' {
				return
			}
			parens = max(parens-1, 0)
		case c == '`' && term == '`':
			flush()
			l.i++
			return
		case c == '<' || c == '>':
			// A file descriptor glued to the operator (2>) is no argument.
			if n := len(command); n > 0 && command[n-1].end == l.i && isDigits([]byte(l.src[command[n-1].start:l.i])) {
				command[n-1].redirect = true
			}
			for l.i < l.limit && (l.src[l.i] == '<' || l.src[l.i] == '>' || l.src[l.i] == '&' ||
				l.src[l.i] == '|' && l.src[l.i-1] == '>') {
				l.i++
			}
			redirect = true
		case c == '#':
			// A comment is read as commands too (# was: mysql -pX).
			end := strings.IndexByte(l.src[l.i:l.limit], '\n')
			if end < 0 {
				end = l.limit
			} else {
				end += l.i
			}
			l.nested(l.i+1, end)
			l.i = end
		default:
			w := l.word(term)
			w.redirect, redirect = redirect, false
			command = append(command, w)
		}
	}
}

// nested lexes src[start:end] as commands one level deeper, or when that is
// past the limit masks it whole if it names a client (fallback, when set,
// is the range to mask instead).
func (l *lexer) nested(start, end int) {
	if l.blind {
		return
	}
	if l.tooDeep() {
		if containsAny(fold(l.src[start:end]), commandNeedles) {
			l.mask(start, end)
		}
		return
	}
	child := l.child(start, end)
	child.commands(0)
	l.masks = append(l.masks, child.masks...)
}

// substitution lexes the commands of $(…) or `…` starting at l.i, one level
// deeper, and returns where it ends.
func (l *lexer) substitution(term byte) int {
	start := l.i
	child := l.child(l.i, l.limit)
	if l.tooDeep() && !l.blind {
		// Too deep: find the end without reading, and mask it whole if it
		// names a client.
		child.blind = true
		child.commands(term)
		if containsAny(fold(l.src[start:child.i]), commandNeedles) {
			l.mask(start, child.i)
		}
		return child.i
	}
	child.commands(term)
	l.masks = append(l.masks, child.masks...)
	return child.i
}

func isDigits(text []byte) bool {
	for _, c := range text {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(text) > 0
}

func isWordEnd(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', ';', '&', '|', '(', ')', '<', '>':
		return true
	}
	return false
}

// word lexes one word at l.i.
func (l *lexer) word(term byte) word {
	w := word{start: l.i}
	// end is where the word's last part ends: a line continuation after it
	// is not part of it.
	end := l.i
	for l.i < l.limit {
		c := l.src[l.i]
		if isWordEnd(c) || c == '`' && term == '`' {
			break
		}
		switch c {
		case '\\':
			if l.i+1 >= l.limit {
				w.add('\\', l.i, l.i+1, -1, false)
				l.i++
			} else if l.src[l.i+1] == '\n' {
				l.i += 2
				continue
			} else {
				w.add(l.src[l.i+1], l.i, l.i+2, -1, false)
				l.i += 2
			}
		case '\'':
			l.single(&w)
		case '"':
			l.double(&w, l.i)
		case '`':
			start := l.i
			l.i++
			end := l.substitution('`')
			l.i = end
			w.add(0, start, end, -1, false)
			w.dynamic = true
		case '$':
			l.dollar(&w, -1, false)
		default:
			w.add(c, l.i, l.i+1, -1, false)
			l.i++
		}
		end = l.i
	}
	w.end = end
	return w
}

// single lexes '…' at l.i.
func (l *lexer) single(w *word) {
	start := l.i
	l.i++
	first := true
	for l.i < l.limit && l.src[l.i] != '\'' {
		w.add(l.src[l.i], l.i, l.i+1, start, first)
		first = false
		l.i++
	}
	if l.i < l.limit {
		l.i++
	}
}

// double lexes "…" at l.i; quote is where the quoted part starts ($"…").
func (l *lexer) double(w *word, quote int) {
	l.i++
	mark := len(w.cooked)
	for l.i < l.limit && l.src[l.i] != '"' {
		c := l.src[l.i]
		switch {
		case c == '\\' && l.i+1 < l.limit && strings.IndexByte("$`\"\\", l.src[l.i+1]) >= 0:
			w.add(l.src[l.i+1], l.i, l.i+2, quote, false)
			l.i += 2
		case c == '\\' && l.i+1 < l.limit && l.src[l.i+1] == '\n':
			l.i += 2
		case c == '`':
			start := l.i
			l.i++
			end := l.substitution('`')
			l.i = end
			w.add(0, start, end, quote, false)
			w.dynamic = true
		case c == '$':
			l.dollar(w, quote, true)
		default:
			w.add(c, l.i, l.i+1, quote, false)
			l.i++
		}
	}
	if l.i < l.limit {
		l.i++
	}
	if len(w.first) > mark {
		w.first[mark] = true
	}
}

// dollar lexes what starts with $ at l.i: $'…', $"…", $(…), ${…}, $name,
// or a literal $.
func (l *lexer) dollar(w *word, quote int, inDouble bool) {
	start := l.i
	next := byte(0)
	if l.i+1 < l.limit {
		next = l.src[l.i+1]
	}
	switch {
	case next == '\'' && !inDouble:
		l.i++
		l.ansi(w, start)
	case next == '"' && !inDouble:
		l.i++
		l.double(w, start)
	case next == '(':
		l.i += 2
		end := l.substitution(')')
		l.i = end
		w.add(0, start, end, quote, false)
		w.dynamic = true
	case next == '{':
		end := braceEnd(l.src, l.i+2, l.limit)
		l.i = end
		w.add(0, start, end, quote, false)
		w.dynamic = true
		w.opaque = true
	case next == '_' || 'a' <= next && next <= 'z' || 'A' <= next && next <= 'Z':
		l.i += 2
		for l.i < l.limit && isNameByte(l.src[l.i]) {
			l.i++
		}
		w.add(0, start, l.i, quote, false)
		w.dynamic = true
	case next != 0 && strings.IndexByte("0123456789@*#?$!-", next) >= 0:
		l.i += 2
		w.add(0, start, l.i, quote, false)
		w.dynamic = true
	default:
		w.add('$', l.i, l.i+1, quote, false)
		l.i++
	}
}

func isNameByte(c byte) bool {
	return c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

// braceEnd is the end of ${…} whose body starts at i: past the } that
// closes it, skipping quotes and nested braces, or limit.
func braceEnd(src string, i, limit int) int {
	depth := 1
	for i < limit {
		switch src[i] {
		case '\\':
			i++
		case '\'':
			if end := strings.IndexByte(src[i+1:limit], '\''); end >= 0 {
				i += end + 1
			} else {
				return limit
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return limit
}

// ansi lexes $'…' at l.i (the quote), reading its escapes.
func (l *lexer) ansi(w *word, quote int) {
	l.i++
	first := true
	add := func(c byte, from, to int) {
		w.add(c, from, to, quote, first)
		first = false
	}
	for l.i < l.limit && l.src[l.i] != '\'' {
		c := l.src[l.i]
		if c != '\\' || l.i+1 >= l.limit {
			add(c, l.i, l.i+1)
			l.i++
			continue
		}
		start, e := l.i, l.src[l.i+1]
		l.i += 2
		switch e {
		case 'n':
			add('\n', start, l.i)
		case 't':
			add('\t', start, l.i)
		case 'r':
			add('\r', start, l.i)
		case 'a':
			add('\a', start, l.i)
		case 'b':
			add('\b', start, l.i)
		case 'e', 'E':
			add(0x1b, start, l.i)
		case 'f':
			add('\f', start, l.i)
		case 'v':
			add('\v', start, l.i)
		case 'x':
			if l.i+1 < l.limit {
				if v, ok := hexByte(l.src[l.i], l.src[l.i+1]); ok {
					l.i += 2
					add(v, start, l.i)
					continue
				}
			}
			add('\\', start, start+1)
			add('x', start+1, l.i)
		default:
			if '0' <= e && e <= '7' {
				v := int(e - '0')
				for n := 0; n < 2 && l.i < l.limit && '0' <= l.src[l.i] && l.src[l.i] <= '7'; n++ {
					v = v*8 + int(l.src[l.i]-'0')
					l.i++
				}
				add(byte(v), start, l.i)
			} else if e == '\\' || e == '\'' || e == '"' || e == '?' {
				add(e, start, l.i)
			} else {
				add('\\', start, start+1)
				add(e, start+1, l.i)
			}
		}
	}
	if l.i < l.limit {
		l.i++
	}
}

// read reads one command's words: secret environment assignments in any
// word, every word that names a client as that client's command line, and
// the commands inside quoted words.
func (l *lexer) read(command []word) {
	programs := make([]*commandProgram, len(command))
	for index := range command {
		w := &command[index]
		l.secretEnv(w)
		if w.opaque && containsAny(fold(l.src[w.start:w.end]), commandNeedles) {
			l.mask(w.start, w.end)
		} else {
			l.inner(w)
		}
		programs[index] = programOf(l.src, w)
	}
	// A client's command line runs to the end of the command, but a later
	// word naming the same client reads the rest afresh, which masks at
	// least as much (its options are not past a --, and its first operand
	// is still to come). So each reading stops at that word, and the reads
	// stay linear in the words (mysql -p\<newline> repeated).
	tail := len(command)
	for index, program := range programs {
		if program == nil {
			continue
		}
		stop := len(command)
		for next := index + 1; next < len(command); next++ {
			if programs[next] == program {
				stop = next + 1
				break
			}
		}
		l.arguments(program, command, index+1, stop, &tail)
	}
}

// inner reads the commands a quoted or escaped word holds (bash -c "…",
// ssh host '…', a JSON string), mapping its masks back to the source.
func (l *lexer) inner(w *word) {
	cooked := string(w.cooked)
	if !w.argv && cooked == l.src[w.start:w.end] || !containsAny(fold(cooked), commandNeedles) {
		return
	}
	if l.tooDeep() {
		l.mask(w.start, w.end)
		return
	}
	child := &lexer{src: cooked, limit: len(cooked), depth: l.depth + 1}
	child.commands(0)
	for _, m := range child.masks {
		l.mask(w.from[m.Start], w.to[m.End-1])
	}
}

// secretEnv masks the value of a secret variable assigned in w
// (REDISCLI_AUTH=X, env 'REDISCLI_AUTH=X', export SSHPASS=X).
func (l *lexer) secretEnv(w *word) {
	cooked := string(w.cooked)
	for _, name := range commandRules.SecretEnv {
		prefix := name + "="
		for at := 0; ; {
			found := strings.Index(cooked[at:], prefix)
			if found < 0 {
				break
			}
			k := at + found
			if k == 0 || !isNameByte(w.cooked[k-1]) {
				l.maskFrom(w, k+len(prefix))
			}
			at = k + 1
		}
	}
}

// maskFrom masks w's value that starts at cooked byte k, to the word's end.
func (l *lexer) maskFrom(w *word, k int) {
	if k < len(w.cooked) {
		l.mask(w.valueStart(k), w.end)
	}
}

// programOf is the client w names, if any: the last path component of the
// word, cooked or as written, without case and without .exe, .cmd or .bat.
func programOf(src string, w *word) *commandProgram {
	raw := strings.NewReplacer("'", "", `"`, "").Replace(src[w.start:w.end])
	for _, text := range []string{string(w.cooked), raw} {
		name := strings.ToLower(trailingName(text))
		for _, suffix := range []string{".exe", ".cmd", ".bat"} {
			name = strings.TrimSuffix(name, suffix)
		}
		if name == "" {
			continue
		}
		for index := range commandRules.Programs {
			program := &commandRules.Programs[index]
			if slices.Contains(program.Names, name) {
				return program
			}
			for _, prefix := range program.NamePrefixes {
				if strings.HasPrefix(name, prefix) && len(name) > len(prefix) {
					return program
				}
			}
		}
	}
	return nil
}

// trailingName is the run of name characters ([A-Za-z0-9._+-]) at the end
// of text: a program's name after its directory (/usr/bin/, C:\bin\) or
// whatever else is glued before it ({"cmd":mysql).
func trailingName(text string) string {
	i := len(text)
	for i > 0 {
		c := text[i-1]
		if !(isNameByte(c) || c == '.' || c == '-' || c == '+') {
			break
		}
		i--
	}
	return toLowerASCII(text[i:])
}

func toLowerASCII(text string) string {
	for i := 0; i < len(text); i++ {
		if 'A' <= text[i] && text[i] <= 'Z' {
			b := []byte(text)
			for j := i; j < len(b); j++ {
				if 'A' <= b[j] && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return text
}

// arguments reads args[from:stop], the words after a client's name, by the
// client's option grammar. A positional secret (redis-cli AUTH) masks every
// word after it to the end of args; *tail is where the words already masked
// that way start.
func (l *lexer) arguments(program *commandProgram, args []word, from, stop int, tail *int) {
	optionsDone, operandSeen := false, false
	for j := from; j < stop; j++ {
		w := &args[j]
		if w.redirect {
			continue
		}
		c := string(w.cooked)
		if !optionsDone && c == "--" {
			optionsDone = true
			continue
		}
		if !optionsDone && len(c) > 1 && c[0] == '-' {
			// An option's value is the next word that is not a
			// redirection (--pass 2>err X takes X).
			next := j + 1
			for next < len(args) && args[next].redirect {
				next++
			}
			var took int
			if c[1] == '-' {
				took = l.longOption(program, w, args[next:])
			} else {
				took = l.shortOptions(program, w, args[next:])
			}
			if took > 0 {
				j = next
			}
			continue
		}
		if !operandSeen {
			operandSeen = true
			for _, keyword := range program.Positional {
				if strings.EqualFold(c, keyword.Word) {
					for k := j + 1; k < *tail; k++ {
						if !args[k].redirect {
							l.mask(args[k].start, args[k].end)
						}
					}
					*tail = min(*tail, j+1)
					return
				}
			}
		}
		if !program.OptionsAnywhere {
			return
		}
	}
}

// longOption reads --name[=value] and returns how many of the next words
// (rest, without redirections) it takes.
func (l *lexer) longOption(program *commandProgram, w *word, rest []word) int {
	c := string(w.cooked)
	name, _, equals := strings.Cut(c[2:], "=")
	for _, secret := range program.LongSecrets {
		minimum := secret.MinPrefix
		if minimum == 0 {
			minimum = len(secret.Flag)
		}
		if len(name) < minimum || !strings.HasPrefix(secret.Flag, toLowerASCII(name)) {
			continue
		}
		if equals && secret.Attached {
			l.maskFrom(w, 2+len(name)+1)
		} else if !equals && secret.Next && len(rest) > 0 {
			l.mask(rest[0].start, rest[0].end)
			return 1
		}
		return 0
	}
	return 0
}

// shortOptions reads a group of short options (-vpX) and returns how many
// of the next words (rest, without redirections) it takes.
func (l *lexer) shortOptions(program *commandProgram, w *word, rest []word) int {
	c := w.cooked
	for k := 1; k < len(c); k++ {
		letter := c[k]
		for _, secret := range program.ShortSecrets {
			if secret.Flag[0] != letter {
				continue
			}
			if k+1 < len(c) {
				if secret.Attached {
					l.maskFrom(w, k+1)
				}
				return 0
			}
			if secret.Next && len(rest) > 0 {
				l.mask(rest[0].start, rest[0].end)
				return 1
			}
			return 0
		}
		if strings.IndexByte(program.ShortNoArg, letter) >= 0 {
			continue
		}
		// An option that takes the next word, unless the next word is an
		// option itself, which is then read as one (over-redaction at worst).
		if k+1 == len(c) && strings.IndexByte(program.ShortWithArg, letter) >= 0 &&
			len(rest) > 0 && !strings.HasPrefix(string(rest[0].cooked), "-") {
			return 1
		}
		return 0
	}
	return 0
}
