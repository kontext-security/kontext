package readers

import (
	"bytes"
	"errors"
)

// JSONC permits comments and trailing commas, but otherwise uses encoding/json.
func jsonc(data []byte) ([]byte, error) {
	data = bytes.Clone(data)
	inString := false
	for i := 0; i < len(data); i++ {
		if inString {
			if data[i] == '\\' {
				i++
			} else if data[i] == '"' {
				inString = false
			}
			continue
		}
		if data[i] == '"' {
			inString = true
			continue
		}
		if data[i] != '/' || i+1 >= len(data) {
			continue
		}
		switch data[i+1] {
		case '/':
			for ; i < len(data) && data[i] != '\n' && data[i] != '\r'; i++ {
				data[i] = ' '
			}
		case '*':
			end := bytes.Index(data[i+2:], []byte("*/"))
			if end < 0 {
				return nil, errors.New("unterminated JSON comment")
			}
			end += i + 4
			for ; i < end; i++ {
				data[i] = ' '
			}
			i--
		}
	}
	inString = false
	for i := 0; i < len(data); i++ {
		if inString {
			if data[i] == '\\' {
				i++
			} else if data[i] == '"' {
				inString = false
			}
			continue
		}
		if data[i] == '"' {
			inString = true
			continue
		}
		if data[i] != ',' {
			continue
		}
		next := bytes.TrimLeft(data[i+1:], " \t\r\n")
		previous := bytes.TrimRight(data[:i], " \t\r\n")
		if len(previous) > 0 && !bytes.ContainsAny(previous[len(previous)-1:], "[{,:") && len(next) > 0 && (next[0] == '}' || next[0] == ']') {
			data[i] = ' '
		}
	}
	return data, nil
}
