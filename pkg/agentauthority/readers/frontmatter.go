package readers

import (
	"bytes"
	"encoding/json"
	"errors"

	"go.yaml.in/yaml/v3"
)

var errFrontmatterShape = errors.New("frontmatter is not a mapping")

// FrontmatterHooks reads the `hooks` field of a skill's SKILL.md or a
// subagent's definition: YAML frontmatter between a leading `---` line and
// the next `---` line, in the settings files' hooks format. A file without
// frontmatter, or frontmatter without hooks, declares none.
func FrontmatterHooks(data []byte) (HookSettings, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	block, ok := frontmatter(data)
	if !ok {
		return HookSettings{}, nil
	}
	var top map[string]any
	if err := yaml.Unmarshal(block, &top); err != nil {
		return HookSettings{}, err
	}
	if top == nil {
		// An empty block declares nothing.
		return HookSettings{}, nil
	}
	raw, ok := top["hooks"]
	if !ok || raw == nil {
		return HookSettings{}, nil
	}
	encoded, err := json.Marshal(map[string]any{"hooks": raw})
	if err != nil {
		// A YAML map with non-string keys has no JSON form.
		return HookSettings{}, errFrontmatterShape
	}
	settings, err := Hooks(encoded)
	if err != nil {
		return HookSettings{}, err
	}
	// Only hooks: a skill's frontmatter holds no settings switches.
	return HookSettings{Hooks: settings.Hooks}, nil
}

// frontmatter returns the block between a first line `---` and the next
// line `---`.
func frontmatter(data []byte) ([]byte, bool) {
	first, rest, found := bytes.Cut(data, []byte("\n"))
	if !found || string(bytes.TrimRight(first, "\r \t")) != "---" {
		return nil, false
	}
	var block []byte
	for len(rest) > 0 {
		line, next, more := bytes.Cut(rest, []byte("\n"))
		if string(bytes.TrimRight(line, "\r \t")) == "---" {
			return block, true
		}
		block = append(block, line...)
		block = append(block, '\n')
		if !more {
			break
		}
		rest = next
	}
	// No closing line: not frontmatter.
	return nil, false
}
