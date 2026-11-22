package readers

import (
	"bytes"
	"encoding/json"
	"errors"

	"go.yaml.in/yaml/v3"
)

var (
	errFrontmatterShape = errors.New("frontmatter is not a mapping")
	errFrontmatterAlias = errors.New("frontmatter uses a YAML alias")
)

// maxFrontmatterDepth bounds how deep frontmatter nests.
const maxFrontmatterDepth = 32

// hasAlias reports an alias anywhere in the document, or nesting past
// maxFrontmatterDepth.
func hasAlias(node *yaml.Node, depth int) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.AliasNode || depth > maxFrontmatterDepth {
		return true
	}
	for _, child := range node.Content {
		if hasAlias(child, depth+1) {
			return true
		}
	}
	return false
}

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
	var doc yaml.Node
	if err := yaml.Unmarshal(block, &doc); err != nil {
		return HookSettings{}, err
	}
	// An alias repeats a value without its bytes, so a small file could
	// expand past every bound: frontmatter with one isn't read.
	if hasAlias(&doc, 0) {
		return HookSettings{}, errFrontmatterAlias
	}
	var top map[string]any
	if err := doc.Decode(&top); err != nil {
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
