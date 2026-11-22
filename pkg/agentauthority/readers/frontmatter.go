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

// Bounds on the parsed frontmatter, checked before anything is decoded:
// the decoder compares every pair of keys in a mapping, so a wide mapping
// costs far more than its bytes.
const (
	maxFrontmatterDepth = 32
	maxFrontmatterNodes = 4096
	maxFrontmatterPairs = 256
)

var errFrontmatterSize = errors.New("frontmatter is too large to read")

// checkNodes refuses an alias anywhere in the document, and nesting, nodes
// or mapping pairs past the bounds.
func checkNodes(node *yaml.Node, depth int, count *int) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode {
		return errFrontmatterAlias
	}
	*count++
	if depth > maxFrontmatterDepth || *count > maxFrontmatterNodes || node.Kind == yaml.MappingNode && len(node.Content) > 2*maxFrontmatterPairs {
		return errFrontmatterSize
	}
	for _, child := range node.Content {
		if err := checkNodes(child, depth+1, count); err != nil {
			return err
		}
	}
	return nil
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
	count := 0
	if err := checkNodes(&doc, 0, &count); err != nil {
		return HookSettings{}, err
	}
	if len(doc.Content) == 0 {
		// An empty block declares nothing.
		return HookSettings{}, nil
	}
	top := doc.Content[0]
	if top.Kind != yaml.MappingNode {
		if top.Kind == yaml.ScalarNode && top.Tag == "!!null" {
			return HookSettings{}, nil
		}
		return HookSettings{}, errFrontmatterShape
	}
	// Only the hooks value is decoded: the rest of the frontmatter is the
	// skill's own and never read.
	var raw any
	found := false
	for i := 0; i+1 < len(top.Content); i += 2 {
		if key := top.Content[i]; key.Kind == yaml.ScalarNode && key.Value == "hooks" {
			if found {
				return HookSettings{}, errFrontmatterShape
			}
			found = true
			if err := top.Content[i+1].Decode(&raw); err != nil {
				return HookSettings{}, err
			}
		}
	}
	if raw == nil {
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
