package agentauthority

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

func (g *guard) credential(kind, path string, detail int, host, login string) {
	result := g.access(path, "stat")
	if result.err != nil {
		return
	}
	info := result.info
	stamp := info.ModTime().UTC().Format(time.RFC3339)
	g.report.Credentials = append(g.report.Credentials, Credential{Kind: kind, Path: safe(g.source(path), 1024), Present: true, ModifiedAt: &stamp, Detail: detail, Host: pointer(safe(host, 128)), Login: pointer(safe(login, 128))})
}
func (g *guard) credentials() {
	ssh := filepath.Join(g.home, ".ssh")
	keys := 0
	var newest time.Time
	for _, entry := range g.entries(ssh) {
		if strings.HasPrefix(entry.Name(), "id_") && !strings.HasSuffix(entry.Name(), ".pub") {
			result := g.access(filepath.Join(ssh, entry.Name()), "stat")
			if errors.Is(result.err, os.ErrNotExist) {
				g.fail(ReasonChangedDuringRead)
			}
			if result.err == nil {
				keys++
				if result.info.ModTime().After(newest) {
					newest = result.info.ModTime()
				}
			}
		}
	}
	if keys > 0 {
		stamp := newest.UTC().Format(time.RFC3339)
		g.report.Credentials = append(g.report.Credentials, Credential{Kind: "ssh_key", Path: "~/.ssh", Present: true, ModifiedAt: &stamp, Detail: keys})
	}
	for _, entry := range []struct{ path, kind string }{
		{".config/gh/hosts.yml", "gh_token"}, {".aws/credentials", "aws_credentials"}, {".aws/config", "aws_config_profiles"},
		{".kube/config", "kubeconfig"}, {".npmrc", "npm_token"}, {".docker/config.json", "docker_config_auth"},
	} {
		path := filepath.Join(g.home, entry.path)
		facts, err := readParsed(g, path, func(data []byte) ([]Credential, error) { return credentialFacts(entry.kind, data) })
		if err != nil {
			continue
		}
		for _, fact := range facts {
			host, login := "", ""
			if fact.Host != nil {
				host = *fact.Host
			}
			if fact.Login != nil {
				login = *fact.Login
			}
			g.credential(entry.kind, path, fact.Detail, host, login)
		}
	}
	g.credential("gcloud_adc", filepath.Join(g.home, ".config/gcloud/application_default_credentials.json"), 1, "", "")
}

// Carries no parser text: the error is cached and these files hold secrets.
var errMalformedCredentials = errors.New("malformed credential file")

// kubeContexts walks the parsed tree because kubectl accepts repeated keys and
// keeps the last value, while a map decode rejects them.
func kubeContexts(data []byte) (int, bool) {
	var doc yaml.Node
	if yaml.Unmarshal(data, &doc) != nil {
		return 0, false
	}
	if len(doc.Content) == 0 {
		return 0, true
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return 0, false
	}
	count := 0
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "contexts" {
			count = 0
			value := root.Content[i+1]
			if value.Kind == yaml.AliasNode {
				value = value.Alias
			}
			if value.Kind == yaml.SequenceNode {
				count = len(value.Content)
			}
		}
	}
	return count, true
}

// validINI accepts what the AWS tools read: sections, comments, assignments
// inside a section, and indented lines continuing an assignment.
func validINI(data []byte) bool {
	section, assigned := false, false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
		case assigned && (raw[0] == ' ' || raw[0] == '\t'):
		case line[0] == '[':
			if !strings.HasSuffix(line, "]") {
				return false
			}
			section, assigned = true, false
		case section && strings.ContainsAny(line, "=:"):
			assigned = true
		default:
			return false
		}
	}
	return true
}

// Only presence metadata is retained in the scanner cache.
func credentialFacts(kind string, data []byte) ([]Credential, error) {
	facts := []Credential{}
	count := 0
	switch kind {
	case "gh_token":
		var hosts map[string]map[string]any
		if yaml.Unmarshal(data, &hosts) != nil {
			return nil, errMalformedCredentials
		}
		host, login := "", ""
		flush := func() {
			if host != "" {
				facts = append(facts, Credential{Detail: 1, Host: pointer(safe(host, 128)), Login: pointer(safe(login, 128))})
			}
		}
		lines := bufio.NewScanner(bytes.NewReader(data))
		lines.Buffer(make([]byte, 4096), maxFileBytes)
		for lines.Scan() {
			line := lines.Text()
			if line != "" && line[0] != ' ' && line[0] != '\t' && strings.HasSuffix(line, ":") {
				flush()
				host = strings.Trim(strings.TrimSuffix(line, ":"), "\"'")
				login = ""
			} else if strings.HasPrefix(strings.TrimSpace(line), "user:") {
				login = strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "user:")), "\"'")
			}
		}
		flush()
	case "aws_credentials", "aws_config_profiles":
		if !validINI(data) {
			return nil, errMalformedCredentials
		}
		for _, line := range bytes.Split(data, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if bytes.HasPrefix(line, []byte("[")) && bytes.HasSuffix(line, []byte("]")) {
				count++
			}
		}
	case "kubeconfig":
		contexts, ok := kubeContexts(data)
		if !ok {
			return nil, errMalformedCredentials
		}
		facts = append(facts, Credential{Detail: contexts})
	case "npm_token":
		for _, line := range bytes.Split(data, []byte("\n")) {
			key, _, ok := bytes.Cut(bytes.TrimSpace(line), []byte("="))
			if ok && bytes.HasSuffix(bytes.TrimSpace(key), []byte("_authToken")) {
				count = 1
				break
			}
		}
	case "docker_config_auth":
		var config struct {
			Auths map[string]json.RawMessage `json:"auths"`
		}
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, err
		}
		count = len(config.Auths)
	}
	if count > 0 {
		facts = append(facts, Credential{Detail: count})
	}
	return facts, nil
}
