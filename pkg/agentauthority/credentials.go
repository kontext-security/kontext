package agentauthority

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
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

// Only presence metadata is retained in the scanner cache.
func credentialFacts(kind string, data []byte) ([]Credential, error) {
	facts := []Credential{}
	count := 0
	switch kind {
	case "gh_token":
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
		for _, line := range bytes.Split(data, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if bytes.HasPrefix(line, []byte("[")) && bytes.HasSuffix(line, []byte("]")) {
				count++
			}
		}
	case "kubeconfig":
		inContexts := false
		for _, line := range strings.Split(string(data), "\n") {
			if line == "contexts:" {
				inContexts = true
				continue
			}
			if inContexts && strings.HasPrefix(line, "- context:") {
				count++
			} else if line != "" && line[0] != ' ' && line[0] != '-' {
				inContexts = false
			}
		}
		facts = append(facts, Credential{Detail: count})
		count = 0
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
