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
func (g *guard) credentials(projects []string) {
	ssh := filepath.Join(g.home, ".ssh")
	for _, entry := range g.entries(ssh) {
		if strings.HasPrefix(entry.Name(), "id_") && !strings.HasSuffix(entry.Name(), ".pub") {
			g.credential("ssh_key", filepath.Join(ssh, entry.Name()), 1, "", "")
		}
	}
	gh := filepath.Join(g.home, ".config/gh/hosts.yml")
	if data := g.read(gh); data != nil {
		host, login := "", ""
		flush := func() {
			if host != "" {
				g.credential("gh_token", gh, 1, host, login)
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
	}
	for _, entry := range []struct{ path, kind string }{{".aws/credentials", "aws_credentials"}, {".aws/config", "aws_config_profiles"}} {
		path := filepath.Join(g.home, entry.path)
		if data := g.read(path); data != nil {
			profiles := 0
			for _, line := range bytes.Split(data, []byte("\n")) {
				line = bytes.TrimSpace(line)
				if bytes.HasPrefix(line, []byte("[")) && bytes.HasSuffix(line, []byte("]")) {
					profiles++
				}
			}
			if profiles > 0 {
				g.credential(entry.kind, path, profiles, "", "")
			}
		}
	}
	g.credential("gcloud_adc", filepath.Join(g.home, ".config/gcloud/application_default_credentials.json"), 1, "", "")
	kube := filepath.Join(g.home, ".kube/config")
	if data := g.read(kube); data != nil {
		contexts := 0
		inContexts := false
		for _, line := range strings.Split(string(data), "\n") {
			if line == "contexts:" {
				inContexts = true
				continue
			}
			if inContexts && strings.HasPrefix(line, "- context:") {
				contexts++
			} else if line != "" && line[0] != ' ' && line[0] != '-' {
				inContexts = false
			}
		}
		g.credential("kubeconfig", kube, contexts, "", "")
	}
	npm := filepath.Join(g.home, ".npmrc")
	if data := g.read(npm); data != nil {
		for _, line := range bytes.Split(data, []byte("\n")) {
			key, _, ok := bytes.Cut(bytes.TrimSpace(line), []byte("="))
			if ok && bytes.HasSuffix(bytes.TrimSpace(key), []byte("_authToken")) {
				g.credential("npm_token", npm, 1, "", "")
				break
			}
		}
	}
	docker := filepath.Join(g.home, ".docker/config.json")
	if data := g.read(docker); data != nil {
		var config struct {
			Auths map[string]json.RawMessage `json:"auths"`
		}
		if json.Unmarshal(data, &config) == nil && len(config.Auths) > 0 {
			g.credential("docker_config_auth", docker, len(config.Auths), "", "")
		}
	}
	for _, project := range projects {
		path := filepath.Join(project, ".env")
		if data := g.read(path); data != nil {
			count := 0
			for _, line := range bytes.Split(data, []byte("\n")) {
				key, _, ok := bytes.Cut(line, []byte("="))
				if !ok {
					continue
				}
				name := string(bytes.TrimSpace(key))
				for _, suffix := range []string{"_TOKEN", "_KEY", "_SECRET", "PASSWORD"} {
					if strings.HasSuffix(name, suffix) {
						count++
						break
					}
				}
			}
			if count > 0 {
				g.credential("project_env", path, count, "", "")
			}
		}
	}
}
