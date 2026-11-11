package managedstream

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/busyfile"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

const (
	InventorySchema = "inventory-sources-v1"

	inventoryStateFile = "inventory-state.json"
	presenceFamily     = "presence"
	// The same per-family bound the authority report applies. With a closed
	// source list this bounds the pending state as a whole.
	maxPendingClaims = 64
)

// Inventory is the per-source outcome block of a report.
type Inventory struct {
	Schema  string                        `json:"schema"`
	Sources []agentauthority.SourceResult `json:"sources"`
}

// InventoryAck is the hosted verdict on one source of one upload.
type InventoryAck struct {
	ID              string `json:"id"`
	Revision        int64  `json:"revision"`
	Outcome         string `json:"outcome"`
	AppliedRevision int64  `json:"applied_revision"`
}

// InventoryHealth is local bookkeeping for `kontext doctor`. Nothing reads it to
// make a decision: a backend outage must not reach discovery or policy.
type InventoryHealth struct {
	LastAttemptAt    string           `json:"last_attempt_at,omitempty"`
	LastCompleteAt   string           `json:"last_complete_at,omitempty"`
	LastUploadAt     string           `json:"last_upload_at,omitempty"`
	AppliedRevisions map[string]int64 `json:"applied_revisions,omitempty"`
	// Presence and authority scans record separately and at different rates, so
	// a complete scan needs every source's latest result to be complete.
	IncompleteSources map[string]bool `json:"incomplete_sources,omitempty"`
}

// sourceClaims holds what one source reported, so that it can be merged with a
// later scan and still reach device.agents and device.authority.
type sourceClaims struct {
	Agent       *agentinventory.Agent       `json:"agent,omitempty"`
	MCPServers  []agentauthority.MCPServer  `json:"mcp_servers,omitempty"`
	Plugins     []agentauthority.Plugin     `json:"plugins,omitempty"`
	Connectors  []agentauthority.Connector  `json:"connectors,omitempty"`
	Permissions *agentauthority.Permissions `json:"permissions,omitempty"`
	Credentials []agentauthority.Credential `json:"credentials,omitempty"`
}

func (c sourceClaims) positive() bool {
	return c.Agent != nil || len(c.MCPServers) > 0 || len(c.Plugins) > 0 || len(c.Connectors) > 0 || c.Permissions != nil || len(c.Credentials) > 0
}

type pendingSource struct {
	Result agentauthority.SourceResult `json:"result"`
	Claims sourceClaims                `json:"claims"`
}

type inventoryFile struct {
	InstallationID string                   `json:"installation_id"`
	Revision       int64                    `json:"revision"`
	Pending        map[string]pendingSource `json:"pending"`
	Health         InventoryHealth          `json:"health"`
}

// InventoryStore holds the revision counter and every result the cloud has not
// acknowledged. Scan loops and the stream writer share it.
type InventoryStore struct {
	mu   sync.Mutex
	path string
	file inventoryFile
}

// InventoryStatePath is the store's place beside the stream's own state.
func InventoryStatePath(streamStatePath string) string {
	return filepath.Join(filepath.Dir(streamStatePath), inventoryStateFile)
}

// OpenInventoryStore starts over when the file is unreadable or belongs to
// another installation: a lost counter recovers from the first stale verdict.
func OpenInventoryStore(path, installationID string) *InventoryStore {
	store := &InventoryStore{path: path}
	if data, err := busyfile.ReadFile(path); err == nil && json.Unmarshal(data, &store.file) == nil && store.file.InstallationID == installationID {
		if store.file.Pending == nil {
			store.file.Pending = map[string]pendingSource{}
		}
		return store
	}
	store.file = inventoryFile{InstallationID: installationID, Pending: map[string]pendingSource{}}
	return store
}

// LoadInventoryHealth reads the bookkeeping only, for doctor.
func LoadInventoryHealth(path string) (InventoryHealth, bool) {
	data, err := busyfile.ReadFile(path)
	if err != nil {
		return InventoryHealth{}, false
	}
	var file inventoryFile
	if json.Unmarshal(data, &file) != nil {
		return InventoryHealth{}, false
	}
	return file.Health, true
}

func (s *InventoryStore) save() error {
	data, err := json.Marshal(s.file)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, append(data, '\n'), ".inventory-state-*.tmp")
}

// RecordAgents takes a new revision for a presence scan.
func (s *InventoryStore) RecordAgents(inv agentinventory.Inventory) error {
	rows := make(map[string]*agentinventory.Agent, len(inv.Agents))
	for i := range inv.Agents {
		rows[inv.Agents[i].ID] = &inv.Agents[i]
	}
	return s.record(inv.Sources, func(agent, _ string) sourceClaims {
		return sourceClaims{Agent: rows[agent]}
	})
}

// RecordAuthority takes a new revision for an authority scan.
func (s *InventoryStore) RecordAuthority(report agentauthority.Report) error {
	rows := make(map[string]agentauthority.Agent, len(report.Agents))
	for _, row := range report.Agents {
		rows[row.ID] = row
	}
	return s.record(report.Sources, func(agent, family string) sourceClaims {
		if agent+"/"+family == agentauthority.HostCredentials {
			return sourceClaims{Credentials: report.Credentials}
		}
		row, ok := rows[agent]
		if !ok {
			return sourceClaims{}
		}
		switch family {
		case "mcp":
			return sourceClaims{MCPServers: row.MCPServers}
		case "plugins":
			return sourceClaims{Plugins: row.Plugins}
		case "connectors":
			return sourceClaims{Connectors: row.Connectors}
		case "permissions":
			if row.Permissions.Observed() {
				permissions := row.Permissions
				return sourceClaims{Permissions: &permissions}
			}
		}
		return sourceClaims{}
	})
}

func (s *InventoryStore) record(results []agentauthority.SourceResult, claimsOf func(agent, family string) sourceClaims) error {
	if len(results) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.file.Revision++
	if s.file.Health.IncompleteSources == nil {
		s.file.Health.IncompleteSources = map[string]bool{}
	}
	// Each batch restates its kind, so a source it no longer reports stops counting.
	presence := isPresence(results[0].ID)
	maps.DeleteFunc(s.file.Health.IncompleteSources, func(id string, _ bool) bool { return isPresence(id) == presence })
	for _, result := range results {
		result.Revision = s.file.Revision
		agent, family, _ := strings.Cut(result.ID, "/")
		entry := pendingSource{Result: result, Claims: claimsOf(agent, family)}
		if prior, ok := s.file.Pending[result.ID]; ok && result.Status != agentauthority.StatusComplete {
			entry = mergePending(prior, entry)
		}
		s.file.Pending[result.ID] = entry
		if result.Status != agentauthority.StatusComplete {
			s.file.Health.IncompleteSources[result.ID] = true
		}
	}
	finished := results[len(results)-1].FinishedAt
	s.file.Health.LastAttemptAt = finished
	if len(s.file.Health.IncompleteSources) == 0 {
		s.file.Health.LastCompleteAt = finished
	}
	return s.save()
}

// mergePending keeps what an unacknowledged result saw when a newer scan could
// not establish the whole source: it may never have reached the server. The
// server dates claims by finished_at, so inherited claims keep the older time
// and their freshness is understated, never overstated.
func mergePending(older, newer pendingSource) pendingSource {
	if older.Claims.positive() {
		newer.Result.Status = agentauthority.StatusPartial
		newer.Result.StartedAt, newer.Result.FinishedAt = older.Result.StartedAt, older.Result.FinishedAt
	}
	newer.Claims = mergeClaims(older.Claims, newer.Claims)
	return newer
}

func mergeClaims(older, newer sourceClaims) sourceClaims {
	merged := sourceClaims{
		Agent:       newer.Agent,
		MCPServers:  mergeByKey(older.MCPServers, newer.MCPServers, mcpKey),
		Plugins:     mergeByKey(older.Plugins, newer.Plugins, pluginKey),
		Connectors:  mergeByKey(older.Connectors, newer.Connectors, func(c agentauthority.Connector) string { return c.UUID }),
		Permissions: mergePermissions(older.Permissions, newer.Permissions),
		Credentials: mergeByKey(older.Credentials, newer.Credentials, credentialKey),
	}
	if merged.Agent == nil {
		merged.Agent = older.Agent
	}
	return merged
}

// mergeByKey lists newer first, so the bound drops the oldest observations.
func mergeByKey[T any](older, newer []T, key func(T) string) []T {
	if len(older) == 0 {
		return newer
	}
	seen := make(map[string]bool, len(newer))
	merged := make([]T, 0, min(len(newer)+len(older), maxPendingClaims))
	for _, list := range [][]T{newer, older} {
		for _, value := range list {
			if k := key(value); !seen[k] && len(merged) < maxPendingClaims {
				seen[k] = true
				merged = append(merged, value)
			}
		}
	}
	return merged
}

func text(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func mcpKey(m agentauthority.MCPServer) string {
	return strings.Join([]string{m.Name, m.Scope, text(m.Project), m.Source}, "\x00")
}

func pluginKey(p agentauthority.Plugin) string {
	return p.Name + "\x00" + text(p.Marketplace)
}

func credentialKey(c agentauthority.Credential) string {
	return strings.Join([]string{c.Kind, c.Path, text(c.Host), text(c.Login)}, "\x00")
}

func mergePermissions(older, newer *agentauthority.Permissions) *agentauthority.Permissions {
	if older == nil {
		return newer
	}
	if newer == nil {
		return older
	}
	merged := *newer
	merged.Allow = mergeByKey(older.Allow, newer.Allow, func(g agentauthority.Grant) string { return g.Pattern })
	if merged.DefaultMode == nil {
		merged.DefaultMode = older.DefaultMode
	}
	if merged.DenyCount == 0 {
		merged.DenyCount = older.DenyCount
	}
	if merged.Sandbox.Enabled == nil {
		merged.Sandbox.Enabled = older.Sandbox.Enabled
	}
	if merged.Sandbox.AllowUnsandboxed == nil {
		merged.Sandbox.AllowUnsandboxed = older.Sandbox.AllowUnsandboxed
	}
	if merged.Sandbox.AllowedDomains == 0 {
		merged.Sandbox.AllowedDomains = older.Sandbox.AllowedDomains
	}
	if merged.Codex == nil {
		merged.Codex = older.Codex
	}
	return &merged
}

func (s *InventoryStore) pendingFor(id string) (pendingSource, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.file.Pending[id]
	return entry, ok
}

// snapshot is safe to read while scans continue: merges build new slices.
func (s *InventoryStore) snapshot() map[string]pendingSource {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := make(map[string]pendingSource, len(s.file.Pending))
	for id, entry := range s.file.Pending {
		copied[id] = entry
	}
	return copied
}

func (s *InventoryStore) hasPendingAuthority() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.file.Pending {
		if !isPresence(id) {
			return true
		}
	}
	return false
}

// acknowledge applies the verdicts on an accepted upload. Only a verdict on the
// revision still pending can clear it: a newer scan may have replaced it while
// the upload was in flight.
func (s *InventoryStore) acknowledge(acks []InventoryAck, sent []agentauthority.SourceResult, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.file.Health.LastUploadAt = now.UTC().Format(time.RFC3339Nano)
	var resend []string
	for _, ack := range acks {
		entry, ok := s.file.Pending[ack.ID]
		current := ok && entry.Result.Revision == ack.Revision
		switch ack.Outcome {
		case "applied", "duplicate":
			if current {
				if s.file.Health.AppliedRevisions == nil {
					s.file.Health.AppliedRevisions = map[string]int64{}
				}
				// Report what the server got: the size bound can lower a result
				// at send time and leave the pending one complete.
				status := entry.Result.Status
				if i := slices.IndexFunc(sent, func(r agentauthority.SourceResult) bool { return r.ID == ack.ID }); i >= 0 {
					status = sent[i].Status
				}
				if ack.Revision > s.file.Health.AppliedRevisions[status] {
					s.file.Health.AppliedRevisions[status] = ack.Revision
				}
				delete(s.file.Pending, ack.ID)
			}
		case "rejected":
			// The same content would fail again; the next scan reports afresh.
			if current {
				delete(s.file.Pending, ack.ID)
			}
		case "stale", "conflict":
			// Above the applied revision is no ordering problem: the result
			// predates an opt-out this endpoint never saw, so a retry cannot pass.
			if ack.Outcome == "stale" && ack.Revision > ack.AppliedRevision {
				if current {
					delete(s.file.Pending, ack.ID)
				}
				continue
			}
			s.file.Revision = max(s.file.Revision, ack.AppliedRevision)
			if current {
				resend = append(resend, ack.ID)
			}
		}
	}
	if len(resend) > 0 {
		s.file.Revision++
		for _, id := range resend {
			entry := s.file.Pending[id]
			entry.Result.Revision = s.file.Revision
			s.file.Pending[id] = entry
		}
	}
	return s.save()
}

// DiscardAuthority forgets pending authority results after an opt-out. The
// server has cleared those claims and rejects anything dated before that, so a
// resumed scan must not inherit them. The counter stays: revisions never repeat.
func (s *InventoryStore) DiscardAuthority() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	authority := func(id string) bool { return !isPresence(id) }
	before := len(s.file.Pending) + len(s.file.Health.IncompleteSources)
	maps.DeleteFunc(s.file.Pending, func(id string, _ pendingSource) bool { return authority(id) })
	maps.DeleteFunc(s.file.Health.IncompleteSources, func(id string, _ bool) bool { return authority(id) })
	if len(s.file.Pending)+len(s.file.Health.IncompleteSources) == before {
		return nil
	}
	return s.save()
}

func isPresence(id string) bool { return strings.HasSuffix(id, "/"+presenceFamily) }

// addInventory states the pending results. A source travels only when its
// claims do, because a complete source without them would withdraw them all.
// The block goes out even when empty: without it the server would read this
// report as an older CLI's and refresh every claim.
func addInventory(payload *Payload, opts Options) {
	device := payload.Device
	if opts.Inventory == nil || device == nil || device.Agents == nil && device.Authority == nil {
		return
	}
	pending := opts.Inventory.snapshot()
	ids := make([]string, 0, len(pending))
	for id := range pending {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if device.Agents != nil {
		overlayAgents(device, pending, ids)
	}
	var trimmed []string
	if device.Authority != nil {
		trimmed = overlayAuthority(device, pending, ids)
	}
	sources := []agentauthority.SourceResult{}
	for _, id := range ids {
		if isPresence(id) && device.Agents == nil || !isPresence(id) && device.Authority == nil {
			continue
		}
		result := pending[id].Result
		if slices.Contains(trimmed, id) {
			result.Status = agentauthority.StatusPartial
			result.Reasons = append(slices.Clone(result.Reasons), agentauthority.ReasonSizeLimit)
		}
		sources = append(sources, result)
	}
	device.Inventory = &Inventory{Schema: InventorySchema, Sources: sources}
}

// overlayAgents makes each pending source's row the one in its result, so a
// result never travels with another scan's claims. The cached scan is shared,
// so it is copied rather than changed.
func overlayAgents(device *Device, pending map[string]pendingSource, ids []string) {
	list := slices.Clone(*device.Agents)
	for _, id := range ids {
		if !isPresence(id) {
			continue
		}
		agent, _, _ := strings.Cut(id, "/")
		index := slices.IndexFunc(list, func(a agentinventory.Agent) bool { return a.ID == agent })
		claimed := pending[id].Claims.Agent
		switch {
		case claimed != nil && index >= 0:
			list[index] = *claimed
		case claimed != nil:
			list = append(list, *claimed)
		case index >= 0:
			list = slices.Delete(list, index, index+1)
		}
	}
	device.Agents = &list
}

func replaceClaims[T any](field *[]T, claims []T, changed *bool) {
	if len(*field) == 0 && len(claims) == 0 || reflect.DeepEqual(*field, claims) {
		return
	}
	*field, *changed = claims, true
	if claims == nil {
		*field = []T{}
	}
}

// overlayAuthority does the same for the report, and returns the sources that
// lost claims to the report's bounds.
func overlayAuthority(device *Device, pending map[string]pendingSource, ids []string) []string {
	report := *device.Authority
	report.Agents = slices.Clone(report.Agents)
	changed := false
	for _, id := range ids {
		entry := pending[id]
		if isPresence(id) {
			continue
		}
		if id == agentauthority.HostCredentials {
			replaceClaims(&report.Credentials, entry.Claims.Credentials, &changed)
			continue
		}
		agent, family, _ := strings.Cut(id, "/")
		index := slices.IndexFunc(report.Agents, func(a agentauthority.Agent) bool { return a.ID == agent })
		if index < 0 {
			if !entry.Claims.positive() {
				continue
			}
			report.Agents = append(report.Agents, agentauthority.Agent{ID: agent, MCPServers: []agentauthority.MCPServer{}, Plugins: []agentauthority.Plugin{}, Permissions: agentauthority.Permissions{Allow: []agentauthority.Grant{}}})
			index = len(report.Agents) - 1
		}
		row := &report.Agents[index]
		switch family {
		case "mcp":
			replaceClaims(&row.MCPServers, entry.Claims.MCPServers, &changed)
		case "plugins":
			replaceClaims(&row.Plugins, entry.Claims.Plugins, &changed)
		case "connectors":
			replaceClaims(&row.Connectors, entry.Claims.Connectors, &changed)
		case "permissions":
			claimed := agentauthority.Permissions{Allow: []agentauthority.Grant{}}
			if entry.Claims.Permissions != nil {
				claimed = *entry.Claims.Permissions
			}
			if !reflect.DeepEqual(claimed, row.Permissions) {
				row.Permissions, changed = claimed, true
			}
		}
	}
	if !changed {
		return nil
	}
	trimmed := report.Seal()
	device.Authority = &report
	return trimmed
}

// dropAuthority removes the optional report together with its sources.
func dropAuthority(payload *Payload) {
	payload.Device.Authority = nil
	if inventory := payload.Device.Inventory; inventory != nil {
		inventory.Sources = slices.DeleteFunc(inventory.Sources, func(r agentauthority.SourceResult) bool { return !isPresence(r.ID) })
	}
}

func ackInventory(opts Options, payload Payload, result ingestResult, now time.Time) {
	if opts.Inventory == nil || payload.Device == nil || payload.Device.Inventory == nil || len(payload.Device.Inventory.Sources) == 0 {
		return
	}
	if err := opts.Inventory.acknowledge(result.InventorySources, payload.Device.Inventory.Sources, now); err != nil {
		opts.Diagnostic.Printf("managed stream inventory state: %v\n", err)
	}
}

// writeFileAtomic never leaves a torn file behind, so a crash cannot lose the
// revision counter along with the write that advanced it.
func writeFileAtomic(path string, data []byte, tempPattern string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), tempPattern)
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	if err := errors.Join(temp.Chmod(0o600), writeAndClose(temp, data)); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	if err := busyfile.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return nil
}

func writeAndClose(file *os.File, data []byte) error {
	_, err := file.Write(data)
	return errors.Join(err, file.Close())
}
