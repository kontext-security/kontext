package browserevents

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/fsperm"
)

// Store limits. Days older than KeepDays are pruned, and the store holds at
// most MaxRows rows; when it is full, new rows are refused rather than old
// ones dropped, so what was recorded first still reaches the cloud.
const (
	KeepDays = 8
	MaxRows  = 2000
)

// row is one snapshot: a visit per browser, profile, app and day, or the
// health of a browser profile. Version counts its changes, so a row that
// changed while its batch was in flight stays to be sent again.
type row struct {
	Record  CloudRecord `json:"record"`
	Version int         `json:"version"`
	Sent    int         `json:"sent"`
}

type storeFile struct {
	// Binding names the enrollment the rows were recorded under: a hash of
	// the cloud, installation and install token. Rows never leave under
	// another one.
	Binding string          `json:"binding,omitempty"`
	Rows    map[string]*row `json:"rows"`
}

// Store keeps the extension's records as snapshots until the cloud has them,
// in one JSON file written atomically and readable by the user only. A
// snapshot replaces what it updates, so a record sent twice changes nothing.
type Store struct {
	path string
	now  func() time.Time

	mu      sync.Mutex
	rows    map[string]*row
	binding string
	// dirty is set while the file is behind the rows, such as after a failed
	// save, so the next call saves again rather than report success.
	dirty bool
}

// OpenStore reads the store at path; a missing file is an empty store and an
// unreadable one starts over, since its rows are snapshots the extension
// sends again.
func OpenStore(path string) (*Store, error) {
	return openStore(path, time.Now)
}

func openStore(path string, now func() time.Time) (*Store, error) {
	s := &Store{path: path, now: now, rows: map[string]*row{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var file storeFile
	if json.Unmarshal(data, &file) == nil && file.Rows != nil {
		s.rows = file.Rows
		s.binding = file.Binding
	}
	if s.pruneLocked() {
		// Days past KeepDays leave the disk now, not at the next message.
		if err := s.saveLocked(); err != nil {
			s.dirty = true
		}
	}
	return s, nil
}

// DefaultStorePath is the store beside the daemon's database.
func DefaultStorePath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "browser-activity.json")
}

func rowKey(r CloudRecord) string {
	if r.Kind == KindHealth {
		return r.Browser + "|" + r.Profile + "|health"
	}
	return r.Browser + "|" + r.Profile + "|visit|" + r.App + "|" + r.Day
}

// Apply merges valid records from one extension into the store and returns
// the ones it could not keep.
func (s *Store) Apply(ext Extension, records []IndexedRecord) ([]Rejection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := s.pruneLocked()
	var rejected []Rejection
	for _, indexed := range records {
		record := CloudRecord{Browser: ext.Browser, Profile: ext.Profile, ExtensionVersion: ext.Version, Record: indexed.Record}
		if record.Kind == KindVisit && !s.recentDay(record.Day) {
			rejected = append(rejected, Rejection{Index: indexed.Index, Reason: "visit day is too old or in the future"})
			continue
		}
		key := rowKey(record)
		current, ok := s.rows[key]
		if !ok {
			if len(s.rows) >= MaxRows {
				rejected = append(rejected, Rejection{Index: indexed.Index, Reason: "daemon store is full"})
				continue
			}
			s.rows[key] = &row{Record: record, Version: 1}
			changed = true
			continue
		}
		if merged, differs := merge(current.Record, record); differs {
			current.Record = merged
			current.Version++
			changed = true
		}
	}
	if !changed && !s.dirty {
		return rejected, nil
	}
	return rejected, s.saveLocked()
}

// merge keeps the widest view of a day: the earliest first sight, the latest
// last sight and the highest count, so replays and out-of-order messages
// cannot lower it. Health keeps the newest observation.
func merge(current, next CloudRecord) (CloudRecord, bool) {
	merged := current
	merged.ExtensionVersion = next.ExtensionVersion
	switch current.Kind {
	case KindHealth:
		if later(next.ObservedAt, current.ObservedAt) {
			merged.ObservedAt = next.ObservedAt
			merged.ConnectedSince = next.ConnectedSince
		}
	case KindVisit:
		if later(current.FirstSeen, next.FirstSeen) {
			merged.FirstSeen = next.FirstSeen
		}
		if later(next.LastSeen, current.LastSeen) {
			merged.LastSeen = next.LastSeen
		}
		if next.Requests > current.Requests {
			merged.Requests = next.Requests
		}
		merged.AppName, merged.Provider, merged.Host = next.AppName, next.Provider, next.Host
	}
	return merged, merged != current
}

func later(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339, a)
	tb, errB := time.Parse(time.RFC3339, b)
	return errA == nil && errB == nil && ta.After(tb)
}

func (s *Store) recentDay(day string) bool {
	d, err := time.Parse(time.DateOnly, day)
	if err != nil {
		return false
	}
	today := s.now().UTC().Truncate(24 * time.Hour)
	return !d.After(today.Add(24*time.Hour)) && today.Sub(d) < KeepDays*24*time.Hour
}

// pruneLocked drops days past KeepDays and says whether it dropped any.
func (s *Store) pruneLocked() bool {
	pruned := false
	for key, r := range s.rows {
		if r.Record.Kind == KindVisit && !s.recentDay(r.Record.Day) {
			delete(s.rows, key)
			pruned = true
		}
	}
	return pruned
}

// Pending is a batch to send: the rows that changed since the cloud last had
// them, oldest days first, at most max.
type Pending struct {
	Records  []CloudRecord
	keys     []string
	versions []int
}

// Pending returns the rows to send.
func (s *Store) Pending(max int) Pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pruneLocked() {
		s.dirty = true
	}
	var keys []string
	for key, r := range s.rows {
		if r.Version != r.Sent {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	sort.SliceStable(keys, func(i, j int) bool { return s.rows[keys[i]].Record.Day < s.rows[keys[j]].Record.Day })
	if len(keys) > max {
		keys = keys[:max]
	}
	var p Pending
	for _, key := range keys {
		p.Records = append(p.Records, s.rows[key].Record)
		p.keys = append(p.keys, key)
		p.versions = append(p.versions, s.rows[key].Version)
	}
	return p
}

// Ack marks a batch as delivered. Rejected records are marked too: the cloud
// will not take them, so sending them again changes nothing. A row that
// changed since the batch was taken stays pending.
func (s *Store) Ack(p Pending) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, key := range p.keys {
		if r, ok := s.rows[key]; ok && r.Version == p.versions[i] {
			r.Sent = r.Version
		}
	}
	return s.saveLocked()
}

// Bind ties the store to the enrollment it sends under. The first binding is
// kept; another one drops every row, since they were recorded for an
// enrollment that may belong to another workspace, and reports it.
func (s *Store) Bind(binding string) (dropped int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.binding {
	case binding:
		return 0, nil
	case "":
	default:
		dropped = len(s.rows)
		s.rows = map[string]*row{}
	}
	s.binding = binding
	return dropped, s.saveLocked()
}

// Len is the number of rows.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rows)
}

// saveLocked writes the rows. Until a write succeeds the store stays dirty.
func (s *Store) saveLocked() error {
	s.dirty = true
	data, err := json.Marshal(storeFile{Binding: s.binding, Rows: s.rows})
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".browser-activity-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// Owner-only on every OS: mode bits on Unix, a protected DACL on Windows.
	if err := fsperm.RestrictFile(tmp); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("browser events: save store: %w", err)
	}
	s.dirty = false
	return nil
}
