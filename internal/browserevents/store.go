package browserevents

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
	// MaxStoreBytes bounds the file read at startup. MaxRows rows are far
	// below it; a larger file is damaged and starts over.
	MaxStoreBytes = 16 << 20
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
	// generation counts the bindings, so an answer for rows of an earlier
	// one never marks rows of a later one, even under the same binding.
	generation uint64
	// suspended is set while the current enrollment cannot be confirmed,
	// such as when the configuration names another cloud: no record is
	// taken and the extension is told there is no enrollment.
	suspended bool
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
	removeLeftovers(path)
	data, private, trusted, err := readStoreFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if errors.Is(err, errOversizedStore) {
		// Far larger than MaxRows rows: start over, and the next save
		// replaces it. The extension sends its snapshots again.
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var file storeFile
	// A file that is not owner-only, such as one restored from a backup,
	// may have been changed by another account: its rows are not read,
	// so none of them can leave with this enrollment's token.
	if trusted && json.Unmarshal(data, &file) == nil && file.Rows != nil && file.Binding != "" {
		// Rows without a binding cannot say which workspace they belong
		// to, so they are not read: Bind would otherwise give them to the
		// current one.
		// A damaged file can hold null rows; they are dropped, not read.
		for key, r := range file.Rows {
			if r == nil {
				delete(file.Rows, key)
			}
		}
		// A row the contract no longer allows, sent or not, leaves the
		// disk at open: its text is not kept until it ages out.
		for key, r := range file.Rows {
			source := Extension{Version: r.Record.ExtensionVersion, Browser: r.Record.Browser, Profile: r.Record.Profile}
			if source.validate() != nil || r.Record.Record.Validate() != nil {
				delete(file.Rows, key)
				private = false // written again below
			}
		}
		s.rows = file.Rows
		s.binding = file.Binding
		s.generation = 1
	}
	// A file others can read, such as one restored from a backup, is
	// written again at once: a save makes a private file.
	if s.pruneLocked() || !private {
		// Days past KeepDays leave the disk now, not at the next message.
		if err := s.saveLocked(); err != nil {
			if !private {
				// Others could read the file and it cannot be replaced:
				// it is not used.
				return nil, fmt.Errorf("browser events: store %s is not private and cannot be rewritten: %w", path, err)
			}
			s.dirty = true
		}
	}
	return s, nil
}

var errOversizedStore = errors.New("browser events: store file is too large")

// readStoreFile reads the store without blocking on a FIFO or reading a file
// of any size: startup waits for it, and hooks start only after it.
func readStoreFile(path string) (data []byte, private, trusted bool, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, false, false, err
	}
	if !info.Mode().IsRegular() {
		// A FIFO would block startup; a folder or link is not ours.
		return nil, false, false, fmt.Errorf("browser events: store %s is not a regular file", path)
	}
	if info.Size() > MaxStoreBytes {
		return nil, false, false, errOversizedStore
	}
	// The file can change between Lstat and open, so the opened file is
	// checked again, and opening it never waits.
	f, err := os.OpenFile(path, os.O_RDONLY|openNoBlock, 0)
	if err != nil {
		return nil, false, false, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, false, false, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, false, false, fmt.Errorf("browser events: store %s changed while it was opened", path)
	}
	private, err = fsperm.PrivateFile(path, opened)
	if err != nil {
		// Unknown counts as not private: the next save fixes it.
		private = false
	}
	// Rows are read from a private file, or one only its owner can use at
	// all, such as a backup restored read-only: no other account could
	// have changed it. The second is still written again private.
	trusted = private || onlyOwnerMode(opened)
	data, err = io.ReadAll(io.LimitReader(f, MaxStoreBytes+1))
	if err != nil {
		return nil, false, false, err
	}
	if len(data) > MaxStoreBytes {
		return nil, false, false, errOversizedStore
	}
	return data, private, trusted, nil
}

// tempPattern names the store's temporary files after the store, so a
// leftover from a crash is found and removed at the next open.
func tempPattern(path string) string {
	return "." + filepath.Base(path) + "-*.tmp"
}

// removeLeftovers deletes temporary copies a crash left beside the store:
// they hold rows that would never be pruned.
func removeLeftovers(path string) {
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	// Matched literally: the database name may hold glob characters. Only
	// the names CreateTemp makes, a uint32 in decimal in place of the star,
	// are removed.
	prefix := "." + filepath.Base(path) + "-"
	for _, entry := range entries {
		name := entry.Name()
		random, ok := strings.CutPrefix(name, prefix)
		if ok {
			random, ok = strings.CutSuffix(random, ".tmp")
		}
		if entry.Type().IsRegular() && ok && isTempSuffix(random) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

// DefaultStorePath is the store beside the daemon's database, named after
// it, so two daemons with their own databases in one folder keep their own
// stores.
func DefaultStorePath(dbPath string) string {
	return dbPath + ".browser-activity.json"
}

func rowKey(r CloudRecord) string {
	if r.Kind == KindHealth {
		return r.Browser + "|" + r.Profile + "|health"
	}
	if r.Kind == KindAccount {
		// Each type seen that day has its row, so a personal account used
		// beside a company one is not hidden by whichever came last.
		return r.Browser + "|" + r.Profile + "|account|" + r.App + "|" + r.Day + "|" + r.AccountType
	}
	return r.Browser + "|" + r.Profile + "|" + r.Kind + "|" + r.App + "|" + r.Day
}

// Applied is what Apply did: the records it could not keep, and the
// enrollment it checked them against, which the answer must name so the
// extension learns the one its records were judged by.
type Applied struct {
	Rejected   []Rejection
	Enrollment string
}

// Apply merges valid records from one extension into the store. enrollment is
// the id the extension recorded under: records sent for another enrollment are
// all refused, so nothing counted for one workspace reaches another, and the
// extension learns the current id from the answer.
func (s *Store) Apply(ext Extension, enrollment string, records []IndexedRecord) (Applied, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := s.pruneLocked()
	if changed {
		// Expired rows leave the disk at the next save, even when this
		// message is refused below.
		s.dirty = true
	}
	current := s.enrollmentLocked()
	refuseAll := func(reason string) Applied {
		applied := Applied{Enrollment: current}
		for _, indexed := range records {
			applied.Rejected = append(applied.Rejected, Rejection{Index: indexed.Index, Reason: reason})
		}
		return applied
	}
	if s.suspended {
		// The enrollment is not confirmed, not changed: an empty enrollment
		// in the answer would tell the extension to discard its counts.
		return Applied{}, ErrSuspended
	}
	if s.binding == "" {
		// Until the store knows its enrollment, a record could later leave
		// under another workspace's token, so none is taken.
		return refuseAll("daemon is not enrolled yet"), nil
	}
	if enrollment != current {
		return refuseAll("recorded for another enrollment"), nil
	}
	applied := Applied{Enrollment: current}
	// What each changed row was before, so a message whose save fails is
	// taken back: the extension is told unavailable and rolls back, and
	// the row must not go out as if it had been taken.
	undo := map[string]*row{}
	keep := func(key string, before *row) {
		if _, seen := undo[key]; seen {
			return
		}
		if before == nil {
			undo[key] = nil
			return
		}
		copied := *before
		undo[key] = &copied
	}
	for _, indexed := range records {
		record := CloudRecord{Browser: ext.Browser, Profile: ext.Profile, ExtensionVersion: ext.Version, Record: indexed.Record}
		if (record.Kind == KindVisit || record.Kind == KindAccount) && !s.recentDay(record.Day) {
			applied.Rejected = append(applied.Rejected, Rejection{Index: indexed.Index, Reason: record.Kind + " day is too old or in the future"})
			continue
		}
		if record.Kind == KindAccount && !s.notAhead(record.ObservedAt) {
			// The newest observation of a type wins its day, so one from a
			// clock running ahead would hide every true one after it.
			applied.Rejected = append(applied.Rejected, Rejection{Index: indexed.Index, Reason: "account observed_at is in the future"})
			continue
		}
		if record.Kind == KindHealth && !s.recentObservation(record.ObservedAt) {
			applied.Rejected = append(applied.Rejected, Rejection{Index: indexed.Index, Reason: "health observed_at is too old or in the future"})
			continue
		}
		key := rowKey(record)
		existing, ok := s.rows[key]
		if !ok {
			if len(s.rows) >= MaxRows {
				applied.Rejected = append(applied.Rejected, Rejection{Index: indexed.Index, Reason: "daemon store is full"})
				continue
			}
			keep(key, nil)
			s.rows[key] = &row{Record: record, Version: 1}
			changed = true
			continue
		}
		if merged, differs := merge(existing.Record, record); differs {
			keep(key, existing)
			existing.Record = merged
			existing.Version++
			changed = true
		}
	}
	if !changed && !s.dirty {
		return applied, nil
	}
	if err := s.saveLocked(); err != nil {
		for key, before := range undo {
			if before == nil {
				delete(s.rows, key)
				continue
			}
			*s.rows[key] = *before
		}
		return Applied{}, err
	}
	return applied, nil
}

// merge keeps the widest view of a day: the earliest first sight, the latest
// last sight and the highest count, so replays and out-of-order messages
// cannot lower it. Health keeps the newest observation. The extension
// version, and a visit's name, provider and host, come with the newest
// snapshot, so an older one replayed after an upgrade changes none of them.
func merge(current, next CloudRecord) (CloudRecord, bool) {
	merged := current
	switch current.Kind {
	case KindHealth:
		if later(next.ObservedAt, current.ObservedAt) {
			merged.ObservedAt = next.ObservedAt
			merged.ConnectedSince = next.ConnectedSince
			merged.ExtensionVersion = next.ExtensionVersion
		}
	case KindVisit:
		if later(current.FirstSeen, next.FirstSeen) {
			merged.FirstSeen = next.FirstSeen
		}
		if !later(current.LastSeen, next.LastSeen) {
			merged.AppName, merged.Provider, merged.Host = next.AppName, next.Provider, next.Host
			merged.ExtensionVersion = next.ExtensionVersion
		}
		if later(next.LastSeen, current.LastSeen) {
			merged.LastSeen = next.LastSeen
		}
		if next.Requests > current.Requests {
			merged.Requests = next.Requests
		}
		if next.Messages > current.Messages {
			merged.Messages = next.Messages
		}
	case KindAccount:
		// The newest observation of that type on the day.
		if later(next.ObservedAt, current.ObservedAt) {
			merged = next
		}
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

// MaxClockAhead is how far ahead of the daemon's clock an account may be
// observed, the same allowance the cloud gives.
const MaxClockAhead = 10 * time.Minute

// notAhead reports whether observed is at most MaxClockAhead after now.
func (s *Store) notAhead(observed string) bool {
	at, err := time.Parse(time.RFC3339, observed)
	return err == nil && !at.After(s.now().Add(MaxClockAhead))
}

// recentObservation reports whether observed is within KeepDays before now,
// and at most a day after it, so a clock far ahead cannot keep a row forever.
func (s *Store) recentObservation(observed string) bool {
	at, err := time.Parse(time.RFC3339, observed)
	if err != nil {
		return false
	}
	now := s.now()
	return !at.After(now.Add(24*time.Hour)) && now.Sub(at) < KeepDays*24*time.Hour
}

// pruneLocked drops visits of days past KeepDays, and the health of
// profiles not seen for KeepDays, such as deleted ones, so they cannot fill
// the store. It says whether it dropped any.
func (s *Store) pruneLocked() bool {
	pruned := false
	for key, r := range s.rows {
		if s.expired(r.Record) {
			delete(s.rows, key)
			pruned = true
		}
	}
	return pruned
}

func (s *Store) expired(r CloudRecord) bool {
	switch r.Kind {
	case KindVisit, KindAccount:
		return !s.recentDay(r.Day)
	case KindHealth:
		return !s.recentObservation(r.ObservedAt)
	default:
		return true
	}
}

// Pending is a batch to send: the rows that changed since the cloud last had
// them, oldest days first, at most max.
type Pending struct {
	Records  []CloudRecord
	keys     []string
	versions []int
	// binding is the enrollment the rows were taken under. A batch is sent
	// only with that enrollment's token, and acknowledged only while the
	// store is still in the same binding.
	binding    string
	generation uint64
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
	p := Pending{binding: s.binding, generation: s.generation}
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
	if p.binding != s.binding || p.generation != s.generation {
		// The store was bound again while the batch was out: its rows are
		// gone, and a row with the same key is another one.
		return nil
	}
	for i, key := range p.keys {
		if r, ok := s.rows[key]; ok && r.Version == p.versions[i] {
			r.Sent = r.Version
		}
	}
	return s.saveLocked()
}

// Drop removes rows the contract no longer allows, so their text leaves the
// disk and they stop taking room. A row that changed since the batch was
// taken stays.
func (s *Store) Drop(p Pending) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.binding != s.binding || p.generation != s.generation {
		return nil
	}
	for i, key := range p.keys {
		if r, ok := s.rows[key]; ok && r.Version == p.versions[i] {
			delete(s.rows, key)
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
	s.suspended = false
	switch s.binding {
	case binding:
		return 0, nil
	case "":
	default:
		dropped = len(s.rows)
		s.rows = map[string]*row{}
	}
	s.binding = binding
	s.generation++
	return dropped, s.saveLocked()
}

// Suspend stops the store taking records until the next Bind, for when the
// current enrollment cannot be confirmed. Its rows stay: they belong to the
// binding they were taken under and leave only with its token.
func (s *Store) Suspend() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.suspended = true
}

// Flush writes the store if the file is behind it, such as after a prune
// with nothing to send or a failed save.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pruneLocked() {
		s.dirty = true
	}
	if !s.dirty {
		return nil
	}
	return s.saveLocked()
}

// ErrSuspended is Apply's answer while the store cannot confirm the
// enrollment it is bound to. The extension is told the daemon is
// unavailable, so it keeps its counts until the enrollment is known again.
var ErrSuspended = errors.New("browser events: the enrollment cannot be confirmed")

// Confirmed returns the enrollment and whether it is confirmed now, in one
// read, so a suspension between two reads cannot answer an empty enrollment.
func (s *Store) Confirmed() (enrollment string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binding != "" && s.suspended {
		return "", false
	}
	return s.enrollmentLocked(), true
}

// Enrollment is the opaque id of the enrollment the store records under, as
// the extension gets it, or "" while the store is unbound. It is derived
// from the binding and reveals nothing of the token.
func (s *Store) Enrollment() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enrollmentLocked()
}

func (s *Store) enrollmentLocked() string {
	if s.binding == "" || s.suspended {
		return ""
	}
	sum := sha256.Sum256([]byte("browser-enrollment\n" + s.binding))
	return hex.EncodeToString(sum[:8])
}

// Bound says whether the store knows its enrollment.
func (s *Store) Bound() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.binding != ""
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
	tmp, err := os.CreateTemp(dir, tempPattern(s.path))
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
	// The extension is told a record was taken once this returns, so the
	// file is on disk before the rename, and the rename before the answer.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("browser events: save store: %w", err)
	}
	// Until the rename is durable the store stays dirty, and the extension
	// is not told its records were taken.
	if err := fsperm.SyncDir(dir); err != nil {
		return fmt.Errorf("browser events: sync store folder: %w", err)
	}
	s.dirty = false
	return nil
}

func isTempSuffix(s string) bool {
	n, err := strconv.ParseUint(s, 10, 32)
	return err == nil && strconv.FormatUint(n, 10) == s
}
