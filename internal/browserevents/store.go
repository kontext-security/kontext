package browserevents

import (
	"bytes"
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
	"sync/atomic"
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

// counter decodes a stored delivery counter; null, missing or not an int is
// damaged.
func counter(raw json.RawMessage, into *int) bool {
	var n *int
	if json.Unmarshal(raw, &n) != nil || n == nil {
		return false
	}
	*into = *n
	return true
}

// maxRowVersion bounds a stored row's version, so a damaged one can never
// overflow when the row changes again.
const maxRowVersion = 1 << 30

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
	// epoch counts every Bind and Suspend, so a token read that started
	// before a later one never undoes it. It is changed under mu but read
	// without it, so a caller never waits for a slow save to learn it.
	epoch atomic.Uint64
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
		// Far larger than MaxRows rows: start over. The extension sends
		// its snapshots again. A file others can read is replaced now, or
		// not used; a private one is replaced by the next save.
		if !private {
			var committed *committedError
			if err := s.saveLocked(); err != nil && !errors.As(err, &committed) {
				return nil, fmt.Errorf("browser events: store %s is not private and cannot be rewritten: %w", path, err)
			}
		}
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var file struct {
		Binding string                     `json:"binding"`
		Rows    map[string]json.RawMessage `json:"rows"`
	}
	rewrite := false
	// A file that is not owner-only, such as one restored from a backup,
	// may have been changed by another account: its rows are not read,
	// so none of them can leave with this enrollment's token.
	if trusted && json.Unmarshal(data, &file) == nil && file.Rows != nil && file.Binding != "" {
		// Rows without a binding cannot say which workspace they belong
		// to, so they are not read: Bind would otherwise give them to the
		// current one.
		// A row id given twice decodes as its last row: the file is
		// written again, so the first one's text leaves the disk.
		if hasDuplicateKeys(data) {
			rewrite = true
		}
		rows := make(map[string]*row, len(file.Rows))
		for key, raw := range file.Rows {
			// Each row is read on its own: a damaged or null one is
			// dropped, and the others are kept.
			var stored *struct {
				Record  *CloudRecord    `json:"record"`
				Version json.RawMessage `json:"version"`
				Sent    json.RawMessage `json:"sent"`
			}
			if json.Unmarshal(raw, &stored) != nil || stored == nil || stored.Record == nil {
				rewrite = true
				continue
			}
			r := &row{Record: *stored.Record}
			// Damaged delivery counters cannot say what was sent: the
			// row is sent again, which changes nothing in the cloud,
			// rather than taken as delivered and never sent. No answer
			// in flight outlives the open, so 1 and 0 are safe.
			if !counter(stored.Version, &r.Version) || !counter(stored.Sent, &r.Sent) ||
				r.Version < 1 || r.Version > maxRowVersion || r.Sent < 0 || r.Sent > r.Version {
				r.Version, r.Sent = 1, 0
				rewrite = true
			}
			// A row the contract no longer allows, sent or not, leaves
			// the disk at open: its text is not kept until it ages out.
			// A row under another row's key would take that row's
			// snapshots: it is dropped too.
			source := Extension{Version: r.Record.ExtensionVersion, Browser: r.Record.Browser, Profile: r.Record.Profile}
			if source.validate() != nil || r.Record.Record.Validate() != nil || rowKey(r.Record) != key || !storedKeysAllowed(raw, r.Record.Kind) {
				rewrite = true
				continue
			}
			rows[key] = r
		}
		s.rows = rows
		s.binding = file.Binding
		s.generation = 1
	}
	// A file others can read, such as one restored from a backup, is
	// written again at once: a save makes a private file.
	pruned := s.pruneLocked()
	// A restored file can hold more rows than the store takes: after
	// retention, the oldest leave, so new profiles are not refused until
	// they expire.
	if len(s.rows) > MaxRows {
		trimRows(s.rows)
		rewrite = true
	}
	if pruned || rewrite || !private {
		// Days past KeepDays leave the disk now, not at the next message.
		var committed *committedError
		if err := s.saveLocked(); err != nil && !errors.As(err, &committed) {
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
	// An elevated daemon of this user can leave the file owned by
	// Administrators; its DACL still grants this user alone.
	private, err = fsperm.PrivateFileAnyOwner(path, opened)
	if err != nil {
		// Unknown is not unsafe: the file is left as it is, unread, rather
		// than replaced by an empty store.
		return nil, false, false, fmt.Errorf("browser events: store %s permissions: %w", path, err)
	}
	// Only a file whose permissions are known is replaced for its size.
	if opened.Size() > MaxStoreBytes {
		return nil, private, false, errOversizedStore
	}
	// Rows are read from a private file, or one only its owner could have
	// written, such as a backup restored 0644 or 0400: no other account
	// could have changed it. It is still written again private.
	trusted = trustedFile(private, opened)
	data, err = io.ReadAll(io.LimitReader(f, MaxStoreBytes+1))
	if err != nil {
		return nil, false, false, err
	}
	if len(data) > MaxStoreBytes {
		return nil, private, false, errOversizedStore
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

// storedKeysAllowed reports whether a stored row has only a row's keys and,
// for an account, its record only an account's keys and its source's.
// Decoding drops an unknown key, such as an address restored from a backup,
// without telling: the row is dropped instead, so the file is rewritten
// without it.
func storedKeysAllowed(raw json.RawMessage, kind string) bool {
	// A key given twice is decoded as its last value: the row could read
	// one way here and another way to any other reader.
	if hasDuplicateKeys(raw) {
		return false
	}
	var wrapper map[string]json.RawMessage
	if json.Unmarshal(raw, &wrapper) != nil {
		return false
	}
	for key := range wrapper {
		if key != "record" && key != "version" && key != "sent" {
			return false
		}
	}
	if kind != KindAccount {
		return true
	}
	var stored struct {
		Record map[string]json.RawMessage `json:"record"`
	}
	if json.Unmarshal(raw, &stored) != nil {
		return false
	}
	for key := range stored.Record {
		if !accountKeys[key] && key != "browser" && key != "profile" && key != "extension_version" {
			return false
		}
	}
	return true
}

// hasDuplicateKeys reports whether any object in raw, at any depth, names
// a key twice, or raw is not valid JSON.
func hasDuplicateKeys(raw json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// One entry per open object or array: the keys seen so far, nil for an
	// array.
	var open []map[string]bool
	// Whether the next string token in the innermost object is a key.
	expectKey := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return false
		}
		if err != nil {
			return true
		}
		inObject := len(open) > 0 && open[len(open)-1] != nil
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				open = append(open, map[string]bool{})
				expectKey = true
			case '[':
				open = append(open, nil)
				expectKey = false
			default:
				open = open[:len(open)-1]
				expectKey = len(open) > 0 && open[len(open)-1] != nil
			}
			continue
		case string:
			if inObject && expectKey {
				keys := open[len(open)-1]
				if keys[t] {
					return true
				}
				keys[t] = true
				expectKey = false
				continue
			}
		}
		// A value: in an object, a key comes next.
		expectKey = inObject
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
		var committed *committedError
		if errors.As(err, &committed) {
			// On disk already: taken back in memory, it would come back at
			// the next start.
			return applied, nil
		}
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
	case KindVisit:
		return !s.recentDay(r.Day)
	case KindAccount:
		// Also one too far ahead, as Apply refuses: from a restored file,
		// or kept while the clock was set back. Its newer time would hide
		// every later observation of that type, and the cloud refuses it.
		return !s.recentDay(r.Day) || !s.notAhead(r.ObservedAt)
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
	return s.PendingExcept(max, nil)
}

// PendingExcept returns the rows to send, leaving out those held says are
// waiting, so rows held back never take a batch from the rows behind them.
func (s *Store) PendingExcept(max int, held func(key string, version int) bool) Pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pruneLocked() {
		s.dirty = true
	}
	var keys []string
	for key, r := range s.rows {
		if r.Version != r.Sent && (held == nil || !held(key, r.Version)) {
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
		// The record too, not only its version: a row pruned while the
		// batch was out, such as an account ahead of a clock set back, and
		// recorded again under the same key starts again at version 1.
		if r, ok := s.rows[key]; ok && r.Version == p.versions[i] && r.Record == p.Records[i] {
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
		if r, ok := s.rows[key]; ok && r.Version == p.versions[i] && r.Record == p.Records[i] {
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
	return s.bindLocked(binding)
}

// BindAt binds as Bind does only if no Bind or Suspend has happened since
// Epoch returned epoch. A token read that started before a later suspension
// cannot undo it: ok is false and the store stays as it is.
func (s *Store) BindAt(binding string, epoch uint64) (dropped int, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch.Load() != epoch {
		return 0, false, nil
	}
	dropped, err = s.bindLocked(binding)
	return dropped, true, err
}

func (s *Store) bindLocked(binding string) (dropped int, err error) {
	s.suspended = false
	s.epoch.Add(1)
	switch s.binding {
	case binding:
		// A switch whose save failed is not confirmed until it is on
		// disk: otherwise a restart under the old binding brings its rows
		// back.
		if !s.dirty {
			return 0, nil
		}
	case "":
	default:
		dropped = len(s.rows)
		s.rows = map[string]*row{}
	}
	if s.binding != binding {
		s.binding = binding
		s.generation++
	}
	var committed *committedError
	if err := s.saveLocked(); err != nil && !errors.As(err, &committed) {
		// Not on disk: nothing is taken under the new binding yet.
		s.suspended = true
		return dropped, err
	}
	return dropped, nil
}

// Suspend stops the store taking records until the next Bind, for when the
// current enrollment cannot be confirmed. Its rows stay: they belong to the
// binding they were taken under and leave only with its token.
func (s *Store) Suspend() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.suspended = true
	s.epoch.Add(1)
}

// SuspendAt suspends as Suspend does only if no Bind or Suspend has happened
// since Epoch returned epoch, so a caller that gave up waiting does not
// suspend an enrollment confirmed in the meantime.
func (s *Store) SuspendAt(epoch uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch.Load() != epoch {
		return false
	}
	s.suspended = true
	s.epoch.Add(1)
	return true
}

// Epoch returns the count of Bind and Suspend calls so far, for BindAt and
// SuspendAt.
func (s *Store) Epoch() uint64 {
	return s.epoch.Load()
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
		// The new file is in place and a restart reads it: this save
		// counts as done, so the answer agrees with what is on disk. The
		// store stays dirty and the next save syncs again.
		return &committedError{err}
	}
	s.dirty = false
	return nil
}

// committedError is a save whose file is in place but whose folder could not
// be synced.
type committedError struct{ err error }

func (e *committedError) Error() string {
	return "browser events: sync store folder: " + e.err.Error()
}

func (e *committedError) Unwrap() error { return e.err }

func isTempSuffix(s string) bool {
	n, err := strconv.ParseUint(s, 10, 32)
	return err == nil && strconv.FormatUint(n, 10) == s
}

// trimRows removes the oldest rows until at most MaxRows remain.
func trimRows(rows map[string]*row) {
	// Rows without a LastSeen (health, and any kind that only carries an
	// observation time) sort by ObservedAt, so a fresh row never sorts at the
	// zero time and is dropped before an older visit.
	seen := func(r *row) time.Time {
		at := r.Record.LastSeen
		if r.Record.Kind == KindHealth || at == "" {
			at = r.Record.ObservedAt
		}
		t, _ := time.Parse(time.RFC3339Nano, at)
		return t
	}
	keys := make([]string, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := seen(rows[keys[i]]), seen(rows[keys[j]])
		if !a.Equal(b) {
			return a.Before(b)
		}
		return keys[i] < keys[j]
	})
	for _, key := range keys[:len(keys)-MaxRows] {
		delete(rows, key)
	}
}
