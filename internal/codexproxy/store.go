package codexproxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/fsperm"
)

// Store keeps every decision of every session: a replacement, or nil to keep
// the part. Each session has a file of its own, readable by its owner only,
// so a restarted proxy answers a resumed session with the same bytes, and a
// session's file goes once it is older than the saved outputs it points to.
type Store struct {
	dir string
	now func() time.Time

	mu       sync.Mutex
	sessions map[string]*decisions
}

type decisions struct {
	m       map[string]*string
	file    *os.File
	touched time.Time
}

type storeLine struct {
	Key         string  `json:"k"`
	Replacement *string `json:"r"`
}

// storeIdle is how long a session's decisions stay in memory after their
// last use; they reload from the file if the session comes back.
const storeIdle = time.Hour

var sessionPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// OpenStore keeps decisions under dir; an empty dir keeps them in memory.
func OpenStore(dir string) (*Store, error) {
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, err
		}
	}
	return &Store{dir: dir, now: time.Now, sessions: map[string]*decisions{}}, nil
}

// Get returns a session's decision for key, and whether there is one.
func (s *Store) Get(session, key string) (*string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	replacement, ok := s.session(session).m[key]
	return replacement, ok
}

// PutIfAbsent stores replacement unless key already has a decision, and
// returns the decision that stands. A decision the file cannot take is kept
// in memory only.
func (s *Store) PutIfAbsent(session, key string, replacement *string) *string {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(session)
	if old, ok := state.m[key]; ok {
		return old
	}
	// A replacement the file does not take would not be replayed after a
	// restart, which would change the request's prefix: keep the part.
	if state.file != nil {
		line, _ := json.Marshal(storeLine{Key: key, Replacement: replacement})
		if _, err := state.file.Write(append(line, '\n')); err != nil {
			replacement = nil
		}
	} else if s.dir != "" {
		// The session's file did not open.
		replacement = nil
	}
	state.m[key] = replacement
	return replacement
}

// session returns a session's decisions, loading its file the first time.
// s.mu must be held.
func (s *Store) session(session string) *decisions {
	state := s.sessions[session]
	if state == nil {
		state = &decisions{m: map[string]*string{}}
		if s.dir != "" && sessionPattern.MatchString(session) && session != "." && session != ".." {
			state.file = s.load(filepath.Join(s.dir, session+".jsonl"), state.m)
		}
		s.sessions[session] = state
	}
	state.touched = s.now()
	return state
}

func (s *Store) load(path string, into map[string]*string) *os.File {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil
	}
	if fsperm.RestrictFile(file) != nil {
		_ = file.Close()
		return nil
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(nil, maxBodyBytes)
	var last []byte
	for scanner.Scan() {
		last = scanner.Bytes()
		var line storeLine
		// A line cut short by a crash is the last one and is skipped.
		if json.Unmarshal(last, &line) == nil && line.Key != "" {
			if _, ok := into[line.Key]; !ok {
				into[line.Key] = line.Replacement
			}
		}
	}
	// End a line cut short, so the next decision is a line of its own.
	if info, err := file.Stat(); err == nil && info.Size() > 0 {
		end := make([]byte, 1)
		if _, err := file.ReadAt(end, info.Size()-1); err == nil && end[0] != '\n' {
			if _, err := file.Write([]byte("\n")); err != nil {
				_ = file.Close()
				return nil
			}
		}
	}
	return file
}

// Prune forgets sessions idle for storeIdle, and deletes session files not
// written for retention.
func (s *Store) Prune(retention time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for session, state := range s.sessions {
		if now.Sub(state.touched) > storeIdle {
			if state.file != nil {
				_ = state.file.Close()
			}
			delete(s.sessions, session)
		}
	}
	if s.dir == "" {
		return nil
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || filepath.Ext(entry.Name()) != ".jsonl" || now.Sub(info.ModTime()) <= retention {
			continue
		}
		session := entry.Name()[:len(entry.Name())-len(".jsonl")]
		if _, open := s.sessions[session]; open {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close closes the session files.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for session, state := range s.sessions {
		if state.file != nil {
			errs = append(errs, state.file.Close())
		}
		delete(s.sessions, session)
	}
	return errors.Join(errs...)
}
