package appserver

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pocketcontext-labs/pocketcontext-core/atomicfile"
	"github.com/pocketcontext-labs/pocketcontext-core/sqliteuri"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// The synced database is never opened by the server. It is copied into the
// cache on start, and consistent snapshots are written back with VACUUM INTO
// and an atomic rename. A sync client therefore only ever sees whole files.

// fileState identifies the synced file this machine last copied or wrote.
type fileState struct {
	Size   int64     `json:"size"`
	Mtime  time.Time `json:"mtime"`
	SHA256 string    `json:"sha256"`
}

type storeState struct {
	Base  *fileState `json:"base"`  // nil: no synced database existed
	Dirty bool       `json:"dirty"` // the working copy has unsaved changes
	// Conflict is the copy that preserves this computer's changes after the
	// synced file was changed elsewhere; later write-backs refresh it.
	Conflict string `json:"conflict,omitempty"`
}

// MaxWriteBackDelay bounds how long committed changes wait for a quiet moment.
// Under steady writes the synced file is still refreshed this often.
const MaxWriteBackDelay = time.Minute

// Store owns the working copy of one project's database.
//
// mu guards the counters and state and is only ever held briefly, so a request
// that records a change never waits for a snapshot. writing serializes
// write-backs; it is taken before mu, never while holding it.
type Store struct {
	p       *Project
	writing sync.Mutex
	mu      sync.Mutex
	state   storeState
	changes uint64    // bumped on every committed model change
	saved   uint64    // the value of changes the synced file is known to contain
	last    time.Time // the latest change
	pending time.Time // the oldest change not yet written back
	// dirtyUnsaved records that the dirty flag could not be persisted, so the
	// next change tries again instead of trusting a state file that says clean.
	dirtyUnsaved bool
	now          func() time.Time // nil means time.Now
}

func (s *Store) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Store) statePath() string { return filepath.Join(s.p.LiveDir(), "state.json") }
func (s *Store) livePath() string  { return filepath.Join(s.p.LiveDir(), "data.db") }

func (s *Store) loadState() error {
	data, err := os.ReadFile(s.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.state)
}

func (s *Store) saveState() error {
	data, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	return atomicfile.WriteAtomic(s.statePath(), data, 0600)
}

// current describes the synced file, hashing only when size or time changed.
// Callers are the single-threaded start and recovery paths.
func (s *Store) current() (*fileState, error) { return s.currentFrom(s.state.Base) }

// currentFrom is current against an explicit base, for callers that must not
// read the state without the lock.
func (s *Store) currentFrom(b *fileState) (*fileState, error) {
	info, err := os.Stat(s.p.DB)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if b != nil && b.Size == info.Size() && b.Mtime.Equal(info.ModTime()) {
		return b, nil
	}
	sum, err := atomicfile.FileSHA256(s.p.DB)
	if err != nil {
		return nil, err
	}
	return &fileState{Size: info.Size(), Mtime: info.ModTime(), SHA256: sum}, nil
}

func sameFile(a, b *fileState) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.SHA256 == b.SHA256
}

// Open prepares the working copy. Unsaved changes left by a crash are written
// back first unless the synced file changed meanwhile, which needs a decision.
func (s *Store) Open() error {
	if err := os.MkdirAll(s.p.LiveDir(), 0700); err != nil {
		return err
	}
	if err := s.loadState(); err != nil {
		return fmt.Errorf("working copy state: %w", err)
	}
	synced, err := s.current()
	if err != nil {
		return err
	}
	_, statErr := os.Stat(s.livePath())
	haveLive := statErr == nil
	if haveLive && s.state.Dirty {
		// Unsaved changes of an earlier release stay where they are, untouched.
		if err := checkDatabase(s.p.rt, s.livePath(), s.p.DB); err != nil {
			return err
		}
		if !sameFile(synced, s.state.Base) {
			return fmt.Errorf("%s changed (probably on another computer) while this computer had unsaved changes from an interrupted run; "+
				"run `%s recover --keep local` or `--keep synced`", s.p.DB, s.p.rt.cfg.Identity.Command)
		}
		// Recover the interrupted run before anything else touches the files.
		s.changes = 1
		if err := s.writeBack(); err != nil {
			return fmt.Errorf("recovering unsaved changes: %w", err)
		}
		return nil
	}
	if haveLive && sameFile(synced, s.state.Base) {
		return nil // the working copy already matches the synced file
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(s.livePath() + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if synced != nil {
		if err := atomicfile.CopyFile(s.p.DB, s.livePath()); err != nil {
			return fmt.Errorf("copying %s: %w", s.p.DB, err)
		}
	}
	s.state = storeState{Base: synced}
	return s.saveState()
}

// Recover resolves an interrupted run whose synced file also changed.
func (s *Store) Recover(keepLocal bool) error {
	if err := s.loadState(); err != nil {
		return err
	}
	if !s.state.Dirty {
		return errors.New("nothing to recover: the working copy has no unsaved changes")
	}
	if keepLocal {
		synced, err := s.current()
		if err != nil {
			return err
		}
		if synced != nil {
			backup := fmt.Sprintf("%s.replaced-%s.db", s.p.DB, time.Now().UTC().Format("20060102T150405Z"))
			if err := atomicfile.CopyFile(s.p.DB, backup); err != nil {
				return err
			}
		}
		s.state.Base = synced
		s.changes = 1
		return s.writeBack()
	}
	conflict := s.state.Conflict
	if conflict == "" {
		conflict = filepath.Join(s.p.Dir, conflictName(s.p.DB))
	}
	if err := s.snapshotTo(conflict); err != nil {
		return err
	}
	s.state = storeState{}
	if err := s.saveState(); err != nil {
		return err
	}
	return os.Remove(s.livePath())
}

// Changed records a committed change; it persists the dirty flag at once so a
// crash cannot lose track of unsaved work. The change is already committed, so
// a failure to persist the flag is logged and retried on the next change.
func (s *Store) Changed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	if s.changes == s.saved {
		s.pending = now
	}
	s.changes++
	s.last = now
	if !s.state.Dirty || s.dirtyUnsaved {
		s.state.Dirty = true
		if err := s.saveState(); err != nil {
			if !s.dirtyUnsaved {
				log.Printf("write-back: could not record unsaved changes (%v); a crash before the next write-back may leave them only in the working copy", err)
			}
			s.dirtyUnsaved = true
		} else {
			s.dirtyUnsaved = false
		}
	}
}

// Flush writes back once changes have been quiet for the given interval, or
// once the oldest unsaved change has waited MaxWriteBackDelay.
func (s *Store) Flush(quiet time.Duration) error {
	s.mu.Lock()
	now := s.clock()
	due := s.changes != s.saved && (now.Sub(s.last) >= quiet || now.Sub(s.pending) >= MaxWriteBackDelay)
	s.mu.Unlock()
	if !due {
		return nil
	}
	return s.writeBack()
}

// Close performs the final write-back.
func (s *Store) Close() error {
	s.mu.Lock()
	clean := s.changes == s.saved && !s.state.Dirty
	s.mu.Unlock()
	if clean {
		return nil
	}
	return s.writeBack()
}

func conflictName(db string) string {
	host, _ := os.Hostname()
	host, _, _ = strings.Cut(host, ".")
	return fmt.Sprintf("%s.conflict-%s-%s-%s.db", filepath.Base(db), safeName(host), time.Now().UTC().Format("20060102T150405Z"), atomicfile.RandomHex(2))
}

func safeName(s string) string {
	out := []rune{}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "host"
	}
	return string(out)
}

// NewStore returns the store of project p. It opens nothing.
func NewStore(p *Project) *Store { return &Store{p: p} }

// LivePath returns the private working database path.
func (s *Store) LivePath() string { return s.livePath() }

// Snapshot writes a consistent copy of the working database to dst.
func (s *Store) Snapshot(dst string) error { return s.snapshot(dst) }

// snapshot writes a consistent copy of the working database to dst.
func (s *Store) snapshot(dst string) error {
	// Read-write: a WAL database without its -shm file cannot be opened read-only.
	u := sqliteuri.File(s.livePath())
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA busy_timeout=10000"); err != nil {
		return err
	}
	_, err = db.Exec("VACUUM INTO ?", dst)
	return err
}

// snapshotTo atomically replaces dst with a consistent copy of the working database.
func (s *Store) snapshotTo(dst string) error {
	temp := filepath.Join(filepath.Dir(dst), "."+filepath.Base(s.p.DB)+".tmp-"+atomicfile.RandomHex(4))
	defer os.Remove(temp)
	if err := s.snapshot(temp); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	if f, err := os.Open(temp); err == nil {
		_ = f.Sync()
		f.Close()
	}
	return atomicfile.RenameRetry(temp, dst)
}

// writeBack snapshots the working copy into the synced folder. It must be
// called without s.mu: hashing and the snapshot run outside it, so recording a
// change never waits for them. A change committed while the snapshot runs may
// or may not be in it, so it stays counted as unsaved and is written next time.
func (s *Store) writeBack() error {
	s.writing.Lock()
	defer s.writing.Unlock()
	s.mu.Lock()
	target := s.changes
	started := s.clock()
	base, conflict := s.state.Base, s.state.Conflict
	s.mu.Unlock()

	synced, err := s.currentFrom(base)
	if err != nil {
		return err
	}
	if !sameFile(synced, base) {
		// Never overwrite a file another computer wrote; keep both and say so.
		if conflict == "" {
			conflict = filepath.Join(s.p.Dir, conflictName(s.p.DB))
		}
		if err := s.snapshotTo(conflict); err != nil {
			return err
		}
		s.mu.Lock()
		s.settle(target, started)
		s.state.Conflict = conflict
		s.state.Dirty = true
		if err := s.saveState(); err != nil {
			log.Printf("write-back: could not record the conflict copy: %v", err)
			s.dirtyUnsaved = true
		}
		s.mu.Unlock()
		return fmt.Errorf("%s changed on another computer; this computer's changes are kept in %s; run `%s stop`, then `%s recover`", s.p.DB, conflict, s.p.rt.cfg.Identity.Command, s.p.rt.cfg.Identity.Command)
	}
	if err := s.snapshotTo(s.p.DB); err != nil {
		return err
	}
	written, err := s.currentFrom(nil)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settle(target, started)
	s.state = storeState{Base: written, Dirty: s.changes != target}
	if err := s.saveState(); err != nil {
		s.dirtyUnsaved = s.state.Dirty
		return err
	}
	s.dirtyUnsaved = false
	return nil
}

// settle records that changes up to target are written. Later changes have
// waited since the snapshot started at the earliest. Caller holds s.mu.
func (s *Store) settle(target uint64, started time.Time) {
	s.saved = target
	if s.changes != target {
		s.pending = started
	}
}

// Lease marks the project as active on one computer. Cloud folders cannot
// share a SQLite lock, so a heartbeat file is the cross-machine guard.
type Lease struct {
	Host      string    `json:"host"`
	PID       int       `json:"pid"`
	Instance  string    `json:"instance"`
	Heartbeat time.Time `json:"heartbeat"`
}

// LeaseTimeout is how long a silent lease from another computer blocks starting.
const LeaseTimeout = 2 * time.Minute

func ReadLease(p *Project) (*Lease, error) {
	data, err := os.ReadFile(p.LeaseFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var l Lease
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, nil // a partially synced lease counts as absent
	}
	return &l, nil
}

func writeLease(p *Project) error {
	host, _ := os.Hostname()
	if p.LeaseHost != "" {
		host = p.LeaseHost
	}
	data, _ := json.Marshal(Lease{Host: host, PID: os.Getpid(), Instance: p.Config.Instance, Heartbeat: time.Now().UTC()})
	return atomicfile.WriteAtomic(p.LeaseFile(), data, 0644)
}

// claimLease fails if another computer used the project recently.
func claimLease(p *Project, takeOver bool) error {
	l, err := ReadLease(p)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	if p.LeaseHost != "" {
		host = p.LeaseHost
	}
	if l != nil && l.Host != host && time.Since(l.Heartbeat) < LeaseTimeout && !takeOver {
		return fmt.Errorf("the project is active on %s (last seen %s); stop it there, or start with --take-over if that computer is off",
			l.Host, l.Heartbeat.Local().Format(time.RFC822))
	}
	return writeLease(p)
}

func releaseLease(p *Project) {
	host, _ := os.Hostname()
	if p.LeaseHost != "" {
		host = p.LeaseHost
	}
	if l, _ := ReadLease(p); l != nil && l.Host == host && l.PID == os.Getpid() {
		_ = os.Remove(p.LeaseFile())
	}
}
