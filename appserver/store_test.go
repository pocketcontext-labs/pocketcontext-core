package appserver

import (
	"database/sql"
	"github.com/pocketcontext-labs/pocketcontext-core/atomicfile"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testProject(t *testing.T) *Project {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "Cloud Drive", "PocketContext")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	return &Project{rt: testRT, DB: filepath.Join(dir, "fixture.db"), Dir: dir, Cache: filepath.Join(root, "cache"), Config: ProjectConfig{Port: testRT.cfg.Identity.DefaultPort}}
}

func execLive(t *testing.T, s *Store, statement string) {
	t.Helper()
	db, err := sql.Open("sqlite3", s.livePath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(statement); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, path, table string) int {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWriteBackAndReopen(t *testing.T) {
	p := testProject(t)
	s := &Store{p: p}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	execLive(t, s, "CREATE TABLE notes(x); INSERT INTO notes VALUES (1)")
	s.Changed()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if n := count(t, p.DB, "notes"); n != 1 {
		t.Fatalf("synced copy has %d rows", n)
	}
	// A new run reuses the matching working copy and sees no unsaved changes.
	s2 := &Store{p: p}
	if err := s2.Open(); err != nil {
		t.Fatal(err)
	}
	if s2.state.Dirty {
		t.Fatal("reopened working copy is dirty")
	}
	entries, _ := os.ReadDir(p.Dir)
	for _, e := range entries {
		if e.Name() != "fixture.db" {
			t.Errorf("unexpected file in project folder: %s", e.Name())
		}
	}
}

func TestSyncedFileReplacedElsewhere(t *testing.T) {
	p := testProject(t)
	s := &Store{p: p}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	execLive(t, s, "CREATE TABLE notes(x)")
	s.Changed()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Another computer's version arrives through the sync client.
	other := filepath.Join(t.TempDir(), "other.db")
	db, _ := sql.Open("sqlite3", other)
	if _, err := db.Exec("CREATE TABLE notes(x); INSERT INTO notes VALUES (1), (2)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := atomicfile.CopyFile(other, p.DB); err != nil {
		t.Fatal(err)
	}
	execLive(t, s, "INSERT INTO notes VALUES (99)")
	s.Changed()
	err := s.Close()
	if err == nil || !strings.Contains(err.Error(), "changed on another computer") {
		t.Fatalf("expected conflict, got %v", err)
	}
	if n := count(t, p.DB, "notes"); n != 2 {
		t.Fatalf("the other computer's file was overwritten (%d rows)", n)
	}
	if n := count(t, s.state.Conflict, "notes"); n != 1 {
		t.Fatalf("conflict copy has %d rows", n)
	}
	// Restarting refuses until the user chooses.
	if err := (&Store{p: p}).Open(); err == nil || !strings.Contains(err.Error(), "recover") {
		t.Fatalf("expected recover instruction, got %v", err)
	}
	if err := (&Store{p: p}).Recover(false); err != nil {
		t.Fatal(err)
	}
	s3 := &Store{p: p}
	if err := s3.Open(); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s3.livePath(), "notes"); n != 2 {
		t.Fatalf("working copy did not adopt the synced file (%d rows)", n)
	}
}

func TestLeaseFromAnotherComputer(t *testing.T) {
	p := testProject(t)
	if err := os.WriteFile(p.LeaseFile(), []byte(`{"host":"other-laptop","pid":1,"heartbeat":"2999-01-01T00:00:00Z"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := claimLease(p, false); err == nil || !strings.Contains(err.Error(), "other-laptop") {
		t.Fatalf("expected lease refusal, got %v", err)
	}
	if err := claimLease(p, true); err != nil {
		t.Fatal(err)
	}
	releaseLease(p)
	if _, err := os.Stat(p.LeaseFile()); !os.IsNotExist(err) {
		t.Fatal("lease not released")
	}
}

func TestResolveDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FIXTURE_DB", "")
	p, err := testRT.Resolve(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.DB != filepath.Join(dir, testRT.cfg.Identity.DatabaseFile) || p.Config.Port != testRT.cfg.Identity.DefaultPort {
		t.Fatalf("resolved %+v", p)
	}
}

// Steady writes never leave a quiet moment; the synced file is still refreshed
// once the oldest unsaved change has waited MaxWriteBackDelay.
func TestFlushHasMaximumDelayUnderSteadyWrites(t *testing.T) {
	p := testProject(t)
	now := time.Unix(1_800_000_000, 0)
	s := &Store{p: p, now: func() time.Time { return now }}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	execLive(t, s, "CREATE TABLE notes(x)")
	s.Changed()
	if err := s.Flush(0); err != nil {
		t.Fatal(err)
	}
	// One change a second for just under the maximum delay: never quiet for 3s.
	for i := 0; i < int(MaxWriteBackDelay/time.Second)-1; i++ {
		execLive(t, s, "INSERT INTO notes VALUES (1)")
		s.Changed()
		now = now.Add(time.Second)
		if err := s.Flush(3 * time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, p.DB, "notes"); n != 0 {
		t.Fatalf("written back before the maximum delay (%d rows)", n)
	}
	execLive(t, s, "INSERT INTO notes VALUES (1)")
	s.Changed()
	now = now.Add(time.Second)
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	if n := count(t, p.DB, "notes"); n != int(MaxWriteBackDelay/time.Second) {
		t.Fatalf("steady writes were not written back at the maximum delay (%d rows)", n)
	}
	// The delay restarts from the write-back, not from the first change ever.
	execLive(t, s, "INSERT INTO notes VALUES (2)")
	s.Changed()
	now = now.Add(time.Second)
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	if n := count(t, p.DB, "notes"); n != int(MaxWriteBackDelay/time.Second) {
		t.Fatalf("written back again without a quiet moment (%d rows)", n)
	}
	now = now.Add(3 * time.Second)
	if err := s.Flush(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	if n := count(t, p.DB, "notes"); n != int(MaxWriteBackDelay/time.Second)+1 {
		t.Fatalf("quiet changes were not written back (%d rows)", n)
	}
}

// Recording a change must not wait for a running snapshot, and a change made
// during one stays unsaved until the next write-back.
func TestChangedDoesNotWaitForWriteBack(t *testing.T) {
	p := testProject(t)
	s := &Store{p: p}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	execLive(t, s, "CREATE TABLE notes(x)")
	s.Changed()
	s.writing.Lock() // a write-back is in progress
	done := make(chan struct{})
	go func() { s.Changed(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Changed waited for the write-back")
	}
	s.writing.Unlock()
	if err := s.Flush(0); err != nil {
		t.Fatal(err)
	}
	if s.changes != s.saved || s.state.Dirty {
		t.Fatalf("changes=%d saved=%d dirty=%v", s.changes, s.saved, s.state.Dirty)
	}
}

// A dirty flag that could not be persisted is retried on the next change
// instead of being trusted as recorded.
func TestChangedRetriesUnsavedDirtyFlag(t *testing.T) {
	p := testProject(t)
	s := &Store{p: p}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(p.LiveDir()); err != nil {
		t.Fatal(err)
	}
	s.Changed()
	if !s.dirtyUnsaved {
		t.Fatal("the failed state write was not noticed")
	}
	if err := os.MkdirAll(p.LiveDir(), 0700); err != nil {
		t.Fatal(err)
	}
	s.Changed()
	if s.dirtyUnsaved {
		t.Fatal("the dirty flag was not retried")
	}
	reopened := &Store{p: p}
	if err := reopened.loadState(); err != nil || !reopened.state.Dirty {
		t.Fatalf("dirty flag not on disk: %+v %v", reopened.state, err)
	}
}
