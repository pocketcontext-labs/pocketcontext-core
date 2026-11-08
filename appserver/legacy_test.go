package appserver

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pocketcontext-labs/pocketcontext-core/atomicfile"
)

// A database from an earlier release is refused before PocketBase opens it,
// and neither the synced file nor the working copy changes.
func TestEarlierReleaseRefused(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, schema string
		refused      bool
	}{
		{"old migrations", "CREATE TABLE _migrations (file TEXT PRIMARY KEY, applied INTEGER); INSERT INTO _migrations VALUES ('1640988000_init.go', 1), ('1791500000_spaces.js', 2);", true},
		{"membership table", "CREATE TABLE space_members (id TEXT PRIMARY KEY);", true},
		{"unknown migration", "CREATE TABLE _migrations (file TEXT PRIMARY KEY, applied INTEGER); INSERT INTO _migrations VALUES ('1999999999_future.js', 1);", true},
		{"unknown system migration", "CREATE TABLE _migrations (file TEXT PRIMARY KEY, applied INTEGER); INSERT INTO _migrations VALUES ('1999999999_future.go', 1);", true},
		{"unknown migration extension", "CREATE TABLE _migrations (file TEXT PRIMARY KEY, applied INTEGER); INSERT INTO _migrations VALUES ('future.sql', 1);", true},
		{"migration path alias", "CREATE TABLE _migrations (file TEXT PRIMARY KEY, applied INTEGER); INSERT INTO _migrations VALUES ('future/1810000000_users.js', 1);", true},
		{"current", "CREATE TABLE _migrations (file TEXT PRIMARY KEY, applied INTEGER); INSERT INTO _migrations VALUES ('1640988000_init.go', 1), ('1810000000_users.js', 2);", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".db")
			db, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("CREATE TABLE notes (id TEXT); " + tc.schema); err != nil {
				t.Fatal(err)
			}
			db.Close()
			before, err := atomicfile.FileSHA256(path)
			if err != nil {
				t.Fatal(err)
			}
			err = checkDatabase(testRT, path, "/synced/fixture.db")
			if got := errors.Is(err, ErrEarlierRelease); got != tc.refused {
				t.Fatalf("refused = %v (%v); want %v", got, err, tc.refused)
			}
			if tc.refused && !strings.Contains(err.Error(), "/synced/fixture.db") {
				t.Fatalf("message does not name the database: %v", err)
			}
			if tc.name == "old migrations" && !strings.Contains(err.Error(), "earlier") {
				t.Fatalf("message: %v", err)
			}
			after, err := atomicfile.FileSHA256(path)
			if err != nil || after != before {
				t.Fatalf("the database changed: %v", err)
			}
		})
	}
}

// Store.Open copies an old synced database into the cache, and Serve refuses it
// there; unsaved changes of an earlier release are never written back.
func TestEarlierReleaseWorkingCopyUntouched(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	project := filepath.Join(t.TempDir(), testRT.cfg.Identity.DatabaseFile)
	db, err := sql.Open("sqlite3", project)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE space_members (id TEXT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before, _ := atomicfile.FileSHA256(project)
	p, err := testRT.Resolve(project)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(p)
	if err := store.Open(); err != nil {
		t.Fatal(err)
	}
	if err := checkDatabase(testRT, store.livePath(), p.DB); !errors.Is(err, ErrEarlierRelease) {
		t.Fatalf("working copy accepted: %v", err)
	}
	store.state.Dirty = true
	if err := store.saveState(); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(p).Open(); !errors.Is(err, ErrEarlierRelease) {
		t.Fatalf("dirty working copy: %v", err)
	}
	if after, _ := atomicfile.FileSHA256(project); after != before {
		t.Fatal("the synced database changed")
	}
	if _, err := os.Stat(store.livePath()); err != nil {
		t.Fatal("the working copy was removed")
	}
}
