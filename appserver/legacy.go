package appserver

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"

	"ganigeorgiev.com/pocketbase/pocketbase/core"

	"github.com/pocketcontext-labs/pocketcontext-core/sqliteuri"
)

// DatabaseFormat identifies the storage contract independently of the executable
// release. Format 1 is the single-account schema. Its existing
// migration ledger identifies it; opening it does not add a format marker or
// require a data migration. A future format must introduce a new migration so
// releases that do not know it refuse the database before bootstrap.
const DatabaseFormat = 1

// databaseMigrationCount reads the private working copy before bootstrap. System
// migrations run during bootstrap, before the application migration lifecycle.
func databaseMigrationCount(db string) (int, error) {
	u := sqliteuri.File(db)
	conn, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec("PRAGMA query_only = 1"); err != nil {
		return 0, err
	}
	var exists int
	if err := conn.QueryRow("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = '_migrations'").Scan(&exists); err != nil {
		return 0, err
	}
	if exists == 0 {
		return 0, nil
	}
	var count int
	err = conn.QueryRow("SELECT count(*) FROM _migrations").Scan(&count)
	return count, err
}

// The schema migrations and tables of an application's earlier releases come
// from Policy.Legacy: a database that recorded any of those migrations, or that
// holds any of those tables, is refused. Core knows no application's history.

// ErrEarlierRelease reports a database this release does not open.
var ErrEarlierRelease = errors.New("unsupported database")

// checkDatabase refuses a working copy created by an earlier (or unknown)
// release before PocketBase opens it, so no migration ever touches it. It only
// reads the working copy in the private cache (query-only, like a snapshot,
// because a WAL file without its -shm cannot be opened read-only); the synced
// file is never opened.
func checkDatabase(rt *Runtime, db, synced string) error {
	return rt.CheckDatabase(db, synced)
}

// CheckDatabase is checkDatabase for read-only diagnostics on a private copy.
func (rt *Runtime) CheckDatabase(db, synced string) error {
	u := sqliteuri.File(db)
	conn, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec("PRAGMA query_only = 1"); err != nil {
		return fmt.Errorf("reading %s: %w", synced, err)
	}
	tables := map[string]bool{}
	rows, err := conn.Query("SELECT name FROM sqlite_master WHERE type = 'table'")
	if err != nil {
		return fmt.Errorf("reading %s: %w", synced, err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		tables[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	schema := rt.cfg.Policy.Legacy
	description := ""
	if schema.Description != "" {
		description = " (" + schema.Description + ")"
	}
	earlier := fmt.Errorf("%w: %s was created by an earlier %s release%s; this release does not open databases from earlier releases and leaves the file unchanged. "+
		"%s", ErrEarlierRelease, synced, rt.cfg.Identity.DisplayName, description, rt.cfg.Text.LegacyRecreateHint)
	for _, t := range schema.Tables {
		if tables[t] {
			return earlier
		}
	}
	if !tables["_migrations"] {
		return nil // an empty database; PocketBase creates the schema
	}
	known := map[string]bool{}
	entries, err := fs.ReadDir(rt.cfg.Assets, "pb_migrations")
	if err != nil {
		return err
	}
	for _, e := range entries {
		known[e.Name()] = true
	}
	// PocketBase migrations can change the storage contract too. Only checking
	// JavaScript migrations would allow an older binary to open a database that
	// a newer PocketBase has changed. Inspect the actual compiled registries.
	for _, list := range []*core.MigrationsList{&core.SystemMigrations, &core.AppMigrations} {
		for _, migration := range list.Items() {
			known[migration.File] = true
		}
	}
	legacy := map[string]bool{}
	for _, name := range schema.Migrations {
		legacy[name] = true
	}
	applied, err := conn.Query("SELECT file FROM _migrations")
	if err != nil {
		return fmt.Errorf("reading %s: %w", synced, err)
	}
	defer applied.Close()
	for applied.Next() {
		var file string
		if err := applied.Scan(&file); err != nil {
			return err
		}
		switch {
		case legacy[file]:
			return earlier
		case !known[file]:
			return fmt.Errorf("%w: %s was created by a different %s release (unknown schema migration %s); this release leaves the file unchanged. Use the release that created it",
				ErrEarlierRelease, synced, rt.cfg.Identity.DisplayName, file)
		}
	}
	return applied.Err()
}
