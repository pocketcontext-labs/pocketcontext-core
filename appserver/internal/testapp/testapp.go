// Package testapp is a synthetic application used only by appserver tests. Its
// names are unrelated to any shipped product, so a hardcoded value in core shows
// up as a failing test rather than passing by coincidence.
package testapp

import (
	"embed"
	"io/fs"

	"github.com/pocketcontext-labs/pocketcontext-core/appidentity"
)

//go:embed all:assets
var assets embed.FS

// Assets returns the fixture's migrations, hooks and reader.
func Assets() fs.FS {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err)
	}
	return sub
}

// Identity returns a complete identity for the fixture.
func Identity() appidentity.Identity {
	return appidentity.Identity{
		AppID: "fixtureapp", LegacyAppIDs: []string{"fixtureold"},
		DisplayName: "Fixture App", Command: "fixtureapp",
		SkillName: "fixtureapp", Marker: ".fixtureapp", RouterMarker: ".fixtureapp-router",
		RegistryNamespace: "fixtureapp", CacheRoot: "fixtureapp",
		SocketHost: "fixture.internal", SocketDirPrefix: "fixture",
		DefaultPort: 8301, DatabaseFile: "fixture.db", ConfigFile: "fixture.json",
		EnvPrefix: "FIXTURE", LocalKeyHeader: "X-Fixture-Local-Key",
		LocalAccountEmail: "me@fixture.localhost", ReaderStorageKey: "fixture.reader.auth",
		HookGlobal: "$fixture",
	}
}
