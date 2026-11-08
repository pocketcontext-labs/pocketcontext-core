package appidentity

import (
	"reflect"
	"testing"
)

func valid() Identity {
	return Identity{
		AppID: "fernapp", LegacyAppIDs: []string{"fernold"}, DisplayName: "Fern App", Command: "fernapp",
		SkillName: "fernapp", Marker: ".fernapp", RouterMarker: ".fernapp-router",
		RegistryNamespace: "fernapp", CacheRoot: "fernapp", SocketHost: "fern.internal", SocketDirPrefix: "fern",
		DefaultPort: 8201, DatabaseFile: "fern.db", ConfigFile: "fern.json", EnvPrefix: "FERN",
		LocalKeyHeader: "X-Fern-Local-Key", LocalAccountEmail: "me@fern.localhost", ReaderStorageKey: "fern.reader.auth", HookGlobal: "$fern",
	}
}

func TestValidIdentity(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
}

// Every required field fails closed when empty.
func TestEveryStringFieldRequired(t *testing.T) {
	typ := reflect.TypeOf(Identity{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Kind() != reflect.String {
			continue
		}
		id := valid()
		reflect.ValueOf(&id).Elem().Field(i).SetString("")
		if err := id.Validate(); err == nil {
			t.Fatalf("empty %s accepted", f.Name)
		}
	}
}

func TestRejectedValues(t *testing.T) {
	cases := map[string]func(*Identity){
		"port too low":       func(i *Identity) { i.DefaultPort = 80 },
		"port too high":      func(i *Identity) { i.DefaultPort = 70000 },
		"zero port":          func(i *Identity) { i.DefaultPort = 0 },
		"path separator":     func(i *Identity) { i.CacheRoot = "a/b" },
		"backslash":          func(i *Identity) { i.Marker = `a\b` },
		"control character":  func(i *Identity) { i.Command = "a\nb" },
		"dot path":           func(i *Identity) { i.RegistryNamespace = ".." },
		"header not a token": func(i *Identity) { i.LocalKeyHeader = "X Fern" },
		"bad email":          func(i *Identity) { i.LocalAccountEmail = "not-an-address" },
		"legacy empty":       func(i *Identity) { i.LegacyAppIDs = []string{""} },
		"legacy equals app":  func(i *Identity) { i.LegacyAppIDs = []string{i.AppID} },
	}
	for name, mutate := range cases {
		id := valid()
		mutate(&id)
		if err := id.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
