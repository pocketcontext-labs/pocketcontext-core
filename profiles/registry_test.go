package profiles

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var testStore = New("fixture-namespace")

func isolate(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	t.Setenv("HOME", root)
	t.Setenv("AppData", root)
}
func entry(t *testing.T, name, instance string) Entry {
	t.Helper()
	dir := t.TempDir()
	return Entry{ID: ID(instance), Name: name, Instance: instance, DB: filepath.Join(dir, "synthetic.db"), Binary: filepath.Join(dir, "synthetic"), Version: "0.13.0", Skill: filepath.Join(dir, "skill")}
}
func TestRegistryIdentityAndRemoval(t *testing.T) {
	isolate(t)
	e := entry(t, "alpha", "one")
	if err := testStore.Put(e, false); err != nil {
		t.Fatal(err)
	}
	if err := testStore.Default("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := testStore.Put(entry(t, "alpha", "two"), true); err == nil {
		t.Fatal("adopted different instance")
	}
	if err := os.WriteFile(e.DB, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	e.Name = "renamed"
	if err := testStore.Put(e, true); err != nil {
		t.Fatal(err)
	}
	r, err := testStore.Read()
	if err != nil || r.Default != "renamed" {
		t.Fatalf("rename default: %+v %v", r, err)
	}
	if err := testStore.Remove("renamed"); err != nil {
		t.Fatal(err)
	}
	r, _ = testStore.Read()
	if len(r.Profiles) != 0 || r.Default != "" {
		t.Fatal("entry retained")
	}
	if _, err := os.Stat(e.DB); err != nil {
		t.Fatal("data removed")
	}
	path, _ := testStore.Path()
	info, _ := os.Stat(path)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("registry not private")
	}
}
func TestConcurrentUpdates(t *testing.T) {
	isolate(t)
	entries := []Entry{entry(t, "alpha", "one"), entry(t, "beta", "two")}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, e := range entries {
		wg.Add(1)
		go func(e Entry) { defer wg.Done(); errs <- testStore.Put(e, false) }(e)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err := testStore.Read()
	if err != nil || len(r.Profiles) != 2 {
		t.Fatalf("lost update: %+v %v", r, err)
	}
}
func TestNamesAndFutureFormat(t *testing.T) {
	isolate(t)
	for _, name := range []string{"../x", "x/y", "x\\y", " x", "x\n", ".."} {
		if ValidateName(name) == nil {
			t.Errorf("accepted %q", name)
		}
	}
	p, _ := testStore.Path()
	os.MkdirAll(filepath.Dir(p), 0700)
	os.WriteFile(p, []byte(`{"format":99}`), 0600)
	if _, err := testStore.Read(); err == nil {
		t.Fatal("accepted future format")
	}
	if err := testStore.Put(entry(t, "alpha", "one"), false); err == nil {
		t.Fatal("overwrote future format")
	}
}

func TestRenameCannotStealLaterEntryName(t *testing.T) {
	isolate(t)
	a := entry(t, "alpha", "one")
	b := entry(t, "beta", "two")
	if err := testStore.Put(a, false); err != nil {
		t.Fatal(err)
	}
	if err := testStore.Put(b, false); err != nil {
		t.Fatal(err)
	}
	a.Name = "beta"
	if err := testStore.Put(a, true); err == nil {
		t.Fatal("rename stole another profile's name")
	}
	r, err := testStore.Read()
	if err != nil || len(r.Profiles) != 2 {
		t.Fatalf("registry damaged: %v", err)
	}
}
