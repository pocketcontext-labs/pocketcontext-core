package appserver

import (
	"encoding/json"
	"github.com/pocketcontext-labs/pocketcontext-core/atomicfile"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/dbx"
)

func TestEnsureRunningRejectsDifferentReleaseButAllowsDiagnosis(t *testing.T) {
	p := &Project{rt: testRT, Cache: t.TempDir(), Key: atomicfile.RandomHex(8), Config: ProjectConfig{Port: 8096, Instance: "same-project"}}
	if err := os.Chmod(p.Cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.KeyFile(), []byte("synthetic-key"), 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := listenSocket(p)
	if err != nil {
		t.Fatal(err)
	}
	var mutations atomic.Int32
	var stops atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/bundle/instance":
			_ = json.NewEncoder(w).Encode(Instance{App: testRT.cfg.Identity.AppID, Key: p.Key, Instance: p.Config.Instance, Version: "older-release"})
		case "/api/bundle/stop":
			stops.Add(1)
			_, _ = w.Write([]byte(`{"stopped":true}`))
		default:
			mutations.Add(1)
			_, _ = w.Write([]byte(`{}`))
		}
	})}
	defer server.Close()
	go server.Serve(ln)
	if err := EnsureRunning(p, StartOptions{}); err == nil || !strings.Contains(err.Error(), "older-release") {
		t.Fatalf("different server release was accepted: %v", err)
	}
	if running, err := Running(p); err != nil || !running {
		t.Fatalf("diagnosis refused: %v", err)
	}
	if i, err := Health(p); err != nil || i.Version != "older-release" {
		t.Fatalf("status refused: %+v %v", i, err)
	}
	if _, err := LocalCall(p, "/api/bundle/name", map[string]string{"name": "Changed"}); err == nil || !strings.Contains(err.Error(), "older-release") {
		t.Fatalf("management mutation accepted: %v", err)
	}
	if _, err := LocalCall(p, "/api/bundle/stop", map[string]any{}); err != nil {
		t.Fatalf("shutdown refused: %v", err)
	}
	if mutations.Load() != 0 || stops.Load() != 1 {
		t.Fatalf("unexpected requests: mutations=%d stops=%d", mutations.Load(), stops.Load())
	}
}

func TestServerCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance Instance
		refused  bool
	}{
		{"matching", Instance{Version: testRT.cfg.Version, DatabaseFormat: DatabaseFormat}, false},
		{"legacy format advertisement", Instance{Version: testRT.cfg.Version}, false},
		{"future format", Instance{Version: testRT.cfg.Version, DatabaseFormat: DatabaseFormat + 1}, true},
		{"missing version", Instance{}, true},
		{"other release", Instance{Version: "another-release", DatabaseFormat: DatabaseFormat}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckServerCompatibility(&Project{rt: testRT}, &tc.instance); (err != nil) != tc.refused {
				t.Fatalf("compatibility: %v", err)
			}
		})
	}
}

// A system migration that only writes SQL must still reach the synced snapshot.
// The migration count must be taken before Bootstrap, which applies system migrations.
func TestSystemMigrationWrittenBack(t *testing.T) {
	a := newTestApp(t)
	migration := "1763020353_update_default_auth_alert_templates.go"
	if _, err := a.app.DB().NewQuery("DELETE FROM _migrations WHERE file = {:file}").Bind(dbx.Params{"file": migration}).Execute(); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(t.TempDir(), "fixture.db")
	if _, err := a.app.DB().NewQuery("VACUUM INTO {:path}").Bind(dbx.Params{"path": project}).Execute(); err != nil {
		t.Fatal(err)
	}
	before, err := databaseMigrationCount(project)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	p, err := testRT.Resolve(project)
	if err != nil {
		t.Fatal(err)
	}
	p.Config.Instance = atomicfile.RandomHex(16)
	if err := p.SaveConfig(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(p, ServeOptions{Headless: true}) }()
	stopped := false
	defer func() {
		if !stopped {
			_ = Stop(p)
			select {
			case <-done:
			case <-time.After(35 * time.Second):
				t.Error("server failed to stop")
			}
		}
	}()
	ready := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		select {
		case err := <-done:
			stopped = true
			t.Fatalf("server stopped: %v", err)
		default:
		}
		if i, err := Health(p); err == nil && i.Instance == p.Config.Instance {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("server did not become ready")
	}
	if err := Stop(p); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(35 * time.Second):
		t.Fatal("server failed to stop")
	}
	after, err := databaseMigrationCount(project)
	if err != nil || after != before+1 {
		t.Fatalf("system migration did not reach snapshot: before=%d after=%d error=%v", before, after, err)
	}
}
