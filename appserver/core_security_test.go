package appserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"github.com/dop251/goja"

	"github.com/pocketcontext-labs/pocketcontext-core/appserver/internal/testapp"
	"github.com/pocketcontext-labs/pocketcontext-core/appserver/routepolicytest"
)

func TestNewRefusesIncompleteConfig(t *testing.T) {
	base := func() Config { return fixtureConfig(fixturePublicRoute) }
	for name, mutate := range map[string]func(*Config){
		"empty identity":   func(c *Config) { c.Identity.AppID = "" },
		"no version":       func(c *Config) { c.Version = "" },
		"no assets":        func(c *Config) { c.Assets = nil },
		"no public route":  func(c *Config) { c.Policy.PublicRoute = nil },
		"no maintenance":   func(c *Config) { c.Policy.Maintenance.ReadPosts = nil },
		"no observe":       func(c *Config) { c.Policy.Observe.Tools = nil },
		"no account name":  func(c *Config) { c.Text.AccountName = "" },
		"no scope":         func(c *Config) { c.Policy.OAuthScope = "" },
		"quoted scope":     func(c *Config) { c.Policy.OAuthScope = `a"b` },
		"two scopes":       func(c *Config) { c.Policy.OAuthScope = "a b" },
		"no body limit":    func(c *Config) { c.Policy.PublicBodyLimit = 0 },
		"no legacy":        func(c *Config) { c.Policy.Legacy.Tables = nil },
		"unnamed legacy":   func(c *Config) { c.Policy.Legacy.Description = "" },
		"partial hosted":   func(c *Config) { c.Policy.Hosted.Burst = 0 },
		"bad hosted label": func(c *Config) { c.Policy.Hosted.Label = "Fixture Account" },
		"no sign-in copy":  func(c *Config) { c.Text.OAuthConsent.SignInHTML = "" },
		"no OTP path":      func(c *Config) { c.Text.OTPLoginPath = "" },
		"OTP path query":   func(c *Config) { c.Text.OTPLoginPath = "/login?x=1" },
		"foreign OTP path": func(c *Config) { c.Text.OTPLoginPath = "//evil.example/login" },
		"no consent copy":  func(c *Config) { c.Text.OAuthConsent.RequestHTML = "" },
		"bad consent copy": func(c *Config) { c.Text.OAuthConsent.RequestHTML = "{{.Name" },
		"shadowed sha256": func(c *Config) {
			c.Hooks.Bindings = func(*goja.Runtime) map[string]any { return map[string]any{"sha256": 1} }
		},
	} {
		c := base()
		mutate(&c)
		if _, err := New(c); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := New(base()); err != nil {
		t.Fatal(err)
	}
}

// Core has no public allowlist of its own. A request is admitted only by a
// product policy, so a deny-everything or missing policy leaves only OAuth, OTP
// and the hosted health check.
func TestPublicRequestDeniedWithoutProductPolicy(t *testing.T) {
	policies := map[string]func(core.App) func(string, string) bool{
		"nil route":  func(core.App) func(string, string) bool { return nil },
		"deny route": func(core.App) func(string, string) bool { return func(string, string) bool { return false } },
	}
	for name, factory := range policies {
		cfg := fixtureConfig(fixturePublicRoute)
		cfg.Policy.PublicRoute = factory
		rt, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		called := false
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
		h := publicHandler(rt, nil, "knowledge.example.com", next)
		for _, tc := range []struct{ method, path string }{
			{"GET", "/"}, {"GET", "/assets/app.js"}, {"POST", "/api/bundle/redeem"}, {"POST", "/api/fixture/read"},
			{"GET", "/api/collections/greetings/records"}, {"POST", "/api/collections/users/auth-with-password"},
			{"GET", "/up"}, {"DELETE", "/anything"},
		} {
			r := httptest.NewRequest(tc.method, "https://knowledge.example.com"+tc.path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound || called {
				t.Fatalf("%s: %s %s admitted: %d", name, tc.method, tc.path, w.Code)
			}
		}
	}
}

func TestFixturePolicyDeniesFrozenNegativeSet(t *testing.T) {
	routepolicytest.Check(t, fixturePublicRoute, routepolicytest.CommonDenied())
	routepolicytest.Check(t, fixturePublicRoute, []routepolicytest.Case{
		{Method: "GET", Path: "/", Allow: true},
		{Method: "POST", Path: "/api/fixture/read", Allow: true},
		{Method: "POST", Path: "/api/collections/greetings/records", Allow: true},
		{Method: "DELETE", Path: "/api/collections/greetings/records/abc", Allow: false},
	})
}

func TestPublicUIDevRefusedWithoutPolicy(t *testing.T) {
	p := &Project{rt: testRT, Cache: t.TempDir()}
	if err := ServeContext(context.Background(), p, ServeOptions{PublicUIDev: true, UIDev: "http://127.0.0.1:5173", HTTPSDomain: "knowledge.example.com", Headless: true}); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("public UI development accepted: %v", err)
	}
	if err := ServeContext(context.Background(), p, ServeOptions{DevHTTPAddress: "127.0.0.1:18080"}); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("dev HTTP address accepted: %v", err)
	}
	h := publicHandlerModeWithUIDev(testRT, nil, "knowledge.example.com", http.NotFoundHandler(), false, false)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://knowledge.example.com/src/main.tsx", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("development route reached the public handler: %d", w.Code)
	}
}

func TestHookBindingsMergeAndKeepSHA256(t *testing.T) {
	cfg := fixtureConfig(fixturePublicRoute)
	cfg.Hooks.Bindings = fixtureHooks
	rt, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	vm := goja.New()
	registerHookBindings(rt, vm)
	result, err := vm.RunString(`[typeof ` + rt.cfg.Identity.HookGlobal + `.sha256, ` + rt.cfg.Identity.HookGlobal + `.fixtureBinding()].join(",")`)
	if err != nil {
		t.Fatal(err)
	}
	if result.String() != "function,bound" {
		t.Fatal(result.String())
	}
}

func socketServer(t *testing.T, p *Project, handler http.HandlerFunc) {
	t.Helper()
	if err := os.Chmod(p.Cache, 0700); err != nil {
		t.Fatal(err)
	}
	ln, err := listenSocket(p)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	t.Cleanup(func() { server.Close() })
	go server.Serve(ln)
}

func instanceProject(t *testing.T) *Project {
	t.Helper()
	dir, err := os.MkdirTemp("", "fx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return &Project{rt: testRT, Cache: dir, Key: "k", Config: ProjectConfig{Port: 8301, Instance: "i"}}
}

func TestHealthAcceptsOnlyOwnAndLegacyAppIDs(t *testing.T) {
	for _, tc := range []struct {
		app string
		ok  bool
	}{{"fixtureapp", true}, {"fixtureold", true}, {"otherapp", false}, {"", false}} {
		t.Run(tc.app, func(t *testing.T) {
			p := instanceProject(t)
			socketServer(t, p, func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(Instance{App: tc.app, Key: "k", Instance: "i", Version: "x", Port: p.Config.Port})
			})
			if _, err := Health(p); (err == nil) != tc.ok {
				t.Fatalf("Health(app=%q): %v", tc.app, err)
			}
		})
	}
}

func TestLegacyServerIsDiagnosedButNeverAdopted(t *testing.T) {
	p := instanceProject(t)
	socketServer(t, p, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Instance{App: "fixtureold", Key: "k", Instance: "i", Version: testRT.cfg.Version})
	})
	if running, err := Running(p); err != nil || !running {
		t.Fatalf("legacy server not diagnosable: %v", err)
	}
	if err := CheckServerCompatibility(p, &Instance{App: "fixtureold", Version: testRT.cfg.Version}); err == nil || !strings.Contains(err.Error(), "earlier Fixture App release") {
		t.Fatalf("legacy adoption accepted: %v", err)
	}
	if err := EnsureRunning(p, StartOptions{}); err == nil || !strings.Contains(err.Error(), "earlier Fixture App release") {
		t.Fatalf("EnsureRunning adopted a legacy server: %v", err)
	}
	if _, err := LocalCall(p, "/api/bundle/name", map[string]string{"name": "Changed"}); err == nil {
		t.Fatal("management call accepted on a legacy server")
	}
}

// Identical values to the source applications, but kept in core's fixture so a
// hardcoded value in core cannot pass by matching a product default.
func TestIdentityValuesComeFromConfiguration(t *testing.T) {
	id := testapp.Identity()
	if id.LocalKeyHeader != keyHeader || id.AppID != "fixtureapp" {
		t.Fatalf("fixture identity: %+v", id)
	}
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("LocalAppData", dir)
	p, err := testRT.Resolve(filepath.Join(t.TempDir(), id.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p.ConfigPath) != id.ConfigFile || !strings.Contains(p.Cache, id.CacheRoot) || p.Config.Port != id.DefaultPort {
		t.Fatalf("project identity: %+v", p)
	}
	if rel, err := filepath.Rel(dir, p.Cache); err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("cache %s outside user cache %s", p.Cache, dir)
	}
}

// The local key file is private, never leaves the cache and is removed on shutdown.
func TestLocalKeyPrivateAndRemovedOnStop(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "cache")
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("AppData", cache)
	t.Setenv("LocalAppData", cache)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	p, err := testRT.Resolve(filepath.Join(root, "project", testRT.cfg.Identity.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := p.SaveConfig(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(p, ServeOptions{Headless: true}) }()
	var ok bool
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := Health(p); err == nil {
			ok = true
			break
		}
	}
	if !ok {
		t.Fatal("server did not start")
	}
	key, err := ReadKey(p)
	if err != nil || key == "" {
		t.Fatal("no key", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(p.KeyFile())
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("key mode: %v %v", info.Mode(), err)
		}
	}
	info, err := Health(p)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(info)
	if strings.Contains(string(encoded), key) {
		t.Fatal("instance response carries the key")
	}
	if !strings.Contains(p.KeyFile(), p.Cache) {
		t.Fatal("key outside cache")
	}
	if err := Stop(p); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.KeyFile()); !os.IsNotExist(err) {
		t.Fatal("key retained after shutdown", err)
	}
}

func TestSecondServerRefusedByCacheLock(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("LocalAppData", filepath.Join(root, "cache"))
	p, err := testRT.Resolve(filepath.Join(root, "project", testRT.cfg.Identity.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.Cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(p.Cache, "server.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := lockFile(lock); err != nil {
		t.Fatal(err)
	}
	err = ServeContext(context.Background(), p, ServeOptions{Headless: true})
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second server not refused: %v", err)
	}
}
