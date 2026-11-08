package appserver

import (
	"context"
	"encoding/json"
	"github.com/pocketcontext-labs/pocketcontext-core/atomicfile"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/router"
)

func TestSocketHostValidation(t *testing.T) {
	p := &Project{rt: testRT, Config: ProjectConfig{Port: 8096}}
	routes := &localRoutes{p: p, key: "private-key", stop: make(chan struct{}, 1)}
	r := router.NewRouter(func(w http.ResponseWriter, r *http.Request) (*core.RequestEvent, router.EventCleanupFunc) {
		return &core.RequestEvent{Event: router.Event{Response: w, Request: r}}, nil
	})
	routes.register(&core.ServeEvent{Router: r})
	handler, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, host, key string
		socket          bool
		want            int
	}{
		{"TCP internal host rejected", testRT.cfg.Identity.SocketHost, "private-key", false, 403},
		{"socket internal host accepted", testRT.cfg.Identity.SocketHost, "private-key", true, 200},
		{"tunnel loopback host accepted", "127.0.0.1:8096", "private-key", true, 200},
		{"tunnel no key rejected", "127.0.0.1:8096", "", true, 403},
		{"socket foreign host rejected", "evil.example", "private-key", true, 403},
		{"socket wrong port rejected", "localhost:8097", "private-key", true, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "http://"+tc.host+"/api/bundle/stop", nil)
			req.RemoteAddr = "127.0.0.1:40000"
			if tc.socket {
				req.RemoteAddr = "@"
				req = req.WithContext(context.WithValue(req.Context(), socketContextKey{}, true))
			}
			req.Header.Set(keyHeader, tc.key)
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != tc.want {
				t.Fatalf("got %d: %s", res.Code, res.Body.String())
			}
		})
	}
}

func TestSocketLifecycleAndTCPActivation(t *testing.T) {
	a := newTestApp(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	p := &Project{rt: testRT, Cache: t.TempDir(), Key: atomicfile.RandomHex(8), Config: ProjectConfig{Port: occupied.Addr().(*net.TCPAddr).Port, Instance: "expected"}}
	p.ConfigPath = filepath.Join(p.Cache, "test-config.json")
	if err := os.Chmod(p.Cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.KeyFile(), []byte("private-key"), 0600); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{}, 1)
	local := &localRoutes{p: p, key: "private-key", stop: stop}
	a.app.OnServe().BindFunc(func(e *core.ServeEvent) error { local.register(e); return e.Next() })
	done := make(chan error, 1)
	go func() { done <- serveHTTP(a.app, p, ServeOptions{Headless: true}, stop, local) }()
	t.Cleanup(func() {
		select {
		case stop <- struct{}{}:
		default:
		}
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(15 * time.Second):
			t.Error("server did not stop")
		}
	})
	var info *Instance
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		info, err = Health(p)
		if err == nil && info.Instance == "expected" {
			break
		}
	}
	if err != nil || info == nil || info.Socket == "" || info.TCP || !info.Headless {
		t.Fatalf("headless status: %+v %v", info, err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(info.Socket)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("socket permissions: %v %v", fi, err)
		}
	}
	if _, err := LocalCall(p, "/api/bundle/name", map[string]string{"name": "Renamed knowledge"}); err != nil {
		t.Fatal(err)
	}
	renamed, err := Health(p)
	if err != nil || renamed.Name != "Renamed knowledge" {
		t.Fatalf("name not visible: %+v %v", renamed, err)
	}
	for _, name := range []string{"", "../unsafe", "bad\nname"} {
		if _, err := LocalCall(p, "/api/bundle/name", map[string]string{"name": name}); err == nil {
			t.Fatalf("accepted invalid name %q", name)
		}
	}
	if err := EnableTCP(p); err == nil {
		t.Fatal("enabled occupied TCP port")
	}
	if ok, err := Running(p); err != nil || !ok {
		t.Fatalf("port conflict stopped socket server: %v", err)
	}
	occupied.Close()
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := EnableTCP(p); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	info, err = Health(p)
	if err != nil || !info.TCP || info.Headless {
		t.Fatalf("TCP status: %+v %v", info, err)
	}
	resp, err := http.Get(p.URL() + "/api/bundle/instance")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// Ordinary authenticated APIs work over the socket without a local-key header.
	client := socketHTTPClient(info.Socket, time.Second)
	defer client.CloseIdleConnections()
	req, _ := http.NewRequest("POST", p.URL()+"/api/fixture/read", strings.NewReader(`{"collection":"buckets"}`))
	req.Header.Set("Authorization", a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("ordinary socket token request returned %d", resp.StatusCode)
	}
}

func TestSocketLongPathAndStaleCleanup(t *testing.T) {
	p := &Project{rt: testRT, Cache: filepath.Join(t.TempDir(), strings.Repeat("long", 40)), Key: atomicfile.RandomHex(8)}
	path, err := p.SocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if len([]byte(path)) >= 104 {
		t.Fatalf("long socket path: %s", path)
	}
	ln, err := listenSocket(p)
	if err != nil {
		t.Fatal(err)
	}
	unix := ln.(*net.UnixListener)
	unix.SetUnlinkOnClose(false)
	ln.Close()
	running, err := Running(p)
	if err != nil || running {
		t.Fatalf("stale socket: %v %v", running, err)
	}
	ln, err = listenSocket(p)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket remains after close: %v", err)
	}
}

func TestSocketDoesNotFallBackToTCP(t *testing.T) {
	tcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Instance{App: testRT.cfg.Identity.AppID, Key: "different"})
	}))
	defer tcp.Close()
	p := &Project{rt: testRT, Cache: t.TempDir(), Key: "expected"}
	p.Config.Port = tcp.Listener.Addr().(*net.TCPAddr).Port
	if _, err := LocalHTTPClient(p, time.Second); err == nil {
		t.Fatal("accepted another project's TCP service")
	}
	path, _ := p.SocketPath()
	if err := os.WriteFile(path, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenSocket(p); err == nil {
		t.Fatal("replaced non-socket file")
	}
	running, err := Running(p)
	if err != nil || running {
		t.Fatalf("stale endpoint fell back: %v %v", running, err)
	}
}

func TestEnsureRunningRejectsForeignSocket(t *testing.T) {
	p := &Project{rt: testRT, Cache: t.TempDir(), Key: atomicfile.RandomHex(8), Config: ProjectConfig{Port: 8096, Instance: "expected"}}
	if err := os.Chmod(p.Cache, 0700); err != nil {
		t.Fatal(err)
	}
	ln, err := listenSocket(p)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Instance{App: testRT.cfg.Identity.AppID, Key: "another", Instance: "another"})
	})}
	defer server.Close()
	go server.Serve(ln)
	err = EnsureRunning(p, StartOptions{})
	if err == nil || !strings.Contains(err.Error(), "another Fixture App database") {
		t.Fatalf("existing socket identity error was suppressed: %v", err)
	}
}

// The TCP response is held until the local socket exists: this deterministically
// reproduces the startup race without sleeps or a real child process.
func TestEnsureRunningSocketAppearsDuringTCPCheck(t *testing.T) {
	for _, mode := range []string{"own", "foreign", "malformed", "tcp-only"} {
		t.Run(mode, func(t *testing.T) {
			p := &Project{rt: testRT, Cache: t.TempDir(), Key: atomicfile.RandomHex(8), Config: ProjectConfig{Instance: "expected"}}
			if err := os.Chmod(p.Cache, 0700); err != nil {
				t.Fatal(err)
			}
			socketServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "malformed" {
					http.Error(w, "not PocketContext", http.StatusNotFound)
					return
				}
				key := p.Key
				if mode == "foreign" {
					key = "another"
				}
				json.NewEncoder(w).Encode(Instance{App: testRT.cfg.Identity.AppID, Key: key, Instance: p.Config.Instance,
					Version: testRT.cfg.Version, DatabaseFormat: DatabaseFormat, Headless: true})
			})}
			defer socketServer.Close()
			var once sync.Once
			tcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				once.Do(func() {
					ln, err := listenSocket(p)
					if err != nil {
						t.Errorf("create socket during TCP check: %v", err)
						return
					}
					go socketServer.Serve(ln)
				})
				http.Error(w, "unrelated service", http.StatusNotFound)
			}))
			defer tcp.Close()
			p.Config.Port = tcp.Listener.Addr().(*net.TCPAddr).Port
			err := EnsureRunning(p, StartOptions{TCP: mode == "tcp-only"})
			want := map[string]string{"foreign": "another Fixture App database", "malformed": "unexpected local socket server", "tcp-only": "used by another program"}[mode]
			if mode == "own" {
				if err != nil {
					t.Fatalf("returned stale TCP error after own socket became ready: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("want %q, got %v", want, err)
			}
		})
	}
}
