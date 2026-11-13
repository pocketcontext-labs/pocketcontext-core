package appserver

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/router"
)

func uiDevTestHandler(t *testing.T, upstream string, publicDomain ...string) http.Handler {
	t.Helper()
	p := &Project{rt: testRT, Config: ProjectConfig{Port: 8096}}
	d, err := newUIDevProxy(upstream, p)
	if err != nil {
		t.Fatal(err)
	}
	r := router.NewRouter(func(w http.ResponseWriter, r *http.Request) (*core.RequestEvent, router.EventCleanupFunc) {
		return &core.RequestEvent{Event: router.Event{Response: w, Request: r}}, nil
	})
	e := &core.ServeEvent{Router: r}
	local := &localRoutes{p: p}
	if len(publicDomain) > 0 {
		d.allowPublic(publicDomain[0])
		local.publicURL = "https://" + publicDomain[0]
	}
	local.register(e)
	r.GET("/api/test", func(e *core.RequestEvent) error { return e.String(http.StatusOK, "API") })
	d.register(e)
	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	if len(publicDomain) > 0 {
		return publicHandlerModeWithUIDev(testRT, nil, publicDomain[0], mux, false, true)
	}
	return mux
}

func TestUIDevURLValidation(t *testing.T) {
	p := &Project{rt: testRT, Config: ProjectConfig{Port: 8096}}
	for _, raw := range []string{"http://127.0.0.1:5173", "http://localhost:5173/"} {
		if _, err := newUIDevProxy(raw, p); err != nil {
			t.Errorf("valid URL %q: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"https://127.0.0.1:5173", "http://example.com:5173", "http://0.0.0.0:5173",
		"http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536",
		"http://user:password@127.0.0.1:5173", "http://127.0.0.1:5173/src",
		"http://127.0.0.1:5173/?token=secret", "http://127.0.0.1:5173/#fragment",
		"http://127.0.0.1:8096", "http://localhost:8096", "file:///tmp/ui",
		"http://127.0.0.1.example.com:5173", "http://[::1]:5173",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := newUIDevProxy(raw, p); err == nil {
				t.Fatalf("accepted invalid upstream %q", raw)
			}
		})
	}
}

func TestUIDevLiveAssetsAndRouteBoundaries(t *testing.T) {
	var revision atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=99999")
		w.Header().Set("Set-Cookie", "upstream=secret")
		fmt.Fprintf(w, "%s:%d", r.URL.RequestURI(), revision.Load())
	}))
	defer upstream.Close()
	handler := uiDevTestHandler(t, upstream.URL)
	for _, path := range []string{"/", "/src/main.tsx?t=123", "/assets/icon.svg", "/node_modules/.vite/deps/react.js?v=abc", "/@vite/client", "/@id/react", "/@fs/tmp/project/module.ts", "/@react-refresh"} {
		t.Run(path, func(t *testing.T) {
			for _, n := range []int32{1, 2} {
				revision.Store(n)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8096"+path, nil))
				if rr.Code != http.StatusOK || rr.Body.String() != fmt.Sprintf("%s:%d", path, n) {
					t.Fatalf("live response = %d %q", rr.Code, rr.Body.String())
				}
				if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Set-Cookie") != "" {
					t.Fatalf("unsafe cache/cookie headers: %v", rr.Header())
				}
				if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
					t.Fatal("missing development CSP")
				}
				if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "img-src 'self' blob:;") {
					t.Fatal("development CSP must allow verified image blobs")
				}
				if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "worker-src 'self' blob:") {
					t.Fatal("development CSP must allow Vite's reconnect worker")
				}
			}
		})
	}
	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "http://127.0.0.1:8096/src/main.tsx", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("HEAD asset response = %d %q, headers %v", head.Code, head.Body.String(), head.Header())
	}
	for _, test := range []struct {
		path, want string
		status     int
	}{
		{"/api/test", "API", 200},
		{"/api/unknown", "", 404},
		{"/bundle/unknown", "", 404},
		{"/not-a-ui-route", "", 404},
		{"/bundle/login", "Fixture App sign-in", 200},
	} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8096"+test.path, nil))
		if rr.Code != test.status || (test.want != "" && !strings.Contains(rr.Body.String(), test.want)) {
			t.Errorf("%s = %d %q", test.path, rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Header().Get("Content-Security-Policy"), "'unsafe-inline'") {
			t.Errorf("development CSP leaked onto %s", test.path)
		}
	}
}

func TestUIDevRejectsCrossOriginBeforeUpstream(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler := uiDevTestHandler(t, upstream.URL)
	for _, test := range []struct{ host, origin, path string }{
		{"evil.example:8096", "", "/"},
		{"127.0.0.1:8096", "https://evil.example", "/src/main.tsx"},
		{"127.0.0.1:8096", "null", "/"},
		{"127.0.0.1:8096", "", "/__ui_hmr"},
		{"127.0.0.1:8096", "http://localhost:8096", "/__ui_hmr"},
		{"127.0.0.1:8096", "http://127.0.0.1:5173", "/__ui_hmr"},
	} {
		t.Run(test.host+test.origin+test.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+test.host+test.path, nil)
			if test.origin != "" {
				req.Header.Set("Origin", test.origin)
			}
			if test.path == "/__ui_hmr" {
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("got %d; want forbidden", rr.Code)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("rejected requests reached upstream: %d", calls.Load())
	}
}

func TestUIDevStripsCredentials(t *testing.T) {
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	handler := uiDevTestHandler(t, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8096/@vite/client", nil)
	for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization", keyHeader, "Referer"} {
		req.Header.Set(name, "private-value")
	}
	req.Header.Set("Origin", "http://127.0.0.1:8096")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("response = %d", rr.Code)
	}
	headers := <-seen
	for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization", keyHeader, "Referer"} {
		if headers.Get(name) != "" {
			t.Errorf("forwarded sensitive %s header", name)
		}
	}
}

func TestUIDevUnavailableUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstream.Close()
	handler := uiDevTestHandler(t, upstream.URL)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8096/", nil))
	if rr.Code != http.StatusBadGateway || !strings.Contains(strings.ToLower(rr.Body.String()), "vite") {
		t.Fatalf("unavailable upstream = %d %q", rr.Code, rr.Body.String())
	}
}

func TestUIDevWebSocketTunnel(t *testing.T) {
	for _, public := range []bool{false, true} {
		t.Run(fmt.Sprintf("public=%v", public), func(t *testing.T) { testUIDevWebSocketTunnel(t, public) })
	}
}
func testUIDevWebSocketTunnel(t *testing.T, public bool) {
	host, origin := "127.0.0.1:8096", "http://127.0.0.1:8096"
	if public {
		host, origin = "dev.example.test", "https://dev.example.test"
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__ui_hmr" || r.URL.RawQuery != "token=synthetic" || r.Header.Get("Sec-WebSocket-Protocol") != "vite-hmr" || r.Header.Get("Origin") != origin {
			http.Error(w, "lost HMR path, token or protocol", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get(keyHeader) != "" {
			http.Error(w, "credentials reached HMR", http.StatusBadRequest)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: vite-hmr\r\n\r\n")
		_ = rw.Flush()
		data := make([]byte, 4)
		if _, err := io.ReadFull(rw, data); err == nil {
			_, _ = conn.Write(data)
		}
	}))
	defer upstream.Close()
	handler := uiDevTestHandler(t, upstream.URL)
	if public {
		handler = uiDevTestHandler(t, upstream.URL, host)
	}
	proxy := httptest.NewServer(handler)
	defer proxy.Close()
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(proxy.URL, "http://"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET /__ui_hmr?token=synthetic HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Protocol: vite-hmr\r\nAuthorization: private-token\r\nCookie: private-cookie\r\nX-PocketContext-Local-Key: private-key\r\n\r\n", host, origin)
	r := bufio.NewReader(conn)
	response, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade response = %d", response.StatusCode)
	}
	if response.Header.Get("Sec-WebSocket-Protocol") != "vite-hmr" {
		t.Fatal("lost WebSocket subprotocol")
	}
	// Verify traffic in both directions after the HTTP upgrade, without adding a
	// WebSocket client dependency just for the proxy transport test.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4)
	if _, err := io.ReadFull(r, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "ping" {
		t.Fatalf("tunnel data = %q", data)
	}
}

func TestEmbeddedReaderKeepsProductionPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{"index.html": "<html>synthetic reader</html>", "assets/index-test.js": "/* synthetic asset */", "assets/logo-test.svg": `<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h1"/></svg>`, "assets/private.txt": "must not be served"} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(path)), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := router.NewRouter(func(w http.ResponseWriter, r *http.Request) (*core.RequestEvent, router.EventCleanupFunc) {
		return &core.RequestEvent{Event: router.Event{Response: w, Request: r}}, nil
	})
	registerReader(&core.ServeEvent{Router: r}, dir, false)
	handler, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path, want, cache string
		status            int
	}{
		{"/", "synthetic reader", "no-store", 200},
		{"/assets/index-test.js", "synthetic asset", "public, max-age=31536000, immutable", 200},
		{"/assets/logo-test.svg", "<svg", "public, max-age=31536000, immutable", 200},
		{"/assets/private.txt", "", "", 404},
		{"/src/main.tsx", "", "", 404},
		{"/@vite/client", "", "", 404},
		{"/__ui_hmr", "", "", 404},
	} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8096"+test.path, nil))
		if rr.Code != test.status || !strings.Contains(rr.Body.String(), test.want) || rr.Header().Get("Cache-Control") != test.cache {
			t.Errorf("%s = %d %q, headers %v", test.path, rr.Code, rr.Body.String(), rr.Header())
		}
		csp := rr.Header().Get("Content-Security-Policy")
		if strings.Contains(csp, "'unsafe-inline'") || strings.Contains(csp, "ws://") {
			t.Errorf("development policy in embedded reader: %s", csp)
		}
		if test.status == 200 && !strings.Contains(csp, "img-src 'self' blob:;") {
			t.Errorf("missing verified image blob policy: %s", csp)
		}
		if test.status == 200 && (!strings.Contains(csp, "script-src 'self';") || rr.Header().Get("X-Frame-Options") != "DENY") {
			t.Errorf("missing production protections: %v", rr.Header())
		}
		if strings.Contains(csp, "frame-src") {
			t.Errorf("reader allows frames without opting in: %s", csp)
		}
	}
}

func TestEmbeddedReaderFramesSelfOptIn(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>synthetic reader</html>"), 0600); err != nil {
		t.Fatal(err)
	}
	r := router.NewRouter(func(w http.ResponseWriter, r *http.Request) (*core.RequestEvent, router.EventCleanupFunc) {
		return &core.RequestEvent{Event: router.Event{Response: w, Request: r}}, nil
	})
	registerReader(&core.ServeEvent{Router: r}, dir, true)
	handler, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8096/", nil))
	csp := rr.Header().Get("Content-Security-Policy")
	if rr.Code != 200 || !strings.Contains(csp, "frame-src 'self'; frame-ancestors 'none';") || !strings.Contains(csp, "default-src 'none';") || rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("framesSelf reader policy = %d %s %v", rr.Code, csp, rr.Header())
	}
}
