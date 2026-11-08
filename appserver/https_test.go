package appserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
)

func TestHTTPSDomain(t *testing.T) {
	for _, s := range []string{"knowledge.example.com", "xn--bcher-kva.example"} {
		if err := ValidateHTTPSDomain(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "localhost", "127.0.0.1", "::1", "https://example.com", "example.com:443", "example.com/", "*.example.com", "EXAMPLE.com", "example.com.", "-x.example", "x-.example", "a..com", "a_b.example", "bücher.example", strings.Repeat("a", 64) + ".com"} {
		if ValidateHTTPSDomain(s) == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestPublicHTTPSReaderAndBoundary(t *testing.T) {
	a := newTestApp(t)
	router, err := apis.NewRouter(a.app)
	if err != nil {
		t.Fatal(err)
	}
	local := &localRoutes{p: &Project{rt: testRT, Config: ProjectConfig{Port: 8096}}, key: "synthetic-key", publicURL: "https://knowledge.example.com"}
	local.register(&core.ServeEvent{App: a.app, Router: router})
	readerDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(readerDir, "index.html"), []byte("<!doctype html><title>Synthetic reader</title>"), 0600); err != nil {
		t.Fatal(err)
	}
	registerReader(&core.ServeEvent{App: a.app, Router: router}, readerDir)
	if err := a.app.OnServe().Trigger(&core.ServeEvent{App: a.app, Router: router}); err != nil {
		t.Fatal(err)
	}
	handler, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	// Obtain a public handoff through the private API, never through HTTPS.
	req := httptest.NewRequest("POST", "http://127.0.0.1:8096/api/bundle/login-code", strings.NewReader(`{"public":true}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(keyHeader, local.key)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("private code: %d %s", rec.Code, rec.Body)
	}
	var code map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &code); err != nil {
		t.Fatal(err)
	}
	link, err := url.Parse(code["url"])
	if err != nil || link.Scheme != "https" || link.Host != "knowledge.example.com" || link.Fragment == "" {
		t.Fatal("invalid public handoff", err)
	}
	// The production listener implementation runs with a synthetic trusted test
	// certificate and ephemeral ports. No CA or external network is contacted.
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	tlsConfig := certServer.TLS.Clone()
	client := certServer.Client()
	certServer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failures := make(chan error, 2)
	pub, err := startPublicListeners(ctx, publicHandler(testRT, a.app, "knowledge.example.com", handler), publicHTTPHandler("knowledge.example.com", func(h http.Handler) http.Handler { return h }), tlsConfig, "127.0.0.1:0", "127.0.0.1:0", failures)
	if err != nil {
		t.Fatal(err)
	}
	defer pub.close()
	client.Timeout = 5 * time.Second
	request := func(method, p, token, body, host, origin string, want int) string {
		t.Helper()
		r, err := http.NewRequest(method, "https://"+pub.tlsListener.Addr().String()+p, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = host
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(keyHeader, local.key)
		r.Header.Set("X-Forwarded-For", "127.0.0.1")
		r.Header.Set("X-Forwarded-Host", "127.0.0.1:8096")
		if token != "" {
			r.Header.Set("Authorization", token)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d %s, want %d", method, p, resp.StatusCode, data, want)
		}
		return string(data)
	}
	domain := "knowledge.example.com"
	if !strings.Contains(request("GET", "/", "", "", domain, "", 200), "Synthetic reader") {
		t.Fatal("reader root unavailable")
	}
	for _, p := range []string{"/api/bundle/token", "/api/bundle/login-code", "/api/bundle/stop", "/api/bundle/reader-code", "/api/batch", "/api/collections/_superusers/auth-with-password", "/api/settings"} {
		request("POST", p, a.token, `{}`, domain, "", 404)
	}
	for _, p := range []string{"/_/", "/api/bundle/instance", "/api/context/maintenance", "/api/collections", "/api/collections/users/records"} {
		request("GET", p, a.token, "", domain, "", 404)
	}
	// Removed agent endpoints must stay unavailable on both local and public transports.
	for _, endpoint := range []struct{ method, path string }{
		{"GET", "/api/chat/status"},
		{"GET", "/api/chat/sessions"},
		{"POST", "/api/chat/sessions"},
		{"POST", "/api/chat/sessions/synthetic/prompt"},
		{"POST", "/api/chat/sessions/synthetic/permission"},
	} {
		request(endpoint.method, endpoint.path, a.token, `{}`, domain, "", 404)
		req := httptest.NewRequest(endpoint.method, "http://127.0.0.1:8096"+endpoint.path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", a.token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("removed local endpoint %s %s: %d", endpoint.method, endpoint.path, rec.Code)
		}
	}
	request("POST", "/api/fixture/read", a.token, `{"collection":"notes"}`, "127.0.0.1:8096", "", 403)
	request("POST", "/api/fixture/read", a.token, `{"collection":"notes"}`, domain, "https://evil.example", 403)
	request("POST", "/api/fixture/read", "", `{"collection":"notes"}`, domain, "", 401)
	request("POST", "/api/fixture/read", a.token, `{"collection":"notes"}`, domain, "https://"+domain, 200)
	request("GET", "/api/fixture/schema", "", "", domain, "", 401)
	request("GET", "/api/fixture/schema", a.token, "", domain, "", 200)
	for _, path := range []string{"/api/spaces/default", "/api/collections/sources/records", "/api/context/schema", "/api/files/sources/id/original.txt"} {
		request("GET", path, a.token, "", domain, "", 404)
	}
	request("POST", "/api/context/query", a.token, `{"sql":"select id from spaces"}`, domain, "", 404)
	request("POST", "/api/collections/users/auth-with-password", "", `{"identity":"me@fixture.localhost","password":"synthetic-password"}`, domain, "", 200)
	redeem := `{"code":"` + link.Fragment + `"}`
	request("POST", "/api/bundle/redeem", "", redeem, domain, "", 200)
	request("POST", "/api/bundle/redeem", "", redeem, domain, "", 401)
	// Port 80 only redirects reads and does not receive login credentials.
	plain := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, method := range []string{"GET", "POST"} {
		r, _ := http.NewRequest(method, "http://"+pub.plainListener.Addr().String()+"/bundle/login", nil)
		r.Host = domain
		resp, err := plain.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		want := 308
		if method == "POST" {
			want = 400
		}
		if resp.StatusCode != want {
			t.Fatal(resp.StatusCode)
		}
		if method == "GET" && resp.Header.Get("Location") != "https://"+domain+"/bundle/login" {
			t.Fatal("bad redirect")
		}
	}
	// An active browser realtime stream must not prevent graceful shutdown.
	sseRequest, err := http.NewRequest("GET", "https://"+pub.tlsListener.Addr().String()+"/api/realtime", nil)
	if err != nil {
		t.Fatal(err)
	}
	sseRequest.Host = domain
	sse, err := client.Do(sseRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer sse.Body.Close()
	if sse.StatusCode != 200 {
		t.Fatal("realtime unavailable", sse.StatusCode)
	}
	// Release pooled client connections, leaving the active SSE body open so
	// cancellation still has to stop the realtime handler during shutdown.
	plain.CloseIdleConnections()
	client.CloseIdleConnections()
	cancel()
	// net/http can allow newly accepted connections over five seconds to send
	// their first request. Keep the deadline above that grace period and allow
	// slower CI runners to schedule the cancelled realtime handler.
	shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	if err := pub.shutdown(shutdown); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-failures:
		case <-time.After(time.Second):
			t.Fatal("listener failed to stop")
		}
	}
	if conn, err := net.DialTimeout("tcp", pub.tlsListener.Addr().String(), time.Second); err == nil {
		conn.Close()
		t.Fatal("TLS listener still open")
	}
}

func TestPublicHTTPSRateLimitAndHeaders(t *testing.T) {
	a := newTestApp(t)
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !publicRequest(r) || r.Header.Get(keyHeader) != "" || r.Header.Get("X-Forwarded-For") != "" {
			t.Error("transport authority leaked")
		}
		w.WriteHeader(401)
	})
	h := publicHandler(testRT, a.app, "knowledge.example.com", next)
	for i := 0; i < 11; i++ {
		r := httptest.NewRequest("POST", "https://knowledge.example.com/api/bundle/redeem", strings.NewReader(`{}`))
		r.RemoteAddr = "127.0.0.1:4321"
		r.Header.Set(keyHeader, "private")
		r.Header.Set("X-Forwarded-For", "192.0.2."+string(rune('a'+i)))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 401
		if i == 10 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if calls != 10 {
		t.Fatal(calls)
	}
}

// Prevent accidental removal of the public transport guard even if a future
// public route mistakenly invokes a local management handler.
func TestPublicTransportCannotUseLocalKey(t *testing.T) {
	r := httptest.NewRequest("POST", "https://knowledge.example.com/api/bundle/token", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set(keyHeader, "key")
	r = r.WithContext(context.WithValue(r.Context(), publicContextKey{}, true))
	local := &localRoutes{p: &Project{rt: testRT}, key: "key"}
	if err := local.requireKey(&core.RequestEvent{Request: r, Response: httptest.NewRecorder()}); err == nil {
		t.Fatal("public loopback request accepted local key")
	}
}

func TestPublicCertificatePolicyAndCache(t *testing.T) {
	p := &Project{rt: testRT, Cache: t.TempDir()}
	opts := ServeOptions{HTTPSDomain: "knowledge.example.com", ACMEEmail: "owner@example.com"}
	manager, tlsConfig, err := publicCertificateManager(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	if manager.Email != opts.ACMEEmail || manager.Cache == nil || tlsConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("missing certificate configuration")
	}
	if err := manager.HostPolicy(context.Background(), opts.HTTPSDomain); err != nil {
		t.Fatal(err)
	}
	if manager.HostPolicy(context.Background(), "other.example.com") == nil {
		t.Fatal("foreign host accepted")
	}
	if _, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"}); err == nil {
		t.Fatal("foreign SNI accepted")
	}
	if err := manager.Cache.Put(context.Background(), "synthetic-cache-key", []byte("synthetic certificate cache data")); err != nil {
		t.Fatal(err)
	}
	second, _, err := publicCertificateManager(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	got, err := second.Cache.Get(context.Background(), "synthetic-cache-key")
	if err != nil || string(got) != "synthetic certificate cache data" {
		t.Fatal("cache did not persist", err)
	}
	info, err := os.Stat(filepath.Join(p.Cache, "acme"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
		t.Fatal("certificate cache is not private")
	}
}

func TestPublicCodeRequiresEnabledHTTPSAndPreservesLocalLinks(t *testing.T) {
	a := newTestApp(t)
	router, err := apis.NewRouter(a.app)
	if err != nil {
		t.Fatal(err)
	}
	local := &localRoutes{p: &Project{rt: testRT, Config: ProjectConfig{Port: 8096}}, key: "synthetic-key"}
	local.register(&core.ServeEvent{App: a.app, Router: router})
	handler, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	call := func(body string, want int) string {
		t.Helper()
		r := httptest.NewRequest("POST", "http://127.0.0.1:8096/api/bundle/login-code", strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set(keyHeader, local.key)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		return w.Body.String()
	}
	call(`{"public":true}`, 400)
	local.publicURL = "https://knowledge.example.com"
	if !strings.Contains(call(`{}`, 200), "http://127.0.0.1:8096/bundle/login#") {
		t.Fatal("ordinary login-code no longer uses loopback")
	}
	if !strings.Contains(call(`{"public":true}`, 200), "https://knowledge.example.com/bundle/login#") {
		t.Fatal("public login-code did not use configured origin")
	}
}
