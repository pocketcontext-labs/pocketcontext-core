package appserver

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
)

// Synthetic deployments: (a) a load balancer appending the client as the
// rightmost X-Forwarded-For entry from a private subnet, and (b) a tunnel
// whose local proxy reports CF-Connecting-IP from loopback.
var (
	albProxy    = &HostedProxy{Header: HostedProxyXForwardedFor, Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}}
	tunnelProxy = &HostedProxy{Header: HostedProxyCFConnectingIP, Networks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}}
)

func proxiedRequest(peer string, headers map[string][]string) *http.Request {
	r := httptest.NewRequest("GET", "http://knowledge.example.com/", nil)
	r.RemoteAddr = peer
	for name, values := range headers {
		for _, v := range values {
			r.Header.Add(name, v)
		}
	}
	return r
}

func TestHostedProxyClientAddress(t *testing.T) {
	xff := HostedProxyXForwardedFor
	cf := HostedProxyCFConnectingIP
	for _, tc := range []struct {
		name    string
		proxy   *HostedProxy
		peer    string
		headers map[string][]string
		want    string
	}{
		{"xff rightmost", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"203.0.113.9"}}, "203.0.113.9:0"},
		{"xff forged leftmost", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"198.51.100.1, 192.0.2.1,203.0.113.9"}}, "203.0.113.9:0"},
		{"xff several lines", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"198.51.100.1", "203.0.113.9"}}, "203.0.113.9:0"},
		{"xff ipv6 client", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"2001:db8::7"}}, "[2001:db8::7]:0"},
		{"xff mapped client", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"::ffff:203.0.113.9"}}, "203.0.113.9:0"},
		{"xff mapped peer", albProxy, "[::ffff:10.0.3.4]:5555", map[string][]string{xff: {"203.0.113.9"}}, "203.0.113.9:0"},
		{"xff untrusted peer", albProxy, "192.0.2.50:5555", map[string][]string{xff: {"203.0.113.9"}}, "192.0.2.50:5555"},
		{"xff missing", albProxy, "10.0.3.4:5555", nil, "10.0.3.4:5555"},
		{"xff rightmost loopback", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"203.0.113.9, 127.0.0.1"}}, "10.0.3.4:5555"},
		{"xff rightmost empty", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"203.0.113.9, "}}, "10.0.3.4:5555"},
		{"xff with port", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"203.0.113.9:443"}}, "10.0.3.4:5555"},
		{"xff bracketed", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"[2001:db8::7]"}}, "10.0.3.4:5555"},
		{"xff zone", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"fe80::1%eth0"}}, "10.0.3.4:5555"},
		{"xff unspecified", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"0.0.0.0"}}, "10.0.3.4:5555"},
		{"xff multicast", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"224.0.0.1"}}, "10.0.3.4:5555"},
		{"xff garbage", albProxy, "10.0.3.4:5555", map[string][]string{xff: {"unknown"}}, "10.0.3.4:5555"},
		{"xff header ignored for cf proxy", tunnelProxy, "127.0.0.1:5555", map[string][]string{xff: {"203.0.113.9"}}, "127.0.0.1:5555"},
		{"cf", tunnelProxy, "127.0.0.1:5555", map[string][]string{cf: {"203.0.113.9"}, xff: {"198.51.100.1, 127.0.0.1"}}, "203.0.113.9:0"},
		{"cf ipv6 loopback peer", tunnelProxy, "[::1]:5555", map[string][]string{cf: {"2001:db8::7"}}, "[2001:db8::7]:0"},
		{"cf untrusted peer", tunnelProxy, "192.0.2.50:5555", map[string][]string{cf: {"203.0.113.9"}}, "192.0.2.50:5555"},
		{"cf loopback value", tunnelProxy, "127.0.0.1:5555", map[string][]string{cf: {"127.0.0.1"}}, "127.0.0.1:5555"},
		{"cf list", tunnelProxy, "127.0.0.1:5555", map[string][]string{cf: {"203.0.113.9, 198.51.100.1"}}, "127.0.0.1:5555"},
		{"cf two lines", tunnelProxy, "127.0.0.1:5555", map[string][]string{cf: {"203.0.113.9", "198.51.100.1"}}, "127.0.0.1:5555"},
		{"unparsable peer", tunnelProxy, "@", map[string][]string{cf: {"203.0.113.9"}}, "@"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.proxy.remoteAddr(proxiedRequest(tc.peer, tc.headers)); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if tc.want != tc.peer {
				if _, _, err := net.SplitHostPort(tc.want); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestHostedProxyValidation(t *testing.T) {
	if err := albProxy.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := tunnelProxy.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]*HostedProxy{
		"nil":            nil,
		"no networks":    {Header: HostedProxyXForwardedFor},
		"ipv4 any":       {Header: HostedProxyXForwardedFor, Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("0.0.0.0/0")}},
		"ipv6 any":       {Header: HostedProxyCFConnectingIP, Networks: []netip.Prefix{netip.MustParsePrefix("::/0")}},
		"unknown header": {Header: "X-Real-IP", Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		"header case":    {Header: "x-forwarded-for", Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		"host bits":      {Header: HostedProxyXForwardedFor, Networks: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/8")}},
		"mapped":         {Header: HostedProxyXForwardedFor, Networks: []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/104")}},
		"zero prefix":    {Header: HostedProxyXForwardedFor, Networks: []netip.Prefix{{}}},
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	if p, err := ParseHostedProxy("", ""); p != nil || err != nil {
		t.Fatal("empty values must mean no proxy", p, err)
	}
	p, err := ParseHostedProxy("X-Forwarded-For", "10.0.0.0/16, 10.1.0.0/16")
	if err != nil || len(p.Networks) != 2 || p.Header != HostedProxyXForwardedFor {
		t.Fatal(p, err)
	}
	for _, tc := range [][2]string{{"X-Forwarded-For", ""}, {"", "10.0.0.0/8"}, {"CF-Connecting-IP", "127.0.0.1"}, {"CF-Connecting-IP", "0.0.0.0/0"}, {"CF-Connecting-IP", "127.0.0.0/8,::/0"}, {"Forwarded", "10.0.0.0/8"}} {
		if _, err := ParseHostedProxy(tc[0], tc[1]); err == nil {
			t.Errorf("%q %q accepted", tc[0], tc[1])
		}
	}

	for _, address := range []string{"0.0.0.0:8080", "127.0.0.1:8098", "[::]:8080", "10.0.0.5:80"} {
		if err := ValidateHostedHTTPAddress(address); err != nil {
			t.Errorf("%s refused: %v", address, err)
		}
	}
	for _, address := range []string{"", ":8080", "localhost:8080", "0.0.0.0", "0.0.0.0:0", "0.0.0.0:65536", "0.0.0.0:http", "[fe80::1%eth0]:8080", "224.0.0.1:8080"} {
		if err := ValidateHostedHTTPAddress(address); err == nil {
			t.Errorf("%q accepted", address)
		}
	}

	hosted := ServeOptions{Hosted: true, HostedHTTPAddress: "0.0.0.0:8080", HostedProxy: albProxy}
	if err := validateHostedServing(hosted); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ServeOptions){
		"address without hosted": func(o *ServeOptions) { o.Hosted = false; o.HostedProxy = nil },
		"proxy without hosted":   func(o *ServeOptions) { o.Hosted = false; o.HostedHTTPAddress = "" },
		"with dev address":       func(o *ServeOptions) { o.DevHTTPAddress = "127.0.0.1:18080" },
		"bad address":            func(o *ServeOptions) { o.HostedHTTPAddress = "localhost:8080" },
		"bad proxy":              func(o *ServeOptions) { o.HostedProxy = &HostedProxy{Header: HostedProxyXForwardedFor} },
	} {
		o := hosted
		mutate(&o)
		if err := validateHostedServing(o); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// ServeContext refuses the options outside hosted mode before touching a database.
	project := &Project{rt: testRT, Cache: t.TempDir()}
	for _, opts := range []ServeOptions{{HostedProxy: tunnelProxy}, {HostedHTTPAddress: "127.0.0.1:18098"}} {
		if err := ServeContext(context.Background(), project, opts); err == nil || !strings.Contains(err.Error(), "--hosted") {
			t.Fatalf("non-hosted serving accepted proxy options: %v", err)
		}
	}
}

// The hosted public handler applies the proxy before limiters and strips every
// client-address header before the application; native HTTPS ignores them.
func TestHostedProxyHandlerRewritesAndStrips(t *testing.T) {
	forged := map[string]string{
		"X-Forwarded-For":  "198.51.100.1, 203.0.113.9",
		"CF-Connecting-IP": "203.0.113.20",
		"True-Client-IP":   "198.51.100.2",
		"X-Real-IP":        "198.51.100.3",
		"Forwarded":        "for=198.51.100.4",
	}
	for _, tc := range []struct {
		name   string
		opts   publicHandlerOptions
		peer   string
		client string
	}{
		{"alb", publicHandlerOptions{hosted: true, proxy: albProxy}, "10.0.3.4:5555", "203.0.113.9:0"},
		{"tunnel", publicHandlerOptions{hosted: true, proxy: tunnelProxy}, "127.0.0.1:5555", "203.0.113.20:0"},
		{"untrusted peer", publicHandlerOptions{hosted: true, proxy: tunnelProxy}, "192.0.2.50:5555", "192.0.2.50:5555"},
		{"hosted without proxy", publicHandlerOptions{hosted: true}, "127.0.0.1:5555", "127.0.0.1:5555"},
		{"native ignores proxy", publicHandlerOptions{proxy: tunnelProxy}, "127.0.0.1:5555", "127.0.0.1:5555"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.RemoteAddr != tc.client {
					t.Errorf("remote address %q, want %q", r.RemoteAddr, tc.client)
				}
				for name := range forged {
					if r.Header.Get(name) != "" {
						t.Errorf("%s reached the application", name)
					}
				}
				w.WriteHeader(http.StatusNoContent)
			})
			h := newPublicHandler(testRT, nil, "knowledge.example.com", next, tc.opts, nil)
			r := httptest.NewRequest("GET", "https://knowledge.example.com/", nil)
			r.RemoteAddr = tc.peer
			for name, v := range forged {
				r.Header.Set(name, v)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if !called || w.Code != http.StatusNoContent {
				t.Fatalf("not served: %d %s", w.Code, w.Body)
			}
		})
	}
	// The handler native HTTPS serving composes (publicHandler) has no proxy.
	h := publicHandler(testRT, nil, "knowledge.example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "127.0.0.1:5555" || r.Header.Get("CF-Connecting-IP") != "" || r.Header.Get("True-Client-IP") != "" {
			t.Errorf("native HTTPS used a forwarded address: %q", r.RemoteAddr)
		}
	}))
	r := httptest.NewRequest("GET", "https://knowledge.example.com/", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("CF-Connecting-IP", "203.0.113.20")
	r.Header.Set("True-Client-IP", "203.0.113.21")
	h.ServeHTTP(httptest.NewRecorder(), r)
}

// Two clients behind one proxy get separate per-address buckets on the
// six-digit code route, while one client still reaches its own limit.
func TestHostedProxySeparateCodeBuckets(t *testing.T) {
	a := newTestApp(t)
	limiter := &publicAuthLimiter{}
	reached := map[string]int{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached[r.RemoteAddr]++
		w.WriteHeader(http.StatusBadRequest)
	})
	h := newPublicHandler(testRT, a.app, "knowledge.example.com", next, publicHandlerOptions{hosted: true, proxy: tunnelProxy, limiter: limiter}, nil)
	send := func(client string) int {
		r := httptest.NewRequest("POST", "http://knowledge.example.com"+OTPCodePath, strings.NewReader(`{}`))
		r.RemoteAddr = "127.0.0.1:40000"
		r.Header.Set("CF-Connecting-IP", client)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	// The instance-wide redemption budget equals the per-address one, so spend
	// the first client's address budget directly; the route then refuses it.
	for i := 0; i < 10; i++ {
		limiter.allow("203.0.113.9:0")
	}
	if code := send("203.0.113.9"); code != http.StatusTooManyRequests {
		t.Fatalf("exhausted client admitted: %d", code)
	}
	if code := send("203.0.113.10"); code != http.StatusBadRequest {
		t.Fatalf("second client shared the first client's bucket: %d", code)
	}
	if reached["203.0.113.10:0"] != 1 || reached["203.0.113.9:0"] != 0 {
		t.Fatalf("unexpected requests reached the route: %v", reached)
	}
	if _, ok := limiter.entries["127.0.0.1"]; ok {
		t.Fatal("the proxy's own address was charged")
	}
}

// OAuth authorization limits each client behind the proxy separately.
func TestHostedProxySeparateOAuthBuckets(t *testing.T) {
	f := newOAuthFixture(t)
	f.o.hosted = true
	h := newPublicHandler(testRT, f.a.app, "knowledge.example.com", http.NotFoundHandler(), publicHandlerOptions{hosted: true, proxy: albProxy}, f.o)
	send := func(client string) int {
		r := httptest.NewRequest("POST", "http://knowledge.example.com/oauth/authorize", strings.NewReader(`{"approve":true}`))
		r.RemoteAddr = "10.0.3.4:5555"
		// A forged leftmost entry that changes per request has no effect.
		r.Header.Set("X-Forwarded-For", "198.51.100."+client[len(client)-1:]+", "+client)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 10; i++ {
		if code := send("203.0.113.9"); code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d limited early", i+1)
		}
	}
	if code := send("203.0.113.9"); code != http.StatusTooManyRequests {
		t.Fatalf("client reached no limit: %d", code)
	}
	if code := send("203.0.113.8"); code == http.StatusTooManyRequests {
		t.Fatal("second client shared the first client's bucket")
	}
}

// PocketBase sees the proxied client as its remote address, and a stored
// trusted-proxy setting can never make it read a header on its own.
func TestHostedProxyPocketBaseAddress(t *testing.T) {
	a := newTestApp(t)
	a.user.SetEmail("owner@example.test")
	if err := a.app.Save(a.user); err != nil {
		t.Fatal(err)
	}
	settings := a.app.Settings()
	settings.TrustedProxy = core.TrustedProxyConfig{Headers: []string{"X-Client-IP"}, UseLeftmostIP: true}
	if err := a.app.Save(settings); err != nil {
		t.Fatal(err)
	}
	if err := configureHosted(testRT, a.app, "knowledge.example.com", syntheticHostedConfig(), false); err != nil {
		t.Fatal(err)
	}
	if got := a.app.Settings().TrustedProxy; len(got.Headers) != 0 || got.UseLeftmostIP {
		t.Fatalf("trusted proxy kept: %+v", got)
	}
	if err := a.app.ReloadSettings(); err != nil {
		t.Fatal(err)
	}
	if got := a.app.Settings().TrustedProxy; len(got.Headers) != 0 {
		t.Fatalf("trusted proxy restored by a reload: %+v", got)
	}
	router, err := apis.NewRouter(a.app)
	if err != nil {
		t.Fatal(err)
	}
	router.GET("/{$}", func(re *core.RequestEvent) error { return re.String(200, re.RealIP()) })
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	h := newPublicHandler(testRT, a.app, "knowledge.example.com", mux, publicHandlerOptions{hosted: true, proxy: tunnelProxy}, nil)
	r := httptest.NewRequest("GET", "http://knowledge.example.com/", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("CF-Connecting-IP", "203.0.113.9")
	r.Header.Set("X-Client-IP", "198.51.100.1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "203.0.113.9" {
		t.Fatalf("PocketBase client address: %d %q", w.Code, w.Body)
	}
}

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	_ = ln.Close()
	return address
}

// The hosted listener binds HostedHTTPAddress, outlives a 60 s proxy idle
// timeout, and a loopback peer with forged client headers and the right local
// key still gains no local privilege, even under a policy admitting everything.
// (/api/bundle/instance and /api/bundle/auth-mode need no key and are not checked.)
func TestHostedHTTPAddressAndLoopbackPeerHasNoLocalPrivilege(t *testing.T) {
	cfg := fixtureConfig(func(string, string) bool { return true })
	rt, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, proxy := range []*HostedProxy{nil, tunnelProxy, {Header: HostedProxyXForwardedFor, Networks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}} {
		a := newTestAppRT(t, rt)
		p := &Project{rt: rt, Cache: t.TempDir(), DB: filepath.Join(t.TempDir(), "fixture.db"), Config: ProjectConfig{Port: 8096, Instance: "synthetic-instance"}}
		router, err := apis.NewRouter(a.app)
		if err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{}, 1)
		local := &localRoutes{p: p, key: "synthetic-local-key", stop: stop, hosted: true, mcp: true, publicURL: "https://knowledge.example.com"}
		if err := local.register(&core.ServeEvent{App: a.app, Router: router}); err != nil {
			t.Fatal(err)
		}
		mux, err := router.BuildMux()
		if err != nil {
			t.Fatal(err)
		}
		address := freeLoopbackAddress(t)
		opts := ServeOptions{Hosted: true, HTTPSDomain: "knowledge.example.com", MCP: true, MCPHandler: func(h http.Handler) http.Handler { return h }, HostedHTTPAddress: address, HostedProxy: proxy}
		failures := make(chan error, 1)
		servers, err := startHostedHTTP(context.Background(), a.app, p, opts, mux, failures)
		if err != nil {
			t.Fatal(err)
		}
		if got := servers.plainListener.Addr().String(); got != address {
			t.Fatalf("listening on %s, want %s", got, address)
		}
		if servers.http.IdleTimeout <= 75*time.Second {
			t.Fatalf("idle timeout %s does not outlive a 60 s proxy idle timeout", servers.http.IdleTimeout)
		}
		client := &http.Client{Timeout: 10 * time.Second}
		do := func(method, path string, headers map[string]string) (int, string) {
			r, err := http.NewRequest(method, "http://"+address+path, strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "knowledge.example.com"
			for k, v := range headers {
				r.Header.Set(k, v)
			}
			resp, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(body)
		}
		if code, _ := do("GET", "/up", nil); code != 200 {
			t.Fatalf("health check: %d", code)
		}
		for _, forged := range []map[string]string{
			{"CF-Connecting-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1"},
			{"CF-Connecting-IP": "203.0.113.9", "X-Forwarded-For": "127.0.0.1, 203.0.113.9"},
			{"CF-Connecting-IP": "::1", "X-Forwarded-For": "203.0.113.9, ::1", "X-Real-IP": "127.0.0.1", "True-Client-IP": "127.0.0.1"},
		} {
			forged[keyHeader] = local.key
			forged["Content-Type"] = "application/json"
			for _, route := range [][2]string{{"POST", "/api/bundle/name"}, {"POST", "/api/bundle/account"}, {"POST", "/api/bundle/token"}, {"POST", "/api/bundle/login-code"}, {"POST", "/api/bundle/flush"}, {"POST", "/api/bundle/stop"}} {
				if code, body := do(route[0], route[1], forged); code != http.StatusForbidden && code != http.StatusNotFound {
					t.Fatalf("proxy %v: %s %s reached local management: %d %s", proxy, route[0], route[1], code, body)
				}
			}
		}
		select {
		case <-stop:
			t.Fatal("a public request stopped the server")
		default:
		}
		servers.close()
	}
}
