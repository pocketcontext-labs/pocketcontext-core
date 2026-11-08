package appserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPublicUIDevOptions(t *testing.T) {
	valid := ServeOptions{PublicUIDev: true, UIDev: "http://127.0.0.1:5174", HTTPSDomain: "dev.example.test", Headless: true, Hosted: true, DevHTTPAddress: "127.0.0.1:18098"}
	if err := validatePublicUIDev(valid); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ServeOptions){
		func(o *ServeOptions) { o.PublicUIDev = false },
		func(o *ServeOptions) { o.UIDev = "" },
		func(o *ServeOptions) { o.HTTPSDomain = "" },
		func(o *ServeOptions) { o.Headless = false },
		func(o *ServeOptions) { o.Hosted = false },
		func(o *ServeOptions) { o.DevHTTPAddress = "0.0.0.0:18098" },
		func(o *ServeOptions) { o.DevHTTPAddress = "localhost:18098" },
		func(o *ServeOptions) { o.DevHTTPAddress = "127.0.0.1:80" },
		func(o *ServeOptions) { o.DevHTTPAddress = "127.0.0.1:65536" },
	} {
		bad := valid
		change(&bad)
		if validatePublicUIDev(bad) == nil {
			t.Fatalf("accepted unsafe options %+v", bad)
		}
	}
}

func TestPublicUIDevBoundaries(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		for _, key := range []string{"Authorization", "Cookie", keyHeader, "X-Forwarded-Host"} {
			if r.Header.Get(key) != "" {
				t.Errorf("credential/header reached Vite: %s", key)
			}
		}
		w.Header().Set("Set-Cookie", "private=upstream")
		w.Write([]byte("development asset"))
	}))
	defer upstream.Close()
	handler := uiDevTestHandler(t, upstream.URL, "dev.example.test")
	for _, p := range []string{"/", "/src/main.tsx", "/@vite/client", "/node_modules/.vite/deps/react.js", "/@fs/tmp/allowed/module.ts"} {
		r := httptest.NewRequest("GET", "https://dev.example.test"+p, nil)
		r.Header.Set("Authorization", "private-token")
		r.Header.Set("Cookie", "private-cookie")
		r.Header.Set("Origin", "https://dev.example.test")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, r)
		if rr.Code != 200 {
			t.Fatalf("%s: %d %s", p, rr.Code, rr.Body.String())
		}
		csp := rr.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "wss://dev.example.test") || strings.Contains(csp, "ws://localhost") || rr.Header().Get("Set-Cookie") != "" || rr.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("unsafe public dev headers: %v", rr.Header())
		}
	}
	before := calls.Load()
	for _, tc := range []struct{ method, path, host, origin, upgrade string }{
		{"GET", "/src/main.tsx", "evil.example.test", "", ""},
		{"GET", "/src/main.tsx", "dev.example.test", "https://evil.example.test", ""},
		{"GET", "/src/main.tsx", "dev.example.test", "http://dev.example.test", ""},
		{"GET", "/src/../private/key", "dev.example.test", "", ""},
		{"GET", "/src/%2fprivate", "dev.example.test", "", ""},
		{"POST", "/src/main.tsx", "dev.example.test", "", ""},
		{"GET", "/api/bundle/instance", "dev.example.test", "", ""},
		{"POST", "/api/bundle/stop", "dev.example.test", "", ""},
		{"GET", "/_/", "dev.example.test", "", ""},
		{"GET", "/.env", "dev.example.test", "", ""},
		{"GET", "/__ui_hmr", "dev.example.test", "", "websocket"},
		{"GET", "/__ui_hmr", "dev.example.test", "https://evil.example.test", "websocket"},
		{"GET", "/src/main.tsx", "dev.example.test", "https://dev.example.test", "websocket"},
	} {
		r := httptest.NewRequest(tc.method, "https://"+tc.host+tc.path, nil)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Upgrade", tc.upgrade)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, r)
		if rr.Code < 400 {
			t.Errorf("accepted unsafe request %+v: %d", tc, rr.Code)
		}
	}
	if calls.Load() != before {
		t.Fatal("rejected request reached Vite")
	}
	// Ordinary production public routing never exposes development module paths.
	prod := publicHandler(testRT, nil, "dev.example.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("production source reached downstream") }))
	rr := httptest.NewRecorder()
	prod.ServeHTTP(rr, httptest.NewRequest("GET", "https://dev.example.test/src/main.tsx", nil))
	if rr.Code != 404 {
		t.Fatalf("production exposes dev source: %d", rr.Code)
	}
}
