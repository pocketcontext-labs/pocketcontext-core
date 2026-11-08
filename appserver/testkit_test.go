package appserver

import (
	"net/http/httptest"
	"testing"
)

func TestTestServerUsesRealPublicPolicy(t *testing.T) {
	a := newTestApp(t)
	if _, err := testRT.NewTestServer(a.app, TestServerOptions{}); err == nil {
		t.Fatal("test server without a domain accepted")
	}
	s, err := testRT.NewTestServer(a.app, TestServerOptions{Domain: "app.example.com", Cache: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://app.example.com/api/health", nil)
	r.RemoteAddr = "192.0.2.1:1"
	w := httptest.NewRecorder()
	s.Public().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("/api/health on the public listener: %d", w.Code)
	}
	if s.Project() == nil || s.Router() == nil {
		t.Fatal("test server incomplete")
	}
}
