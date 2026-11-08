package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
)

// Exercise the exact raw transport used by a headless server, with only a local relay.
func TestSocketBackendPreservesHostAndAuthentication(t *testing.T) {
	// A short temp path also fits Darwin's socket path limit.
	dir := t.TempDir()
	socket := filepath.Join(dir, "s")
	if len(socket) >= 104 {
		t.Skip("test temporary socket path exceeds platform limit")
	}
	backend, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	const servicePort = 18096
	web := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != fmt.Sprintf("127.0.0.1:%d", servicePort) {
			http.Error(w, "bad host", 403)
			return
		}
		if r.Header.Get("X-PocketContext-Local-Key") != "" {
			t.Error("tunnel injected local management key")
		}
		if r.Header.Get("Authorization") != "user-token" {
			http.Error(w, "authenticate", 401)
			return
		}
		io.WriteString(w, "authenticated through socket")
	})}
	go web.Serve(backend)
	defer web.Close()
	id, err := LoadIdentity("fixture-cli", filepath.Join(t.TempDir(), "identity.json"), false)
	if err != nil {
		t.Fatal(err)
	}
	id.Region = localRelay(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan tailcat.Addr, 1)
	served := make(chan error, 1)
	go func() {
		served <- ServeBackend(ctx, servicePort, id, func(a tailcat.Addr) { ready <- a }, func() (net.Conn, error) { return net.Dial("unix", socket) })
	}()
	var address tailcat.Addr
	select {
	case address = <-ready:
	case err := <-served:
		t.Fatalf("server: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("server did not start")
	}
	ln, err := Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	forwarded := make(chan error, 1)
	go func() { forwarded <- Forward(ctx, "fixture-cli", address, ln, servicePort) }()
	c := &http.Client{Timeout: 20 * time.Second}
	for _, authenticated := range []bool{false, true} {
		req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/", nil)
		req.Host = fmt.Sprintf("127.0.0.1:%d", servicePort)
		if authenticated {
			req.Header.Set("Authorization", "user-token")
		}
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		want := 401
		if authenticated {
			want = 200
		}
		if res.StatusCode != want {
			t.Fatalf("status %d, want %d", res.StatusCode, want)
		}
	}
	cancel()
	select {
	case err := <-forwarded:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("forward did not stop")
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not stop")
	}
}
