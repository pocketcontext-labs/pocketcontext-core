package appserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/pocketcontext-labs/pocketcontext-core/atomicfile"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"golang.org/x/crypto/acme"
)

type noACMENetwork struct{ t *testing.T }

func (r noACMENetwork) RoundTrip(*http.Request) (*http.Response, error) {
	r.t.Error("cached certificate unexpectedly contacted ACME")
	return nil, errors.New("test refuses external ACME")
}

func TestPublicCertificateCachedTLSAcrossRestart(t *testing.T) {
	const domain = "knowledge.example.com"
	p := &Project{rt: testRT, Cache: t.TempDir()}
	opts := ServeOptions{HTTPSDomain: domain}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var cached bytes.Buffer
	if err := pem.Encode(&cached, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}); err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(&cached, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	first, _, err := publicCertificateManager(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Cache.Put(context.Background(), domain, cached.Bytes()); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(cert)
	// Each iteration creates a fresh manager with no in-memory state, then runs
	// a real verified TLS handshake using the shared persistent certificate cache.
	for i := 0; i < 2; i++ {
		manager, config, err := publicCertificateManager(p, opts)
		if err != nil {
			t.Fatal(err)
		}
		manager.Client = &acme.Client{HTTPClient: &http.Client{Transport: noACMENetwork{t}}}
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
		s.TLS = config
		s.StartTLS()
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: domain}}, Timeout: 5 * time.Second}
		response, err := client.Get(s.URL)
		if err != nil {
			s.Close()
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 204 || len(response.TLS.PeerCertificates) != 1 || !bytes.Equal(response.TLS.PeerCertificates[0].Raw, der) {
			t.Fatal("cached certificate was not served")
		}
		client.CloseIdleConnections()
		s.Close()
	}
}

func TestPublicHTTPSRejectsAmbiguousPaths(t *testing.T) {
	a := newTestApp(t)
	calls := 0
	h := publicHandler(testRT, a.app, "knowledge.example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }))
	for _, p := range []string{"/api/bundle/%2e%2e/token", "/api/files/sources/id/foo%2fbar.txt", "/api/files/sources/id/foo%5cbar.txt", "/api//spaces/default", "/api/collections/spaces/records/../users", "/api/collections/users/records", "/api/collections/_superusers/records", "/api/batch", "/assets/../bundle/token"} {
		r := httptest.NewRequest("GET", "https://knowledge.example.com"+p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if calls != 0 {
		t.Fatal("ambiguous path reached application")
	}
	for _, p := range []string{"/api/files/sources/id/note.foo%2Bbar", "/api/files/sources/id/note.foo%3Dbar"} {
		r := httptest.NewRequest("GET", "https://knowledge.example.com"+p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Errorf("retired file route %s exposed: %d", p, w.Code)
		}
	}
}

func TestPublicHTTPSecondBindFailureReleasesTLSListener(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	candidate, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := candidate.Addr().String()
	candidate.Close()
	_, err = startPublicListeners(context.Background(), http.NotFoundHandler(), http.NotFoundHandler(), &tls.Config{}, address, occupied.Addr().String(), make(chan error, 2))
	if err == nil || !strings.Contains(err.Error(), "HTTP port 80") {
		t.Fatal("missing second-listener bind error", err)
	}
	reuse, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal("failed startup leaked first listener", err)
	}
	reuse.Close()
}

func TestPublicBindFailureClosesPrivateServer(t *testing.T) {
	// Exercise the production path with an occupied HTTPS port. Platforms that
	// cannot reserve privileged ports still run the ephemeral listener tests.
	occupied, err := net.Listen("tcp", ":443")
	if err != nil {
		// A denied low port or an already occupied port exercises the same
		// production failure path without changing process privileges.
		t.Log("HTTPS port unavailable; checking its startup failure:", err)
	} else {
		defer occupied.Close()
	}
	a := newTestApp(t)
	p := &Project{rt: testRT, Cache: t.TempDir(), Key: atomicfile.RandomHex(8), Config: ProjectConfig{Port: 8096, Instance: "synthetic"}}
	if err := os.Chmod(p.Cache, 0700); err != nil {
		t.Fatal(err)
	}
	local := &localRoutes{p: p, key: "synthetic", stop: make(chan struct{}, 1)}
	a.app.OnServe().BindFunc(func(e *core.ServeEvent) error { local.register(e); return e.Next() })
	companionStarted := false
	err = serveHTTP(a.app, p, ServeOptions{Headless: true, HTTPSDomain: "knowledge.example.com", Service: func(context.Context) error { companionStarted = true; return nil }}, local.stop, local)
	if err == nil || !strings.Contains(err.Error(), "HTTPS port 443") {
		t.Fatal("missing public bind failure", err)
	}
	if companionStarted {
		t.Fatal("companion started before public listeners were ready")
	}
	if _, err := Health(p); err == nil {
		t.Fatal("private server remained reachable after public bind failure")
	}
	socket, err := p.SocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatal("private socket remained after startup failure", err)
	}
	// Rebinding proves that startup failure did not leave the private listener
	// owned by an orphaned http.Server goroutine.
	listener, err := listenSocket(p)
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
}

func TestPublicHTTPSOwnsCompanionLifetime(t *testing.T) {
	// No TLS handshake is made here, so this lifecycle test never contacts a CA.
	reservations := []net.Listener{}
	for _, address := range []string{":80", ":443"} {
		ln, err := net.Listen("tcp", address)
		if err != nil {
			for _, held := range reservations {
				held.Close()
			}
			t.Skip("standard public ports unavailable:", err)
		}
		reservations = append(reservations, ln)
	}
	for _, ln := range reservations {
		ln.Close()
	}
	a := newTestApp(t)
	p := &Project{rt: testRT, Cache: t.TempDir(), Key: atomicfile.RandomHex(8), Config: ProjectConfig{Port: 8096, Instance: "synthetic"}}
	if err := os.Chmod(p.Cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.KeyFile(), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	local := &localRoutes{p: p, key: "synthetic", stop: make(chan struct{}, 1)}
	a.app.OnServe().BindFunc(func(e *core.ServeEvent) error { local.register(e); return e.Next() })
	started, stopped := make(chan struct{}), make(chan struct{})
	service := func(ctx context.Context) error { close(started); <-ctx.Done(); close(stopped); return ctx.Err() }
	done := make(chan error, 1)
	go func() {
		done <- serveHTTP(a.app, p, ServeOptions{Headless: true, HTTPSDomain: "knowledge.example.com", Service: service}, local.stop, local)
	}()
	defer func() {
		select {
		case local.stop <- struct{}{}:
		default:
		}
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatal("startup failed", err)
	case <-time.After(5 * time.Second):
		t.Fatal("companion did not start")
	}
	info, err := Health(p)
	if err != nil || info.PublicURL != "https://knowledge.example.com" || info.TCP {
		t.Fatalf("incorrect public readiness: %+v %v", info, err)
	}
	if _, err := LocalCall(p, "/api/bundle/stop", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("public server did not stop")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("server returned before companion cleanup")
	}
	if _, err := Health(p); err == nil {
		t.Fatal("private server still running")
	}
	for _, address := range []string{":80", ":443"} {
		ln, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal("public listener leaked", err)
		}
		ln.Close()
	}
}
