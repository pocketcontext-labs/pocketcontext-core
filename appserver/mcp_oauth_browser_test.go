package appserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
)

// Synthetic account state and test TLS only. Browser approval proves the consent
// UI and reader handoff integrate. CORE_PLAYWRIGHT_PACKAGE_JSON names a
// package.json whose dependencies include Playwright.
func TestMCPOAuthBrowser(t *testing.T) {
	if os.Getenv("CORE_MCP_BROWSER_TEST") != "1" {
		t.Skip("opt-in Playwright OAuth browser test")
	}
	t.Setenv(testRT.cfg.Identity.EnvPrefix+"_MCP_REDIRECT_EXCEPTIONS", `["cursor://anysphere.cursor-mcp/oauth/callback"]`)
	a := newTestApp(t)
	p := &Project{rt: testRT, Cache: t.TempDir(), Config: ProjectConfig{Port: 8123, Instance: "synthetic-oauth"}}
	router, err := apis.NewRouter(a.app)
	if err != nil {
		t.Fatal(err)
	}
	local := &localRoutes{p: p, publicURL: "https://knowledge.example.com", mcp: true}
	local.register(&core.ServeEvent{App: a.app, Router: router})
	registerReader(&core.ServeEvent{App: a.app, Router: router}, filepath.Join(testAssetsDir(), "ui", "dist"))
	if err := a.app.OnServe().Trigger(&core.ServeEvent{App: a.app, Router: router}); err != nil {
		t.Fatal(err)
	}
	handler, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := newMCPOAuth(a.app, p, "knowledge.example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if MCPAuthToken(r.Context()) == "" {
			t.Error("missing account")
		}
		oauthJSON(w, 200, map[string]bool{"authenticated": true})
	}))
	if err != nil {
		t.Fatal(err)
	}
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	tlsConfig := cert.TLS.Clone()
	cert.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	servers, err := startPublicListeners(ctx, publicHandler(testRT, a.app, "knowledge.example.com", handler, oauth), publicHTTPHandler("knowledge.example.com", func(h http.Handler) http.Handler { return h }), tlsConfig, "127.0.0.1:0", "127.0.0.1:0", make(chan error, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer servers.close()
	code, _ := local.codes.issue(a.user.Id, 2*time.Minute)
	_, port, _ := net.SplitHostPort(servers.tlsListener.Addr().String())
	commandCtx, done := context.WithTimeout(context.Background(), 90*time.Second)
	defer done()
	command := exec.CommandContext(commandCtx, "node", filepath.Join("testdata", "mcp_oauth_browser.mjs"))
	command.Env = append(os.Environ(), "POCKETCONTEXT_SYNTHETIC_SIGNIN=https://knowledge.example.com/bundle/login#"+code, "POCKETCONTEXT_SYNTHETIC_PORT="+port)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("OAuth browser: %v\n%s", err, output)
	}
	t.Log(string(output))
}
