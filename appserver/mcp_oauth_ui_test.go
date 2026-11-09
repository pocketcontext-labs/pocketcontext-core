package appserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func renderOAuthPage(t *testing.T, rt *Runtime, title, name, redirect string, connections, hosted bool) string {
	t.Helper()
	w := httptest.NewRecorder()
	(&mcpOAuth{rt: rt}).oauthPage(w, title, name, redirect, connections, hosted)
	return w.Body.String()
}

func oauthPageRuntime(t *testing.T, page OAuthPage) *Runtime {
	t.Helper()
	cfg := fixtureConfig(fixturePublicRoute)
	cfg.Text.OAuthConsent.Page = page
	rt, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// The golden files are the pages rendered before OAuthPage existed.
func TestOAuthPageDefaultRenderingUnchanged(t *testing.T) {
	for _, tc := range []struct {
		file                string
		connections, hosted bool
	}{
		{"consent", false, false},
		{"consent_hosted", false, true},
		{"connections", true, false},
		{"connections_hosted", true, true},
	} {
		t.Run(tc.file, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", "oauth_page_"+tc.file+".html"))
			if err != nil {
				t.Fatal(err)
			}
			title, name, redirect := "Authorize a connection", "Synthetic <client>", "https://client.example.com/callback?a=1&b=2"
			if tc.connections {
				title, name, redirect = "Connected apps", "", ""
			}
			if got := renderOAuthPage(t, testRT, title, name, redirect, tc.connections, tc.hosted); got != string(want) {
				t.Fatalf("default page changed:\n%s", got)
			}
		})
	}
}

func TestOAuthPageCustomPresentationEscapesClientValues(t *testing.T) {
	rt := oauthPageRuntime(t, OAuthPage{CSS: "body{color:#123456}", BrandHTML: `<div class="brand">Fixture brand</div>`, SignInPath: "/#/signin", ConnectionsPath: "/#/apps"})
	hostile := `<script>alert(1)</script>"'`
	page := renderOAuthPage(t, rt, "Authorize a connection", hostile, "https://client.example.com/cb?x=<img>", false, true)
	if strings.Contains(page, "<script>alert") || strings.Contains(page, "<img>") {
		t.Fatalf("client value not escaped:\n%s", page)
	}
	for _, want := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "<style>body{color:#123456}</style>", `<div class="brand">Fixture brand</div>`, `data-signin="/#/signin"`, `<a id="signin" hidden>Log in</a>`, `<a href="/#/apps">Manage connected apps</a>`} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q in:\n%s", want, page)
		}
	}
	for _, reject := range []string{"open the reader", "another tab", "#f5f3ed", `href="/oauth/connections"`} {
		if strings.Contains(page, reject) {
			t.Errorf("unexpected %q in:\n%s", reject, page)
		}
	}
	if strings.Count(page, "<script") != 1 {
		t.Fatalf("only the fixed script may load:\n%s", page)
	}
}

func TestOAuthPageSignInBranch(t *testing.T) {
	rt := oauthPageRuntime(t, OAuthPage{SignInPath: "/#/signin"})
	consent := renderOAuthPage(t, rt, "Authorize a connection", "Client", "https://client.example.com/cb", false, false)
	if !strings.Contains(consent, `id="signin"`) || strings.Contains(consent, "open --public") {
		t.Fatalf("sign-in action must replace the other-tab text:\n%s", consent)
	}
	// Connections has no return target the application accepts.
	connections := renderOAuthPage(t, rt, "Connected apps", "", "", true, false)
	if strings.Contains(connections, "signin") || !strings.Contains(connections, "open --public") || !strings.Contains(connections, `href="/oauth/connections"`) {
		t.Fatalf("connections page must keep its text:\n%s", connections)
	}
	script := oauthScript("synthetic.key")
	for _, want := range []string{`dataset.signin`, `e.code==="login_required"`, `encodeURIComponent(location.pathname+location.search)`, `if(signIn&&!token())showSignIn("")`} {
		if !strings.Contains(script, want) {
			t.Errorf("script lost %q", want)
		}
	}
	if strings.Contains(script, "location.replace") || strings.Count(script, "location.assign") != 1 {
		t.Fatal("the page must never navigate to sign-in on its own")
	}
}

func TestOAuthPageValidation(t *testing.T) {
	bad := map[string]OAuthPage{
		"closing style":      {CSS: "a{}</STYLE>"},
		"protocol relative":  {SignInPath: "//evil.example"},
		"backslash":          {SignInPath: `/\evil.example`},
		"absolute":           {SignInPath: "https://evil.example/"},
		"relative":           {SignInPath: "signin"},
		"query":              {SignInPath: "/signin?x=1"},
		"control":            {SignInPath: "/sign\tin"},
		"quote":              {ConnectionsPath: `/a"b`},
		"connections scheme": {ConnectionsPath: "javascript:alert(1)"},
		"self redirect":      {ConnectionsPath: "/oauth/connections"},
		"self with fragment": {ConnectionsPath: "/oauth/connections#x"},
	}
	for name, page := range bad {
		t.Run(name, func(t *testing.T) {
			cfg := fixtureConfig(fixturePublicRoute)
			cfg.Text.OAuthConsent.Page = page
			if _, err := New(cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	oauthPageRuntime(t, OAuthPage{SignInPath: "/#/signin", ConnectionsPath: "/#/connect"})
}

func TestOAuthConnectionsRedirectKeepsJSONAPI(t *testing.T) {
	f := newOAuthFixture(t)
	browser := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://knowledge.example.com/oauth/connections", nil)
		r.RemoteAddr = "192.0.2.77:1234"
		r.Header.Set("Accept", "text/html,application/xhtml+xml")
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		return w
	}
	if w := browser(); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="connections"`) {
		t.Fatalf("default page: %d %s", w.Code, w.Body)
	}
	f.o.rt = oauthPageRuntime(t, OAuthPage{ConnectionsPath: "/#/apps"})
	w := browser()
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/#/apps" || w.Body.Len() != 0 {
		t.Fatalf("redirect: %d %q %s", w.Code, w.Header().Get("Location"), w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("redirect lost headers: %v", w.Header())
	}
	if out := f.request("GET", "/oauth/connections", f.a.token, "", "", 200); out["connections"] == nil {
		t.Fatalf("JSON API changed: %v", out)
	}
	f.request("GET", "/oauth/connections", "", "", "", 401)
	f.request("POST", "/oauth/connections", "", `{"id":"x"}`, "application/json", 401)
}
