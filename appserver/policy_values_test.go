package appserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The values below are the application's, not core's. The fixture uses ones no
// shipped product has, so these tests fail if core falls back to a value of its own.

func TestOAuthScopeComesFromPolicy(t *testing.T) {
	f := newOAuthFixture(t)
	scope := testRT.cfg.Policy.OAuthScope
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"} {
		got, _ := f.request("GET", path, "", "", "", 200)["scopes_supported"].([]any)
		if len(got) != 1 || got[0] != scope {
			t.Fatalf("%s scopes_supported = %v", path, got)
		}
	}
	registered := f.request("POST", "/oauth/register", "", `{"redirect_uris":["https://client.example.com/callback"],"token_endpoint_auth_method":"none"}`, "application/json", 201)
	if registered["scope"] != scope {
		t.Fatalf("registration scope = %v", registered["scope"])
	}
	r := httptest.NewRequest("POST", "https://knowledge.example.com/mcp", strings.NewReader("{}"))
	r.RemoteAddr = "192.0.2.9:1234"
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if challenge := w.Header().Get("WWW-Authenticate"); w.Code != 401 || !strings.Contains(challenge, `scope="`+scope+`"`) {
		t.Fatalf("challenge = %d %q", w.Code, challenge)
	}
}

func TestPublicBodyLimitComesFromPolicy(t *testing.T) {
	limit := int(testRT.cfg.Policy.PublicBodyLimit)
	read := func(size int) (n int, err error) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := make([]byte, 32<<10)
			for err == nil {
				var m int
				m, err = r.Body.Read(buf)
				n += m
			}
		})
		r := httptest.NewRequest("POST", "https://knowledge.example.com/api/fixture/read", strings.NewReader(strings.Repeat("x", size)))
		publicHandler(testRT, nil, "knowledge.example.com", next).ServeHTTP(httptest.NewRecorder(), r)
		return n, err
	}
	var tooLarge *http.MaxBytesError
	if n, err := read(limit); n != limit || errors.As(err, &tooLarge) {
		t.Fatalf("a body at the limit was cut: %d bytes, %v", n, err)
	}
	if _, err := read(limit + 1); !errors.As(err, &tooLarge) || int(tooLarge.Limit) != limit {
		t.Fatalf("a body over the limit was read: %v", err)
	}
}

func TestHostedBudgetComesFromPolicy(t *testing.T) {
	a, h := hostedTestApp(t)
	budget := testRT.cfg.Policy.Hosted
	token, err := a.user.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	var last *httptest.ResponseRecorder
	for i := 0; i < budget.Burst+budget.PerSecond*2+1 && (last == nil || last.Code != 429); i++ {
		r := httptest.NewRequest("POST", "http://knowledge.example.com/api/fixture/read", strings.NewReader(`{}`))
		r.RemoteAddr = "192.0.2.60:1000"
		r.Header.Set("Authorization", token)
		r.Header.Set("Content-Type", "application/json")
		last = httptest.NewRecorder()
		h.ServeHTTP(last, r)
	}
	if last.Code != 429 || !strings.Contains(last.Body.String(), testRT.cfg.Text.BudgetExhausted) {
		t.Fatalf("budget not enforced: %d %s", last.Code, last.Body)
	}
	assertRateMetadata(t, last, budget.Label, budget.Burst, 1)
}

func TestHostedRefusedWithoutBudget(t *testing.T) {
	cfg := fixtureConfig(fixturePublicRoute)
	cfg.Policy.Hosted = HostedBudget{}
	rt, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := newTestApp(t)
	if err := configureHosted(rt, a.app, "knowledge.example.com", syntheticHostedConfig(), false); !errors.Is(err, errNoHostedMode) {
		t.Fatalf("configureHosted: %v", err)
	}
	p := &Project{rt: rt, DB: t.TempDir() + "/fixture.db", Cache: t.TempDir()}
	opts := ServeOptions{Hosted: true, Headless: true, MCP: true, HTTPSDomain: "knowledge.example.com", MCPHandler: func(h http.Handler) http.Handler { return h }, HostedConfig: syntheticHostedConfig()}
	if err := ServeContext(context.Background(), p, opts); !errors.Is(err, errNoHostedMode) {
		t.Fatalf("ServeContext: %v", err)
	}
	if _, err := rt.NewTestServer(a.app, TestServerOptions{Domain: "knowledge.example.com", Hosted: true, HostedConfig: syntheticHostedConfig()}); !errors.Is(err, errNoHostedMode) {
		t.Fatalf("NewTestServer: %v", err)
	}
}

func TestHostedEmailLinksToTheApplicationLoginPath(t *testing.T) {
	a, _ := hostedTestApp(t)
	users, err := a.app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	want := `href="https://knowledge.example.com/#/fixture-login?otpId={OTP_ID}&amp;otp={OTP}"`
	if body := users.OTP.EmailTemplate.Body; !strings.Contains(body, want) {
		t.Fatalf("email body: %s", body)
	}
}

// An application with no earlier releases states that with empty lists.
func TestNoLegacySchemaRefusesNothingOfAnotherApplication(t *testing.T) {
	cfg := fixtureConfig(fixturePublicRoute)
	cfg.Policy.Legacy = LegacySchema{Migrations: []string{}, Tables: []string{}}
	if _, err := New(cfg); err != nil {
		t.Fatal(err)
	}
}
