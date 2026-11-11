package appserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/plugins/jsvm"
	"github.com/dop251/goja"

	"github.com/pocketcontext-labs/pocketcontext-core/appserver/internal/testapp"
	"github.com/pocketcontext-labs/pocketcontext-core/maintenance"
	"github.com/pocketcontext-labs/pocketcontext-core/mcpobserve"
)

const fixtureEmail = "me@fixture.localhost"

var testRT = mustTestRuntime()

// keyHeader is the fixture's non-default header, so a hardcoded name in core fails.
var keyHeader = testRT.cfg.Identity.LocalKeyHeader

func fixtureConfig(public func(method, path string) bool) Config {
	return Config{
		Identity: testapp.Identity(), Version: "fixture-release", Commit: "fixturecommit", Assets: testapp.Assets(),
		Policy: Policy{
			PublicRoute: func(core.App) func(string, string) bool { return public },
			Maintenance: maintenance.Policy{ReadPosts: map[string]bool{"/api/fixture/read": true}, ReadGets: map[string]bool{}},
			Observe:     mcpobserve.Policy{Tools: []string{"fixture_tool"}, APIRoutes: []string{"/api/fixture/read"}},
			// Values unlike any shipped product's, so a hardcoded one in core fails.
			OAuthScope: "fixture.read", PublicBodyLimit: 64 << 10,
			Legacy: LegacySchema{Migrations: []string{"1700000000_fixture_old.js"}, Tables: []string{"fixture_members"}, Description: "fixture groups"},
			Hosted: HostedBudget{Label: "fixture_account", Burst: 50, PerSecond: 5},
		},
		Text: Text{
			AccountName: "Fixture Account", LegacyRecreateHint: "Keep the earlier fixture release or recreate its data.",
			OAuthResourceName: "Fixture memory", BudgetExhausted: "Fixture budget exhausted. Retry after the indicated delay.",
			OTPSubject: "Log in to Fixture", OTPSenderName: "Fixture Sender", OTPLoginPath: "/#/fixture-login",
			OAuthConsent: OAuthConsentText{ConnectionsHTML: "<p>These apps can read fixture notes.</p>", RequestHTML: "<p><strong>{{.Name}}</strong> is asking for fixture access.</p>",
				SignInHTML: `If you are not signed in, open your fresh {{.Product}} reader sign-in link in another tab of this browser, then return here. Your setup agent can issue one with <code>open --public</code>. You can also <a href="/" target="_blank" rel="noopener">open the reader</a> and use your password if you set one.`},
		},
	}
}

func mustTestRuntime() *Runtime {
	rt, err := New(fixtureConfig(fixturePublicRoute))
	if err != nil {
		panic(err)
	}
	return rt
}

// testAssetsDir is the on-disk fixture for tests that run the migrations.
func testAssetsDir() string {
	return filepath.Join("internal", "testapp", "assets")
}

// fixturePublicRoute plays a product allowlist for the boundary tests.
func fixturePublicRoute(method, p string) bool {
	read := method == http.MethodGet || method == http.MethodHead
	if read && (p == "/" || p == "/api/bundle/auth-mode" || p == "/bundle/login" || p == "/bundle/login.js" || p == "/api/realtime" || p == "/api/fixture/schema") {
		return true
	}
	if read && strings.HasPrefix(p, "/assets/") && ReaderAssetName(strings.TrimPrefix(p, "/assets/")) {
		return true
	}
	if method == http.MethodPost {
		switch p {
		case "/api/fixture/read", "/api/bundle/redeem", "/api/collections/users/auth-with-password", "/api/collections/users/auth-refresh", "/api/realtime":
			return true
		}
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) >= 4 && parts[0] == "api" && parts[1] == "collections" && parts[2] == "greetings" && parts[3] == "records" {
		if len(parts) == 4 {
			return read || method == http.MethodPost
		}
		return len(parts) == 5 && parts[4] != "" && (read || method == http.MethodPatch)
	}
	return false
}

// fixtureRoutes stands in for a product API behind the public allowlist. The
// read route answers 400 for an empty body so authentication is distinguishable.
func fixtureRoutes(e *core.ServeEvent) error {
	e.Router.POST("/api/fixture/read", func(re *core.RequestEvent) error {
		var body struct {
			Collection string `json:"collection"`
		}
		if err := re.BindBody(&body); err != nil || body.Collection == "" {
			return re.BadRequestError("Collection required.", nil)
		}
		return re.JSON(http.StatusOK, map[string]string{"collection": body.Collection})
	}).Bind(apis.RequireAuth("users"))
	e.Router.GET("/api/fixture/schema", func(re *core.RequestEvent) error {
		return re.JSON(http.StatusOK, map[string]string{"fixture": "schema"})
	}).Bind(apis.RequireAuth("users"))
	return nil
}

type testApp struct {
	app     core.App
	handler http.Handler
	token   string
	user    *core.Record
}

func (a *testApp) request(t *testing.T, method, path, token, body string, want int) map[string]any {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	response := httptest.NewRecorder()
	a.handler.ServeHTTP(response, req)
	if response.Code != want {
		t.Fatalf("%s %s: %d %s; want %d", method, path, response.Code, response.Body, want)
	}
	var data map[string]any
	_ = json.Unmarshal(response.Body.Bytes(), &data)
	return data
}

func fixtureHooks(vm *goja.Runtime) map[string]any {
	return map[string]any{"fixtureBinding": func() string { return "bound" }}
}

// newTestApp runs the fixture migrations and hooks on an isolated database and
// creates the project's one account.
func newTestApp(t *testing.T) *testApp {
	t.Helper()
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	jsvm.MustRegister(app, hooksConfig(testRT, testAssetsDir(), ""))
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	if err := app.RunAllMigrations(); err != nil {
		t.Fatal(err)
	}
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		if err := fixtureRoutes(e); err != nil {
			return err
		}
		return e.Next()
	})
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.OnServe().Trigger(&core.ServeEvent{App: app, Router: router}); err != nil {
		t.Fatal(err)
	}
	handler, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	u := core.NewRecord(users)
	u.SetEmail(fixtureEmail)
	u.SetPassword("synthetic-password")
	u.SetVerified(true)
	if err := app.Save(u); err != nil {
		t.Fatal(err)
	}
	token, err := u.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	return &testApp{app: app, handler: handler, token: token, user: u}
}
