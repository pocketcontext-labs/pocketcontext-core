package appserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/plugins/jsvm"
	"github.com/dop251/goja"

	"github.com/pocketcontext-labs/pocketcontext-core/appserver/internal/testapp"
)

// multiRT is the AccountsMulti variant of the fixture application.
func multiRT(t *testing.T, allow func(core.App, string) (bool, error)) *Runtime {
	t.Helper()
	cfg := fixtureConfig(fixturePublicRoute)
	cfg.Policy.Accounts = AccountsMulti
	cfg.Hooks.AllowSignIn = allow
	cfg.Hooks.Bindings = func(*goja.Runtime) map[string]any {
		return map[string]any{testapp.MultiAccountBinding: func() bool { return true }}
	}
	rt, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// multiHostedTestApp is hostedTestAppRT for an AccountsMulti runtime, without
// the sign-in padding so tests stay fast.
func multiHostedTestApp(t *testing.T, rt *Runtime) (*testApp, http.Handler) {
	t.Helper()
	a, h := hostedTestAppRT(t, rt)
	hostedSignInFor(a.app).minDuration = 0
	return a, h
}

// migratedApp is a fixture database with no accounts, with the hooks of rt.
func migratedApp(t *testing.T, rt *Runtime) core.App {
	t.Helper()
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	jsvm.MustRegister(app, hooksConfig(rt, testAssetsDir(), ""))
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	if err := app.RunAllMigrations(); err != nil {
		t.Fatal(err)
	}
	return app
}

func addUser(t *testing.T, app core.App, email string, verified bool) *core.Record {
	t.Helper()
	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatal(err)
	}
	u := core.NewRecord(users)
	u.SetEmail(email)
	u.SetRandomPassword()
	u.SetVerified(verified)
	if err := app.Save(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestNewAccountsValidation(t *testing.T) {
	allow := func(core.App, string) (bool, error) { return true, nil }
	for name, mutate := range map[string]func(*Config){
		"unset accounts":        func(c *Config) { c.Policy.Accounts = 0 },
		"unknown accounts":      func(c *Config) { c.Policy.Accounts = 7 },
		"sign-in hook single":   func(c *Config) { c.Hooks.AllowSignIn = allow },
		"multi without hosted":  func(c *Config) { c.Policy.Accounts, c.Policy.Hosted = AccountsMulti, HostedBudget{} },
		"hook without accounts": func(c *Config) { c.Policy.Accounts, c.Hooks.AllowSignIn = 0, allow },
	} {
		c := fixtureConfig(fixturePublicRoute)
		mutate(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, mutate := range map[string]func(*Config){
		"single":         func(c *Config) {},
		"multi":          func(c *Config) { c.Policy.Accounts = AccountsMulti },
		"multi and hook": func(c *Config) { c.Policy.Accounts, c.Hooks.AllowSignIn = AccountsMulti, allow },
	} {
		c := fixtureConfig(fixturePublicRoute)
		mutate(&c)
		if _, err := New(c); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
}

func TestHostedMultiOwnerBootstrap(t *testing.T) {
	rt := multiRT(t, nil)
	hosted := func(app core.App, owner string, initialize bool) error {
		c := syntheticHostedConfig()
		c.OwnerEmail = owner
		return configureHosted(rt, app, "knowledge.example.com", c, initialize)
	}
	// Initialization stores the canonical owner address.
	fresh := migratedApp(t, rt)
	if err := hosted(fresh, "Owner@Example.test", true); err != nil {
		t.Fatal(err)
	}
	owner, err := fresh.FindAuthRecordByEmail("users", "owner@example.test")
	if err != nil || owner.Verified() || owner.GetString("name") != "Fixture Account" {
		t.Fatal("initialized owner", err)
	}
	if err := hosted(fresh, "owner@example.test", true); err == nil {
		t.Fatal("initialization repeated")
	}
	// Members beside the owner are kept; a case variant of OWNER_EMAIL is the
	// same owner, and a restart changes nothing.
	member := addUser(t, fresh, "member@example.test", true)
	for _, address := range []string{"owner@example.test", "OWNER@example.TEST", " owner@example.test "} {
		if err := hosted(fresh, address, false); err != nil {
			t.Fatalf("%q: %v", address, err)
		}
	}
	if n, _ := fresh.CountRecords("users"); n != 2 {
		t.Fatal("accounts changed", n)
	}
	again, err := fresh.FindRecordById("users", owner.Id)
	if err != nil || again.TokenKey() != owner.TokenKey() {
		t.Fatal("restart changed the owner", err)
	}
	if kept, err := fresh.FindRecordById("users", member.Id); err != nil || kept.TokenKey() != member.TokenKey() {
		t.Fatal("restart changed a member", err)
	}
	collection, err := fresh.FindCollectionByNameOrId("users")
	if err != nil || collection.PasswordAuth.Enabled || !collection.OTP.Enabled || collection.OTP.Length != 32 || collection.OTP.Duration != 900 {
		t.Fatal("hosted auth configuration mismatch", err)
	}
	if err := configureHosted(testRT, fresh, "knowledge.example.com", syntheticHostedConfig(), false); err == nil {
		t.Fatal("single-account mode accepted other accounts")
	}
	// An OWNER_EMAIL change is refused and creates nothing.
	if err := hosted(fresh, "typo@example.test", false); err == nil || !strings.Contains(err.Error(), "owner changes require explicit maintenance") {
		t.Fatalf("owner change: %v", err)
	}
	if err := hosted(fresh, member.Email(), false); err == nil {
		t.Fatal("a restart transferred ownership to a member")
	}
	if n, _ := fresh.CountRecords("users"); n != 2 {
		t.Fatal("owner change created an account", n)
	}
	// Accounts without the owner are refused; an empty database gets its owner.
	orphan := migratedApp(t, rt)
	addUser(t, orphan, "member@example.test", true)
	if err := hosted(orphan, "owner@example.test", false); err == nil {
		t.Fatal("database without its owner accepted")
	}
	empty := migratedApp(t, rt)
	if err := hosted(empty, "owner@example.test", false); err != nil {
		t.Fatal(err)
	}
	if n, _ := empty.CountRecords("users"); n != 1 {
		t.Fatal("empty database owner", n)
	}
	// A local database is never adopted, whatever the address case, even
	// beside an account with the owner address.
	for _, local := range []string{fixtureEmail, "ME@Fixture.localhost"} {
		app := migratedApp(t, rt)
		addUser(t, app, local, true)
		if err := hosted(app, "owner@example.test", false); err == nil {
			t.Fatalf("local database %q accepted", local)
		}
		addUser(t, app, "owner@example.test", false)
		if err := hosted(app, "owner@example.test", false); err == nil {
			t.Fatalf("local database %q with an owner accepted", local)
		}
	}
	// The local address and non-ASCII addresses are never owners.
	for _, address := range []string{fixtureEmail, "Me@Fixture.Localhost", "own\u212Aer@example.test", "\u017Fowner@example.test"} {
		if err := hosted(migratedApp(t, rt), address, true); err == nil {
			t.Fatalf("owner %q accepted", address)
		}
	}
}

func TestHostedMultiLegacyOwnerBinding(t *testing.T) {
	rt := multiRT(t, nil)
	app := migratedApp(t, rt)
	member := addUser(t, app, "member@example.test", true)
	owner := addUser(t, app, "owner@example.test", true)
	cfg := syntheticHostedConfig()
	start := func() error { return configureHosted(rt, app, "knowledge.example.com", cfg, false) }
	if err := start(); err == nil {
		t.Fatal("ambiguous legacy database started without an owner ID")
	}
	cfg.OwnerID = member.Id
	if err := start(); err == nil {
		t.Fatal("owner ID and owner email identify different users")
	}
	cfg.OwnerID = owner.Id
	if err := start(); err != nil {
		t.Fatal(err)
	}
	cfg.OwnerID = ""
	if err := start(); err != nil {
		t.Fatal("confirmed binding did not persist", err)
	}
	cfg.OwnerID, cfg.OwnerEmail = member.Id, member.Email()
	if err := start(); err == nil {
		t.Fatal("explicit ID overrode established ownership")
	}
}

type sentOTP struct{ email, otpID, password string }

// captureOTPMail records hosted sign-in emails instead of sending them.
func captureOTPMail(app core.App) chan sentOTP {
	sent := make(chan sentOTP, 32)
	app.OnMailerRecordOTPSend("users").BindFunc(func(e *core.MailerRecordEvent) error {
		otpID, _ := e.Meta["otpId"].(string)
		password, _ := e.Meta["password"].(string)
		sent <- sentOTP{e.Record.Email(), otpID, password}
		return nil
	})
	return sent
}

func waitOTPMail(t *testing.T, sent chan sentOTP) sentOTP {
	t.Helper()
	select {
	case m := <-sent:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no sign-in email sent")
	}
	return sentOTP{}
}

func requestOTP(h http.Handler, email string) *httptest.ResponseRecorder {
	return hostedRequest(h, "POST", "/api/collections/users/request-otp", fmt.Sprintf(`{"email":%q}`, email))
}

func TestHostedMultiAllowedSignInCreatesAccountAndSendsOTP(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	rt := multiRT(t, func(app core.App, email string) (bool, error) {
		mu.Lock()
		asked = append(asked, email)
		mu.Unlock()
		return strings.EqualFold(email, "new@example.test"), nil
	})
	a, h := multiHostedTestApp(t, rt)
	sent := captureOTPMail(a.app)
	w := requestOTP(h, "new@example.test")
	if w.Code != 200 {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	created, err := a.app.FindAuthRecordByEmail("users", "new@example.test")
	if err != nil || created.Verified() || created.GetString("name") != "Fixture Account" {
		t.Fatal("allowed address has no hosted account", err)
	}
	mail := waitOTPMail(t, sent)
	if mail.email != "new@example.test" || mail.otpID != out["otpId"] {
		t.Fatal("sign-in email does not match the request", mail.email)
	}
	// The emailed OTP signs the new account in, and only that account.
	w = hostedRequest(h, "POST", "/api/collections/users/auth-with-otp", fmt.Sprintf(`{"otpId":%q,"password":%q}`, mail.otpID, mail.password))
	if w.Code != 200 {
		t.Fatalf("redeem: %d %s", w.Code, w.Body)
	}
	var auth struct {
		Token  string `json:"token"`
		Record struct {
			ID string `json:"id"`
		} `json:"record"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &auth); err != nil || auth.Token == "" || auth.Record.ID != created.Id {
		t.Fatal("redeemed the wrong account", err)
	}
	if signedIn, err := a.app.FindRecordById("users", created.Id); err != nil || !signedIn.Verified() {
		t.Fatal("first sign-in did not verify the account", err)
	}
	// Existing accounts, the owner included, never reach the hook, and each
	// address has its own resend cooldown.
	if w := requestOTP(h, "owner@example.test"); w.Code != 200 {
		t.Fatalf("owner request: %d %s", w.Code, w.Body)
	}
	if waitOTPMail(t, sent).email != "owner@example.test" {
		t.Fatal("owner email not sent beside another account's")
	}
	if w := requestOTP(h, "owner@example.test"); w.Code != 200 {
		t.Fatalf("owner resend: %d %s", w.Code, w.Body)
	}
	if otps, err := a.app.FindAllOTPsByRecord(a.user); err != nil || len(otps) != 1 {
		t.Fatal("resend cooldown not applied", len(otps), err)
	}
	mu.Lock()
	defer mu.Unlock()
	// The hook is asked for every address that passes the cooldown,
	// existing accounts included, so its cost does not tell them apart.
	if !slices.Equal(asked, []string{"new@example.test", "owner@example.test"}) {
		t.Fatal("hook calls", asked)
	}
}

var otpIDPattern = regexp.MustCompile(`^[a-z0-9]{15}$`)

// otpResponseShape is everything a client can observe of a request-otp answer
// except the random id itself.
func otpResponseShape(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %s: %v", w.Body, err)
	}
	id, _ := body["otpId"].(string)
	if len(body) != 1 || !otpIDPattern.MatchString(id) {
		t.Fatalf("unexpected body %s", w.Body)
	}
	header := w.Header().Clone()
	encoded, _ := json.Marshal(header)
	return fmt.Sprintf("%d %s %s", w.Code, encoded, strings.Replace(w.Body.String(), id, "ID", 1))
}

func TestHostedMultiSignInResponsesIndistinguishable(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	rt := multiRT(t, func(app core.App, email string) (bool, error) {
		mu.Lock()
		calls[email]++
		mu.Unlock()
		switch email {
		case "allowed@example.test":
			return true, nil
		case "broken@example.test":
			return true, errors.New("synthetic directory failure for broken@example.test")
		}
		return false, nil
	})
	a, h := multiHostedTestApp(t, rt)
	sent := captureOTPMail(a.app)
	allowed := otpResponseShape(t, requestOTP(h, "allowed@example.test"))
	waitOTPMail(t, sent)
	for _, email := range []string{"denied@example.test", "broken@example.test", "denied@example.test"} {
		if got := otpResponseShape(t, requestOTP(h, email)); got != allowed {
			t.Fatalf("%s response differs:\n%s\n%s", email, got, allowed)
		}
	}
	// No hook: the same answer, nothing created.
	nilHook, nilHandler := multiHostedTestApp(t, multiRT(t, nil))
	if got := otpResponseShape(t, requestOTP(nilHandler, "denied@example.test")); got != allowed {
		t.Fatalf("nil hook response differs:\n%s\n%s", got, allowed)
	}
	// The single-account answer to an unknown address, as before.
	single, singleHandler := hostedTestApp(t)
	if got := otpResponseShape(t, requestOTP(singleHandler, "denied@example.test")); got != allowed {
		t.Fatalf("single-account response differs:\n%s\n%s", got, allowed)
	}
	for _, app := range []core.App{a.app, nilHook.app, single.app} {
		for _, email := range []string{"denied@example.test", "broken@example.test"} {
			if _, err := app.FindAuthRecordByEmail("users", email); err == nil {
				t.Fatal("account created for", email)
			}
		}
	}
	if n, _ := a.app.CountRecords("users"); n != 2 {
		t.Fatal("accounts", n)
	}
	if n, _ := a.app.CountRecords(core.CollectionNameOTPs); n != 1 {
		t.Fatal("OTPs beyond the allowed address", n)
	}
	select {
	case m := <-sent:
		t.Fatal("email sent to", m.email)
	case <-time.After(200 * time.Millisecond):
	}
	mu.Lock()
	defer mu.Unlock()
	// The resend cooldown applies before the hook: a repeated address is not asked again.
	if calls["denied@example.test"] != 1 || calls["broken@example.test"] != 1 || calls["allowed@example.test"] != 1 {
		t.Fatal("hook calls", calls)
	}
}

func TestHostedSingleNeverCallsAllowSignIn(t *testing.T) {
	// New refuses this combination; build it directly to prove the
	// single-account path never reaches the hook.
	cfg := fixtureConfig(fixturePublicRoute)
	called := false
	cfg.Hooks.AllowSignIn = func(core.App, string) (bool, error) { called = true; return true, nil }
	rt := &Runtime{cfg: cfg, oauthTemplate: testRT.oauthTemplate}
	a, h := multiHostedTestApp(t, rt)
	sent := captureOTPMail(a.app)
	if w := requestOTP(h, "absent@example.test"); w.Code != 200 {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	if w := requestOTP(h, "owner@example.test"); w.Code != 200 {
		t.Fatalf("owner: %d %s", w.Code, w.Body)
	}
	waitOTPMail(t, sent)
	if called {
		t.Fatal("single-account mode called AllowSignIn")
	}
	if n, _ := a.app.CountRecords("users"); n != 1 {
		t.Fatal("single-account mode created an account", n)
	}
}

func TestHostedMultiLocalRoutesActAsOwner(t *testing.T) {
	rt := multiRT(t, nil)
	app := migratedApp(t, rt)
	member := addUser(t, app, "member@example.test", true) // created before the owner
	owner := addUser(t, app, "owner@example.test", false)
	cfg := syntheticHostedConfig()
	cfg.OwnerID = owner.Id
	s, err := rt.NewTestServer(app, TestServerOptions{Domain: "knowledge.example.com", Hosted: true, HostedConfig: cfg})
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.local.account(app)
	if err != nil || user.Email() != "owner@example.test" || user.Id == member.Id {
		t.Fatal("local management does not act as the owner", err)
	}
}

type multiOAuth struct {
	*oauthFixture
	owner, member           *core.Record
	ownerToken, memberToken string
	client                  string
}

// newMultiOAuth is an OAuth fixture of a hosted AccountsMulti instance with
// the owner and one member, sharing one registered client.
func newMultiOAuth(t *testing.T) *multiOAuth {
	t.Helper()
	rt := multiRT(t, nil)
	a, _ := multiHostedTestApp(t, rt)
	ownerToken, err := a.user.NewAuthToken() // the fixture token predates the owner address
	if err != nil {
		t.Fatal(err)
	}
	member := addUser(t, a.app, "member@example.test", true)
	memberToken, err := member.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	p := &Project{rt: rt, Cache: t.TempDir(), Config: ProjectConfig{Instance: "synthetic-instance"}}
	adapter := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record, err := a.app.FindAuthRecordByToken(MCPAuthToken(r.Context()), core.TokenTypeAuth)
		if err != nil || r.Header.Get("Authorization") != "" {
			t.Error("invalid internal principal")
			oauthJSON(w, 500, map[string]string{})
			return
		}
		oauthJSON(w, 200, map[string]string{"user": record.Id})
	})
	o, err := newMCPOAuth(a.app, p, "knowledge.example.com", adapter)
	if err != nil {
		t.Fatal(err)
	}
	o.hosted = true
	f := &oauthFixture{t: t, a: a, o: o, p: p}
	f.h = publicHandler(rt, a.app, "knowledge.example.com", http.NotFoundHandler(), o)
	return &multiOAuth{oauthFixture: f, owner: a.user, member: member, ownerToken: ownerToken, memberToken: memberToken, client: f.registration()}
}

// connect authorizes the shared client for the account of token and exchanges
// the code, returning the token response's access token or "" on want != 200.
func (m *multiOAuth) connect(token, verifier string, want int) string {
	m.t.Helper()
	h := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {m.client}, "redirect_uri": {"https://client.example.com/callback"}, "response_type": {"code"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(h[:])}, "resource": {m.o.resource()}, "scope": {"fixture.read"}, "state": {"synthetic-state"}}
	out := m.request("POST", "/oauth/authorize?"+q.Encode(), token, `{"approve":true}`, "application/json", 200)
	u, err := url.Parse(out["redirect"].(string))
	if err != nil {
		m.t.Fatal(err)
	}
	access, _ := m.exchange(m.client, u.Query().Get("code"), verifier, want)["access_token"].(string)
	return access
}

func TestHostedMultiMCPKeepsAccountsApart(t *testing.T) {
	m := newMultiOAuth(t)
	f, a, rt := m.oauthFixture, m.a, m.p.rt
	owner, member, ownerToken, memberToken := m.owner, m.member, m.ownerToken, m.memberToken
	connect := func(token, verifier string) string { return m.connect(token, verifier, 200) }
	ownerAccess := connect(ownerToken, strings.Repeat("o", 64))
	memberAccess := connect(memberToken, strings.Repeat("m", 64))
	if got := f.request("POST", "/mcp", ownerAccess, "{}", "application/json", 200)["user"]; got != owner.Id {
		t.Fatal("owner grant reached", got)
	}
	if got := f.request("POST", "/mcp", memberAccess, "{}", "application/json", 200)["user"]; got != member.Id {
		t.Fatal("member grant reached", got)
	}
	connections := func(token string) []string {
		var ids []string
		for _, c := range f.request("GET", "/oauth/connections", token, "", "", 200)["connections"].([]any) {
			ids = append(ids, c.(map[string]any)["id"].(string))
		}
		return ids
	}
	ownerGrants, memberGrants := connections(ownerToken), connections(memberToken)
	if len(ownerGrants) != 1 || len(memberGrants) != 1 || ownerGrants[0] == memberGrants[0] {
		t.Fatal("connections not per account", ownerGrants, memberGrants)
	}
	// Neither account can revoke the other's grant.
	f.request("POST", "/oauth/connections", ownerToken, `{"id":"`+memberGrants[0]+`"}`, "application/json", 404)
	f.request("POST", "/oauth/connections", memberToken, `{"id":"`+ownerGrants[0]+`"}`, "application/json", 404)
	f.request("POST", "/mcp", memberAccess, "{}", "application/json", 200)
	f.request("POST", "/mcp", ownerAccess, "{}", "application/json", 200)
	// Revoking one's own grant leaves the other account connected.
	f.request("POST", "/oauth/connections", memberToken, `{"id":"`+memberGrants[0]+`"}`, "application/json", 200)
	f.request("POST", "/mcp", memberAccess, "{}", "application/json", 401)
	if got := f.request("POST", "/mcp", ownerAccess, "{}", "application/json", 200)["user"]; got != owner.Id {
		t.Fatal("owner grant lost with the member's", got)
	}
	if len(connections(memberToken)) != 0 || len(connections(ownerToken)) != 1 {
		t.Fatal("revocation crossed accounts")
	}
	// Restore invalidation covers every account.
	before := map[string]string{owner.Id: owner.TokenKey(), member.Id: member.TokenKey()}
	if err := invalidateHostedRestore(a.app, &Project{rt: rt, Cache: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	for id, key := range before {
		after, err := a.app.FindRecordById("users", id)
		if err != nil || after.TokenKey() == key {
			t.Fatal("restore kept a session key", err)
		}
	}
	f.request("POST", "/mcp", ownerAccess, "{}", "application/json", 401)
}

func TestCheckLocalAccounts(t *testing.T) {
	rt := multiRT(t, nil) // hooks that accept any number of accounts
	for name, emails := range map[string][]string{
		"empty":              nil,
		"local account":      {fixtureEmail},
		"local account case": {"ME@Fixture.LOCALHOST"},
	} {
		app := migratedApp(t, rt)
		for _, email := range emails {
			addUser(t, app, email, true)
		}
		if err := checkLocalAccounts(app, fixtureEmail); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	for name, emails := range map[string][]string{
		"single hosted":           {"owner@example.test"},
		"multi hosted":            {"owner@example.test", "member@example.test"},
		"local beside another":    {fixtureEmail, "member@example.test"},
		"another beside local":    {"member@example.test", fixtureEmail},
		"multi without its owner": {"member@example.test"},
	} {
		app := migratedApp(t, rt)
		for _, email := range emails {
			addUser(t, app, email, true)
		}
		if err := checkLocalAccounts(app, fixtureEmail); err == nil {
			t.Errorf("%s accepted for local serving", name)
		}
	}
}

// An AccountsMulti hosted database copied without its private hosted marker is
// still refused by local and tunnel-shaped serving.
func TestMultiHostedDatabaseRefusedForLocalServing(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "cache")
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("AppData", cache)
	t.Setenv("LocalAppData", cache)
	cwd, err := os.Getwd() // serving enters the project folder
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	p, err := testRT.Resolve(filepath.Join(root, "project", testRT.cfg.Identity.DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := p.SaveConfig(); err != nil {
		t.Fatal(err)
	}
	rt := multiRT(t, nil)
	app := migratedApp(t, rt)
	addUser(t, app, "owner@example.test", false)
	if err := configureHosted(rt, app, "knowledge.example.com", syntheticHostedConfig(), false); err != nil {
		t.Fatal(err)
	}
	addUser(t, app, "member@example.test", true)
	if _, err := app.DB().NewQuery("VACUUM INTO {:path}").Bind(map[string]any{"path": p.DB}).Execute(); err != nil {
		t.Fatal(err)
	}
	for name, opts := range map[string]ServeOptions{
		"local":  {Headless: true},
		"tunnel": {Headless: true, Service: func(ctx context.Context) error { <-ctx.Done(); return nil }},
	} {
		done := make(chan error, 1)
		go func() { done <- ServeContext(context.Background(), p, opts) }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "requires explicit --hosted serving") {
				t.Fatalf("%s serving: %v", name, err)
			}
		case <-time.After(30 * time.Second):
			_ = Stop(p)
			t.Fatalf("%s serving started", name)
		}
	}
}
