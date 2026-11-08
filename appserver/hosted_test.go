package appserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/plugins/jsvm"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/hook"
)

func syntheticHostedConfig() *HostedConfig {
	return &HostedConfig{OwnerEmail: "owner@example.test", From: "login@example.test", SMTP: core.SMTPConfig{Enabled: true, Host: "smtp.example.test", Port: 465, TLS: true, Username: "resend", Password: "synthetic-smtp-secret"}}
}

func hostedTestApp(t *testing.T) (*testApp, http.Handler) {
	t.Helper()
	a := newTestApp(t)
	a.user.SetEmail("owner@example.test")
	if err := a.app.Save(a.user); err != nil {
		t.Fatal(err)
	}
	if err := configureHosted(testRT, a.app, "knowledge.example.com", syntheticHostedConfig(), false); err != nil {
		t.Fatal(err)
	}
	router, err := apis.NewRouter(a.app)
	if err != nil {
		t.Fatal(err)
	}
	local := &localRoutes{p: &Project{rt: testRT, Config: ProjectConfig{Port: 8096}}, hosted: true, publicURL: "https://knowledge.example.com"}
	local.register(&core.ServeEvent{App: a.app, Router: router})
	if err = a.app.OnServe().Trigger(&core.ServeEvent{App: a.app, Router: router}); err != nil {
		t.Fatal(err)
	}
	handler, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	return a, publicHandlerMode(testRT, a.app, "knowledge.example.com", handler, true)
}
func hostedRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://knowledge.example.com"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "10.0.0.2:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func testOTP(t *testing.T, a *testApp) (string, string) {
	t.Helper()
	otp := core.NewOTP(a.app)
	otp.SetCollectionRef(a.user.Collection().Id)
	otp.SetRecordRef(a.user.Id)
	code := strings.Repeat("7", 32)
	otp.SetPassword(code)
	if err := a.app.Save(otp); err != nil {
		t.Fatal(err)
	}
	return otp.Id, code
}

func TestHostedBoundaryAndAuthentication(t *testing.T) {
	a, h := hostedTestApp(t)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/api/bundle/auth-mode", "", 200}, {"GET", "/up", "", 200},
		{"POST", "/api/collections/users/auth-with-password", `{"identity":"owner@example.test","password":"synthetic-password"}`, 404},
		{"POST", "/api/bundle/redeem", `{"code":"x"}`, 404}, {"GET", "/bundle/login", "", 404},
		{"POST", "/api/bundle/account", `{}`, 404}, {"GET", "/_/", "", 404},
		{"POST", "/api/files/token", "{}", 404},
	} {
		w := hostedRequest(h, tc.method, tc.path, tc.body)
		if w.Code != tc.status {
			t.Errorf("%s: %d %s", tc.path, w.Code, w.Body)
		}
	}
	w := hostedRequest(h, "GET", "/api/bundle/auth-mode", "")
	if strings.TrimSpace(w.Body.String()) != `{"mode":"email"}` {
		t.Fatal(w.Body.String())
	}
	id, code := testOTP(t, a)
	body := fmt.Sprintf(`{"otpId":%q,"password":%q}`, id, code)
	w = hostedRequest(h, "POST", "/api/collections/users/auth-with-otp", body)
	if w.Code != 200 {
		t.Fatalf("redeem: %d %s", w.Code, w.Body)
	}
	var auth map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &auth); err != nil || auth["token"] == nil {
		t.Fatal("missing token", err)
	}
	w = hostedRequest(h, "POST", "/api/collections/users/auth-with-otp", body)
	if w.Code != 400 {
		t.Fatalf("replay: %d %s", w.Code, w.Body)
	}
	r := httptest.NewRequest("GET", "http://evil.example/api/bundle/auth-mode", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("wrong host accepted")
	}
	r = httptest.NewRequest("GET", "http://knowledge.example.com/api/bundle/auth-mode", nil)
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("wrong origin accepted")
	}
}

func TestHostedOTPConcurrentSingleUseAndDeleteFailure(t *testing.T) {
	a, h := hostedTestApp(t)
	id, code := testOTP(t, a)
	body := fmt.Sprintf(`{"otpId":%q,"password":%q}`, id, code)
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- hostedRequest(h, "POST", "/api/collections/users/auth-with-otp", body).Code
		}()
	}
	wg.Wait()
	close(codes)
	success := 0
	for status := range codes {
		if status == 200 {
			success++
		} else if status != 400 {
			t.Fatalf("unexpected status %d", status)
		}
	}
	if success != 1 {
		t.Fatalf("successful redemptions %d", success)
	}
	a, h = hostedTestApp(t)
	id, code = testOTP(t, a)
	body = fmt.Sprintf(`{"otpId":%q,"password":%q}`, id, code)
	a.app.OnModelDelete().Bind(&hook.Handler[*core.ModelEvent]{Id: "syntheticFailedDelete", Priority: -100, Func: func(e *core.ModelEvent) error {
		if e.Model.TableName() == "_otps" {
			return errors.New("synthetic disk failure")
		}
		return e.Next()
	}})
	w := hostedRequest(h, "POST", "/api/collections/users/auth-with-otp", body)
	if w.Code != 500 || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("delete failure must fail closed: %d %s", w.Code, w.Body)
	}
}

func TestHostedRequestUnknownEmailAndSMTPPrivate(t *testing.T) {
	a, h := hostedTestApp(t)
	w := hostedRequest(h, "POST", "/api/collections/users/request-otp", `{"email":"other@example.test"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "otpId") {
		t.Fatalf("unknown email: %d %s", w.Code, w.Body)
	}
	records, err := a.app.FindAllOTPsByRecord(a.user)
	if err != nil || len(records) != 0 {
		t.Fatal("unknown email created OTP", err)
	}
	// Runtime SMTP credentials must not be persisted into the project database.
	if err = a.app.ReloadSettings(); err != nil {
		t.Fatal(err)
	}
	settings := a.app.Settings()
	if settings.SMTP.Password != "" || settings.SMTP.Host == "smtp.example.test" {
		t.Fatal("SMTP runtime settings persisted")
	}
}

func TestHostedOwnerAndInitializationGuards(t *testing.T) {
	a := newTestApp(t)
	if err := configureHosted(testRT, a.app, "knowledge.example.com", syntheticHostedConfig(), false); err == nil {
		t.Fatal("owner mismatch accepted")
	}
	if err := configureHosted(testRT, a.app, "knowledge.example.com", syntheticHostedConfig(), true); err == nil {
		t.Fatal("existing account overwritten")
	}
	p := &Project{rt: testRT, DB: filepath.Join(t.TempDir(), "fixture.db")}
	opts := ServeOptions{Hosted: true, Headless: true, HTTPSDomain: "knowledge.example.com", MCP: true, MCPHandler: func(h http.Handler) http.Handler { return h }, HostedConfig: syntheticHostedConfig()}
	if err := ServeContext(context.Background(), p, opts); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing db: %v", err)
	}
	if err := os.WriteFile(p.DB, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	opts.HostedInit = true
	if err := ServeContext(context.Background(), p, opts); err == nil || !strings.Contains(err.Error(), "existing") {
		t.Fatalf("existing db: %v", err)
	}
	data, _ := os.ReadFile(p.DB)
	if string(data) != "preserve" {
		t.Fatal("existing db modified")
	}
}

func TestHostedConfigurationValidation(t *testing.T) {
	values := map[string]string{"OWNER_EMAIL": "owner@example.test", "SMTP_FROM": "login@example.test", "SMTP_HOST": "smtp.example.test", "SMTP_PORT": "465", "SMTP_USERNAME": "resend", "SMTP_PASSWORD": "synthetic", "SMTP_TLS": "tls"}
	for k, v := range values {
		t.Setenv("FIXTURE_"+k, v)
	}
	c, err := testRT.HostedConfigFromEnv()
	if err != nil || !c.SMTP.TLS {
		t.Fatal(c, err)
	}
	for _, tc := range []struct{ name, value string }{{"OWNER_EMAIL", "Name <owner@example.test>"}, {"SMTP_PORT", "0"}, {"SMTP_PASSWORD", ""}, {"SMTP_TLS", "insecure"}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FIXTURE_"+tc.name, tc.value)
			if _, err := testRT.HostedConfigFromEnv(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestHostedRestoreInvalidatesCredentialsOnly(t *testing.T) {
	a, _ := hostedTestApp(t)
	id, _ := testOTP(t, a)
	before, err := a.app.FindRecordById("users", a.user.Id)
	if err != nil {
		t.Fatal(err)
	}
	agentsBefore, err := a.app.FindAllRecords("greetings")
	if err != nil {
		t.Fatal(err)
	}
	p := &Project{rt: testRT, Cache: t.TempDir()}
	state := filepath.Join(p.Cache, "mcp-oauth-synthetic.json")
	if err = os.WriteFile(state, []byte(`{"grants":{"old":"synthetic"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = invalidateHostedRestore(a.app, p); err != nil {
		t.Fatal(err)
	}
	after, err := a.app.FindRecordById("users", a.user.Id)
	if err != nil {
		t.Fatal(err)
	}
	if before.TokenKey() == after.TokenKey() || before.Id != after.Id || before.Email() != after.Email() {
		t.Fatal("restore did not rotate credentials preserving identity")
	}
	if _, err = a.app.FindOTPById(id); err == nil {
		t.Fatal("restore retained unused OTP")
	}
	if _, err = os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("restore retained OAuth grants", err)
	}
	agentsAfter, err := a.app.FindAllRecords("greetings")
	if err != nil || len(agentsAfter) != len(agentsBefore) {
		t.Fatal("restore changed knowledge", err)
	}
	// Regular startup configuration must not invalidate browser credentials.
	if err = configureHosted(testRT, a.app, "knowledge.example.com", syntheticHostedConfig(), false); err != nil {
		t.Fatal(err)
	}
	restarted, err := a.app.FindRecordById("users", a.user.Id)
	if err != nil || after.TokenKey() != restarted.TokenKey() {
		t.Fatal("normal startup changed session keys", err)
	}
}

func TestHostedResendCooldownDoesNotRevealEmail(t *testing.T) {
	a, h := hostedTestApp(t)
	sent := make(chan struct{}, 4)
	a.app.OnMailerRecordOTPSend("users").BindFunc(func(e *core.MailerRecordEvent) error { sent <- struct{}{}; return nil })
	for _, email := range []string{"owner@example.test", "owner@example.test", "absent@example.test"} {
		w := hostedRequest(h, "POST", "/api/collections/users/request-otp", fmt.Sprintf(`{"email":%q}`, email))
		if w.Code != 200 || !strings.Contains(w.Body.String(), "otpId") {
			t.Fatalf("email response differs: %d %s", w.Code, w.Body)
		}
	}
	otps, err := a.app.FindAllOTPsByRecord(a.user)
	if err != nil || len(otps) != 1 {
		t.Fatal("resend created another OTP", len(otps), err)
	}
}

func TestHostedInitialAccountAndLocalModeGuard(t *testing.T) {
	app := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	jsvm.MustRegister(app, hooksConfig(testRT, testAssetsDir(), ""))
	var err error
	if err = app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	defer app.ResetBootstrapState()
	if err = app.RunAllMigrations(); err != nil {
		t.Fatal(err)
	}
	if err = configureHosted(testRT, app, "knowledge.example.com", syntheticHostedConfig(), true); err != nil {
		t.Fatal(err)
	}
	users, err := app.FindAllRecords("users")
	if err != nil || len(users) != 1 || users[0].Email() != "owner@example.test" || users[0].Verified() {
		t.Fatal("initial owner mismatch", err)
	}
	collection, err := app.FindCollectionByNameOrId("users")
	if err != nil || collection.PasswordAuth.Enabled || !collection.OTP.Enabled || collection.OTP.Length != 32 || collection.OTP.Duration != 900 {
		t.Fatal("hosted auth configuration mismatch", err)
	}
	if err = configureHosted(testRT, app, "knowledge.example.com", syntheticHostedConfig(), true); err == nil {
		t.Fatal("initialization repeated")
	}
	if _, err := app.FindCollectionByNameOrId("greetings"); err != nil {
		t.Fatal("missing fixture collection", err)
	}
	p := &Project{rt: testRT, Cache: t.TempDir()}
	if err = CheckLocalProject(p); err != nil {
		t.Fatal("ordinary local project refused", err)
	}
	if err = os.WriteFile(filepath.Join(p.Cache, "hosted.json"), []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = CheckLocalProject(p); err == nil {
		t.Fatal("hosted project accepted local mode")
	}
	if err = ServeContext(context.Background(), p, ServeOptions{}); err == nil || !strings.Contains(err.Error(), "hosted") {
		t.Fatal("hosted marker ignored", err)
	}
}
