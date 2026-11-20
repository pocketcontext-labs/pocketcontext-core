package appserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
)

func codeEmailRuntime(t *testing.T) *Runtime {
	t.Helper()
	cfg := fixtureConfig(fixturePublicRoute)
	cfg.Text.OTPCodeEmail = func(m OTPCodeEmail) (string, string, string) {
		return m.Code + " is your Fixture sign-in code", "<p>" + m.Code + "</p><a href=\"" + m.Link + "\">link</a>", m.Code + "\n" + m.Link
	}
	rt, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

type sentLogin struct{ otpID, code, password, subject, html, text string }

// codeLogin requests a login email and returns what the email carried.
func codeLogin(t *testing.T, a *testApp, h http.Handler) sentLogin {
	t.Helper()
	sent := make(chan sentLogin, 1)
	a.app.OnMailerRecordOTPSend("users").BindFunc(func(e *core.MailerRecordEvent) error {
		code := regexp.MustCompile(`^\d{6}`).FindString(e.Message.Subject)
		sent <- sentLogin{otpID: e.Meta["otpId"].(string), password: e.Meta["password"].(string), code: code, subject: e.Message.Subject, html: e.Message.HTML, text: e.Message.Text}
		return nil // do not send
	})
	w := hostedRequest(h, "POST", "/api/collections/users/request-otp", `{"email":"owner@example.test"}`)
	if w.Code != 200 {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	var reply struct{ OtpID string }
	_ = json.Unmarshal(w.Body.Bytes(), &reply)
	select {
	case got := <-sent:
		if got.otpID != reply.OtpID || got.code == "" {
			t.Fatalf("email does not match the request: %+v %s", got, w.Body)
		}
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("no email")
	}
	return sentLogin{}
}

func redeemCode(h http.Handler, otpID, code string) (int, string) {
	w := hostedRequest(h, "POST", OTPCodePath, fmt.Sprintf(`{"otpId":%q,"code":%q}`, otpID, code))
	return w.Code, w.Body.String()
}

func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

func TestHostedOTPCodeEmailAndSingleUse(t *testing.T) {
	a, h := hostedTestAppRT(t, codeEmailRuntime(t))
	got := codeLogin(t, a, h)
	if !strings.HasPrefix(got.subject, got.code+" is your") || !strings.Contains(got.html, got.code) || !strings.HasPrefix(got.text, got.code+"\n") {
		t.Fatalf("email does not carry the code: %+v", got)
	}
	if !strings.Contains(got.text, "https://knowledge.example.com/#/fixture-login?otp="+got.password+"&otpId="+got.otpID) {
		t.Fatalf("email lost the browser link: %q", got.text)
	}
	if status, body := redeemCode(h, got.otpID, wrongCode(got.code)); status != 400 || !strings.Contains(body, "4 tries left") {
		t.Fatalf("wrong code: %d %s", status, body)
	}
	status, body := redeemCode(h, got.otpID, got.code)
	if status != 200 || !strings.Contains(body, `"token"`) {
		t.Fatalf("right code: %d %s", status, body)
	}
	if status, body = redeemCode(h, got.otpID, got.code); status != 400 || !strings.Contains(body, "expired or was already used") {
		t.Fatalf("replayed code: %d %s", status, body)
	}
	// The code spent its login request, so the link is dead too.
	w := hostedRequest(h, "POST", "/api/collections/users/auth-with-otp", fmt.Sprintf(`{"otpId":%q,"password":%q}`, got.otpID, got.password))
	if w.Code != 400 {
		t.Fatalf("link after code: %d %s", w.Code, w.Body)
	}
}

func TestHostedOTPLinkSpendsCode(t *testing.T) {
	a, h := hostedTestAppRT(t, codeEmailRuntime(t))
	got := codeLogin(t, a, h)
	w := hostedRequest(h, "POST", "/api/collections/users/auth-with-otp", fmt.Sprintf(`{"otpId":%q,"password":%q}`, got.otpID, got.password))
	if w.Code != 200 {
		t.Fatalf("link: %d %s", w.Code, w.Body)
	}
	if status, body := redeemCode(h, got.otpID, got.code); status != 400 || !strings.Contains(body, "expired or was already used") {
		t.Fatalf("code after link: %d %s", status, body)
	}
}

func TestHostedOTPCodeAttemptLimit(t *testing.T) {
	a, h := hostedTestAppRT(t, codeEmailRuntime(t))
	got := codeLogin(t, a, h)
	for i, want := range []string{"4 tries left", "3 tries left", "2 tries left", "1 try left", "Too many wrong codes"} {
		if status, body := redeemCode(h, got.otpID, wrongCode(got.code)); status != 400 || !strings.Contains(body, want) {
			t.Fatalf("attempt %d: %d %s", i+1, status, body)
		}
	}
	if status, body := redeemCode(h, got.otpID, got.code); status != 400 || !strings.Contains(body, "expired or was already used") {
		t.Fatalf("right code after lockout: %d %s", status, body)
	}
	if _, err := a.app.FindOTPById(got.otpID); err == nil {
		t.Fatal("lockout kept the login request (and its link) alive")
	}
}

func TestHostedOTPCodeInputAndUnknownRequest(t *testing.T) {
	a, h := hostedTestAppRT(t, codeEmailRuntime(t))
	_ = a
	for _, body := range []string{`{"otpId":"abc","code":"12345"}`, `{"otpId":"abc","code":"12345a"}`, `{"otpId":"a/b","code":"123456"}`, `{}`} {
		w := hostedRequest(h, "POST", OTPCodePath, body)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "6-digit code") {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	if status, body := redeemCode(h, "unknownotpid12", "123456"); status != 400 || !strings.Contains(body, "expired or was already used") {
		t.Fatalf("unknown request: %d %s", status, body)
	}
}

func TestHostedMultiFailedCodesShareOneResponse(t *testing.T) {
	rt := multiRT(t, nil)
	rt.cfg.Text.OTPCodeEmail = codeEmailRuntime(t).cfg.Text.OTPCodeEmail
	a, h := multiHostedTestApp(t, rt)
	got := codeLogin(t, a, h)
	absent := requestOTP(h, "absent@example.test")
	var synthetic struct{ OTPID string }
	if err := json.Unmarshal(absent.Body.Bytes(), &synthetic); err != nil || synthetic.OTPID == "" {
		t.Fatal("expected a synthetic login request", err)
	}
	wantStatus, wantBody := redeemCode(h, synthetic.OTPID, "000000")
	if wantStatus != http.StatusBadRequest {
		t.Fatal("unexpected status for an invalid code", wantStatus)
	}
	for i := 0; i <= otpCodeAttempts; i++ {
		status, body := redeemCode(h, got.otpID, wrongCode(got.code))
		if status != wantStatus || body != wantBody {
			t.Fatalf("failed validation differed on attempt %d: %d %s", i+1, status, body)
		}
	}
	if _, err := a.app.FindOTPById(got.otpID); err == nil {
		t.Fatal("attempt limit left the login request usable")
	}
}

func TestHostedOTPCodeRateLimited(t *testing.T) {
	_, h := hostedTestAppRT(t, codeEmailRuntime(t))
	limited := false
	for i := 0; i < 15; i++ {
		if status, _ := redeemCode(h, "unknownotpid12", "123456"); status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("code redemption is not rate limited")
	}
}

func TestHostedOTPCodeOffWithoutApplicationEmail(t *testing.T) {
	a, h := hostedTestApp(t)
	sent := make(chan string, 1)
	a.app.OnMailerRecordOTPSend("users").BindFunc(func(e *core.MailerRecordEvent) error { sent <- e.Message.Subject; return nil })
	hostedRequest(h, "POST", "/api/collections/users/request-otp", `{"email":"owner@example.test"}`)
	if subject := <-sent; subject != testRT.cfg.Text.OTPSubject {
		t.Fatalf("link-only email changed: %q", subject)
	}
	if status, _ := redeemCode(h, "unknownotpid12", "123456"); status != 404 {
		t.Fatalf("code route without an application email: %d", status)
	}
}

func TestOTPCodeStoreExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := &otpCodes{codes: map[string]*otpCode{}, now: func() time.Time { return now }, ttl: hostedOTPDuration}
	code, err := s.issue("otp1", "user1")
	if err != nil || len(code) != 6 {
		t.Fatal(code, err)
	}
	now = now.Add(hostedOTPDuration)
	if result, _, _ := s.check("otp1", code); result != otpCodeUnknown {
		t.Fatalf("expired code accepted: %v", result)
	}
	code, _ = s.issue("otp2", "user1")
	if result, record, _ := s.check("otp2", code); result != otpCodeOK || record != "user1" {
		t.Fatalf("fresh code: %v %q", result, record)
	}
}

func TestHostedSessionDuration(t *testing.T) {
	cfg := fixtureConfig(fixturePublicRoute)
	cfg.Policy.HostedSession = 30 * 24 * time.Hour
	rt, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := hostedTestAppRT(t, rt)
	users, err := a.app.FindCollectionByNameOrId("users")
	if err != nil || users.AuthToken.Duration != 30*24*3600 {
		t.Fatalf("hosted session: %v %v", users.AuthToken.Duration, err)
	}
}
