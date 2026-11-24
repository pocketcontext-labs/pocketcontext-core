package appserver

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
)

func TestHostedManagedSignIn(t *testing.T) {
	// The app has no email renderer, and the transport is its only mail binding.
	a := newTestAppRT(t, testRT)
	mail := make(chan string, 3)
	cfg := &HostedConfig{OwnerEmail: a.user.Email(), SendSignInCode: func(code string) error {
		mail <- code
		return nil
	}}
	server, err := testRT.NewTestServer(a.app, TestServerOptions{
		Hosted: true, HostedConfig: cfg, Domain: "knowledge.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	h := server.Public()
	if mode := hostedRequest(h, "GET", "/api/bundle/auth-mode", ""); !strings.Contains(mode.Body.String(), `"codeOnly":true`) {
		t.Fatalf("reader has no code-only signal: %s", mode.Body)
	}
	a.app.OnMailerRecordOTPSend("users").BindFunc(func(*core.MailerRecordEvent) error {
		t.Error("managed delivery fell through to the guest mailer")
		return nil
	})
	absent := otpResponseShape(t, requestOTP(h, "absent@example.test"))
	w := requestOTP(h, a.user.Email())
	if w.Code != 200 || otpResponseShape(t, w) != absent {
		t.Fatalf("sign-in request differs from unknown email: %d %s", w.Code, w.Body)
	}
	var reply struct{ OtpID string }
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-mail:
		if !validOTPCodeInput(reply.OtpID, code) {
			t.Fatal("managed submission did not contain a six-digit code")
		}
		if status, _ := redeemCode(h, reply.OtpID, code); status != 200 {
			t.Fatalf("delivered code status %d", status)
		}
		if status, _ := redeemCode(h, reply.OtpID, code); status != 400 {
			t.Fatalf("spent code status %d", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("managed code missing")
	}

	// Even a mail event for a different record cannot select the recipient.
	wrong := core.NewRecord(a.user.Collection())
	wrong.Id = "anotherrecordid"
	wrong.SetEmail(a.user.Email())
	e := &core.MailerRecordEvent{Meta: map[string]any{"otpId": "test", "password": "test"}}
	e.Record, e.App = wrong, a.app
	if err := a.app.OnMailerRecordOTPSend().Trigger(e); err == nil || len(mail) != 0 {
		t.Fatal("unexpected delivery for a different record")
	}
}

func TestHostedManagedSendErrorMatchesMailSendError(t *testing.T) {
	var responses []string
	for _, managed := range []bool{false, true} {
		rt := codeEmailRuntime(t)
		a := newTestAppRT(t, rt)
		mail := make(chan string, 1)
		reject := func(code string) error {
			mail <- code
			return errors.New("synthetic private provider detail")
		}
		cfg := syntheticHostedConfig()
		cfg.OwnerEmail = a.user.Email()
		if managed {
			cfg = &HostedConfig{OwnerEmail: a.user.Email(), SendSignInCode: reject}
		}
		server, err := rt.NewTestServer(a.app, TestServerOptions{
			Hosted: true, HostedConfig: cfg, Domain: "knowledge.example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !managed {
			a.app.OnMailerRecordOTPSend().BindFunc(func(e *core.MailerRecordEvent) error {
				return reject(strings.Fields(e.Message.Subject)[0])
			})
		}
		h := server.Public()
		w := requestOTP(h, a.user.Email())
		responses = append(responses, otpResponseShape(t, w))
		var reply struct{ OtpID string }
		if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		var code string
		select {
		case code = <-mail:
		case <-time.After(5 * time.Second):
			t.Fatal("sign-in submission missing")
		}
		// PocketBase owns asynchronous deletion after either transport fails.
		deadline := time.Now().Add(5 * time.Second)
		for {
			_, err := a.app.FindOTPById(reply.OtpID)
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			if err != nil || time.Now().After(deadline) {
				t.Fatal("failed mail left a pending OTP", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		status, body := redeemCode(h, reply.OtpID, code)
		if status != 400 {
			t.Fatalf("failed submission could authenticate: %d", status)
		}
		responses = append(responses, body, otpResponseShape(t, requestOTP(h, a.user.Email())))
	}
	for i := 0; i < 3; i++ {
		if responses[i] != responses[i+3] {
			t.Fatalf("managed and SMTP behavior differed: %q vs %q", responses[i], responses[i+3])
		}
	}
}

func TestManagedHostedConfig(t *testing.T) {
	a := newTestAppRT(t, testRT)
	cfg := &HostedConfig{OwnerEmail: a.user.Email(), SendSignInCode: func(string) error { return nil }}
	if err := configureHosted(multiRT(t, nil), a.app, "knowledge.example.com", cfg, false); err == nil {
		t.Fatal("managed delivery allowed multiple accounts")
	}
	cfg.From = "login@example.test"
	if err := configureHosted(testRT, a.app, "knowledge.example.com", cfg, false); err == nil {
		t.Fatal("managed delivery accepted guest mail configuration")
	}
	cfg.From = ""
	cfg.OwnerEmail = "Test Person <owner@example.test>"
	if err := configureHosted(testRT, a.app, "knowledge.example.com", cfg, false); err == nil {
		t.Fatal("managed delivery accepted an invalid owner")
	}
}
