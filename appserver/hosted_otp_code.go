package appserver

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sync"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
)

// OTPCodePath redeems the short sign-in code from a hosted login email. An
// installed home-screen web app cannot use the emailed link (the link opens the
// browser, whose cookies and storage are separate), so the email also carries a
// six-digit code the person types into the app that asked for it.
const OTPCodePath = "/api/collections/users/auth-with-otp-code"

// OTPCodeEmail is what an application's hosted sign-in email shows. Code is the
// six-digit code; Link is the browser sign-in link (it still asks to confirm Log
// in); Domain is the hosted domain.
type OTPCodeEmail struct {
	Code   string
	Link   string
	Domain string
}

const (
	hostedOTPDuration = 15 * time.Minute
	otpCodeDigits     = 6
	otpCodeAttempts   = 5
)

// otpCode is one issued code: only its hash is kept, bound to the login request
// (the OTP id that only the requesting client received) and its account.
type otpCode struct {
	hash     [32]byte
	record   string
	expires  time.Time
	attempts int
}

type otpCodes struct {
	// redeem serializes code and link redemption, so a code and its link
	// can never both sign in.
	redeem sync.Mutex
	ttl    time.Duration
	mu     sync.Mutex
	codes  map[string]*otpCode
	now    func() time.Time
}

// One store per app: the mailer hook issues codes and the route redeems them.
// Codes live in memory only; a restart or restore invalidates them, and the
// emailed link keeps working.
var hostedOTPCodeStores sync.Map

func hostedOTPCodesFor(app core.App) *otpCodes {
	store, _ := hostedOTPCodeStores.LoadOrStore(app, &otpCodes{codes: map[string]*otpCode{}, now: time.Now, ttl: hostedOTPDuration})
	return store.(*otpCodes)
}

func otpCodeHash(otpID, code string) [32]byte {
	return sha256.Sum256([]byte(otpID + "\x00" + code))
}

func (s *otpCodes) issue(otpID, record string) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	code := fmt.Sprintf("%0*d", otpCodeDigits, n.Int64())
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.codes {
		if !now.Before(c.expires) {
			delete(s.codes, id)
		}
	}
	s.codes[otpID] = &otpCode{hash: otpCodeHash(otpID, code), record: record, expires: now.Add(s.ttl)}
	return code, nil
}

func (s *otpCodes) drop(otpID string) {
	s.mu.Lock()
	delete(s.codes, otpID)
	s.mu.Unlock()
}

type otpCodeResult int

const (
	otpCodeOK otpCodeResult = iota
	otpCodeUnknown
	otpCodeWrong
	otpCodeLocked
)

// check compares in constant time. A wrong code counts an attempt; the fifth
// wrong code invalidates it. A right code is consumed.
func (s *otpCodes) check(otpID, code string) (otpCodeResult, string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.codes[otpID]
	if c == nil {
		return otpCodeUnknown, "", 0
	}
	if !s.now().Before(c.expires) {
		delete(s.codes, otpID)
		return otpCodeUnknown, "", 0
	}
	want := otpCodeHash(otpID, code)
	if subtle.ConstantTimeCompare(want[:], c.hash[:]) != 1 {
		c.attempts++
		left := otpCodeAttempts - c.attempts
		if left <= 0 {
			delete(s.codes, otpID)
			return otpCodeLocked, "", 0
		}
		return otpCodeWrong, "", left
	}
	delete(s.codes, otpID)
	return otpCodeOK, c.record, 0
}

func validOTPCodeInput(otpID, code string) bool {
	if len(otpID) == 0 || len(otpID) > 255 || len(code) != otpCodeDigits {
		return false
	}
	for _, r := range otpID {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// hostedOTPLink is the browser sign-in link the email has always carried.
func hostedOTPLink(domain, loginPath, otpID, password string) string {
	q := url.Values{}
	q.Set("otpId", otpID)
	q.Set("otp", password)
	return "https://" + domain + loginPath + "?" + q.Encode()
}

// bindHostedOTPCode issues the same short code for managed delivery and for
// apps that render a code in their own email.
func bindHostedOTPCode(rt *Runtime, app core.App, domain string, cfg *HostedConfig) {
	render := rt.cfg.Text.OTPCodeEmail
	send := cfg.SendSignInCode
	if render == nil && send == nil {
		return
	}
	owner := cfg.OwnerEmail
	codes := hostedOTPCodesFor(app)
	app.OnMailerRecordOTPSend("users").BindFunc(func(e *core.MailerRecordEvent) error {
		otpID, _ := e.Meta["otpId"].(string)
		password, _ := e.Meta["password"].(string)
		if send != nil && (otpID == "" || password == "" || !rt.IsOwner(app, e.Record) || e.Record.Email() != owner) {
			return errors.New("invalid managed sign-in request")
		}
		if otpID == "" || password == "" || e.Record == nil {
			return e.Next()
		}
		code, err := codes.issue(otpID, e.Record.Id)
		if err != nil {
			return err
		}
		if send != nil {
			// PocketBase handles a send error (including an unknown outcome)
			// by deleting the pending OTP. Keep transport errors out of logs.
			if err := send(code); err != nil {
				return errors.New("managed sign-in submission failed")
			}
			return nil
		}
		subject, html, plain := render(OTPCodeEmail{Code: code, Link: hostedOTPLink(domain, rt.cfg.Text.OTPLoginPath, otpID, password), Domain: domain})
		e.Message.Subject, e.Message.HTML, e.Message.Text = subject, html, plain
		return e.Next()
	})
	// A redeemed link spends its code too.
	app.OnRecordAuthWithOTPRequest("users").BindFunc(func(e *core.RecordAuthWithOTPRequestEvent) error {
		if err := e.Next(); err != nil {
			return err
		}
		codes.drop(e.OTP.Id)
		return nil
	})
}

// Consume the pending OTP and verify the current record in one transaction.
// Pruning can see either a pending OTP or a verified account throughout.
func consumeHostedOTP(app core.App, otpID, userID string, verify bool) (*core.Record, error) {
	var user *core.Record
	err := app.RunInTransaction(func(tx core.App) error {
		otp, err := tx.FindOTPById(otpID)
		if err != nil {
			return err
		}
		if otp.RecordRef() != userID || otp.HasExpired(hostedOTPDuration) {
			return sql.ErrNoRows
		}
		user, err = tx.FindRecordById(otp.CollectionRef(), userID)
		if err != nil {
			return err
		}
		if user.Collection().Name != "users" {
			return sql.ErrNoRows
		}
		if err := tx.Delete(otp); err != nil {
			return err
		}
		if verify && !user.Verified() {
			user.SetVerified(true)
			return tx.Save(user)
		}
		return nil
	})
	return user, err
}

func registerHostedOTPCodeRoute(e *core.ServeEvent, rt *Runtime, codeOnly bool) {
	if rt.cfg.Text.OTPCodeEmail == nil && !codeOnly {
		return
	}
	codes := hostedOTPCodesFor(e.App)
	e.Router.POST(OTPCodePath, func(re *core.RequestEvent) error {
		var form struct {
			OTPID string `json:"otpId"`
			Code  string `json:"code"`
		}
		if err := re.BindBody(&form); err != nil || !validOTPCodeInput(form.OTPID, form.Code) {
			return re.BadRequestError("Enter the 6-digit code from the email.", nil)
		}
		codes.redeem.Lock()
		defer codes.redeem.Unlock()
		result, recordID, left := codes.check(form.OTPID, form.Code)
		invalid := "This code has expired or was already used. Send a new one."
		if rt.cfg.Policy.Accounts == AccountsMulti {
			invalid = "Could not sign in with that code. Check the code or request a new email."
		}
		if result == otpCodeLocked {
			// Too many wrong codes invalidate the whole login request, link included.
			if otp, err := re.App.FindOTPById(form.OTPID); err == nil {
				_ = re.App.Delete(otp)
			}
		}
		if result != otpCodeOK {
			if rt.cfg.Policy.Accounts == AccountsSingle {
				switch result {
				case otpCodeLocked:
					invalid = "Too many wrong codes. Send a new one."
				case otpCodeWrong:
					invalid = fmt.Sprintf("That code is wrong. %d tries left.", left)
					if left == 1 {
						invalid = "That code is wrong. 1 try left."
					}
				}
			}
			return re.BadRequestError(invalid, nil)
		}
		record, err := consumeHostedOTP(re.App, form.OTPID, recordID, true)
		if errors.Is(err, sql.ErrNoRows) {
			return re.BadRequestError(invalid, nil)
		}
		if err != nil {
			return re.InternalServerError("Could not complete login. Please try again.", nil)
		}
		re.Response.Header().Set("Cache-Control", "no-store")
		return apis.RecordAuthResponse(re, record, core.MFAMethodOTP, nil)
	})
}
