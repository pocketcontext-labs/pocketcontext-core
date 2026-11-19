package appserver

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"net/http"
	"sync"
	"time"

	"ganigeorgiev.com/pocketbase/dbx"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/hook"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/types"
)

const (
	// hostedSendsPerWindow is how many sign-in emails one address gets per OTP
	// lifetime. PocketBase reuses the newest OTP id once a record has ten
	// unexpired OTPs, which would show that the account exists, so core stays
	// below that.
	hostedSendsPerWindow = 9
	// hostedSendHistoryCapacity bounds the per-address send history. When it
	// is full the address with the oldest last send is forgotten; the database
	// count of pending OTPs still keeps existing accounts below the reuse limit.
	hostedSendHistoryCapacity = 4096
	// hostedUnverifiedLimit is the most accounts that have never signed in
	// (unverified, the owner included) before AllowSignIn stops creating more.
	hostedUnverifiedLimit = 100
	// hostedSignInMinDuration is the shortest time a sign-in request takes,
	// so lookups, the application's hook and account creation are not timed.
	hostedSignInMinDuration = 250 * time.Millisecond
	// hostedPruneInterval and hostedPruneBatch pace the removal of accounts
	// that never signed in.
	hostedPruneInterval = 5 * time.Minute
	hostedPruneBatch    = 100
	// hostedOwnerStoreKey holds the canonical OWNER_EMAIL in the app store.
	hostedOwnerStoreKey = "contextHostedOwner"
)

// canonicalEmail trims an address and lower-cases it. Only printable ASCII is
// accepted: the database compares ASCII case-insensitively and nothing else,
// so a Unicode case fold could join addresses it keeps apart.
func canonicalEmail(address string) (string, bool) {
	b := []byte(address)
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	if len(b) == 0 {
		return "", false
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 0x21 || c > 0x7e {
			return "", false
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out), true
}

// lowerASCII lower-cases ASCII letters only, as SQLite's LOWER does.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// findAccountsByEmail returns up to two users whose address equals canonical
// ignoring ASCII case. The users email index is case-sensitive, so it cannot
// answer this alone.
func findAccountsByEmail(app core.App, canonical string) ([]*core.Record, error) {
	var records []*core.Record
	err := app.RecordQuery("users").AndWhere(dbx.NewExp("LOWER([[email]]) = {:email}", dbx.Params{"email": canonical})).Limit(2).All(&records)
	return records, err
}

// IsOwner reports whether record is the instance's owner: on a hosted
// instance the OWNER_EMAIL account, otherwise the local account. Every other
// user of an AccountsMulti instance is not; what each may do is the
// application's decision.
func (rt *Runtime) IsOwner(app core.App, record *core.Record) bool {
	if app == nil || record == nil || record.Collection() == nil || record.Collection().Name != "users" {
		return false
	}
	owner, _ := app.Store().Get(hostedOwnerStoreKey).(string)
	if owner == "" {
		owner = lowerASCII(rt.cfg.Identity.LocalAccountEmail)
	}
	return lowerASCII(record.Email()) == owner
}

// hostedSendHistory allows one sign-in email per address per minute and
// hostedSendsPerWindow per OTP lifetime. It keeps hashes of canonical
// addresses, in memory only.
type hostedSendHistory struct {
	mu    sync.Mutex
	sends map[[32]byte][]time.Time
	now   func() time.Time
}

func (h *hostedSendHistory) allow(canonical string) bool {
	key := sha256.Sum256([]byte(canonical))
	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	previous, known := h.sends[key]
	recent := make([]time.Time, 0, hostedSendsPerWindow)
	for _, at := range previous {
		if now.Sub(at) < hostedOTPDuration {
			recent = append(recent, at)
		}
	}
	if len(recent) > 0 && now.Sub(recent[len(recent)-1]) < time.Minute || len(recent) >= hostedSendsPerWindow {
		h.sends[key] = recent
		return false
	}
	if !known && len(h.sends) >= hostedSendHistoryCapacity {
		h.evict(now)
	}
	h.sends[key] = append(recent, now)
	return true
}

// evict drops expired histories, then, if still full, the oldest one.
func (h *hostedSendHistory) evict(now time.Time) {
	var oldest [32]byte
	var oldestAt time.Time
	for key, sends := range h.sends {
		last := time.Time{}
		if len(sends) > 0 {
			last = sends[len(sends)-1]
		}
		if now.Sub(last) >= hostedOTPDuration {
			delete(h.sends, key)
			continue
		}
		if oldestAt.IsZero() || last.Before(oldestAt) {
			oldest, oldestAt = key, last
		}
	}
	if len(h.sends) >= hostedSendHistoryCapacity {
		delete(h.sends, oldest)
	}
}

// hostedSignIn is the AccountsMulti sign-in state of one app. Tests adjust
// minDuration and unverifiedLimit.
type hostedSignIn struct {
	history         *hostedSendHistory
	minDuration     time.Duration
	unverifiedLimit int
	create          sync.Mutex
}

var hostedSignInStores sync.Map

func hostedSignInFor(app core.App) *hostedSignIn {
	s, _ := hostedSignInStores.LoadOrStore(app, &hostedSignIn{
		history:         &hostedSendHistory{sends: map[[32]byte][]time.Time{}, now: time.Now},
		minDuration:     hostedSignInMinDuration,
		unverifiedLimit: hostedUnverifiedLimit,
	})
	return s.(*hostedSignIn)
}

// fakeOTPResponse is the answer PocketBase gives an address without an account:
// a random OTP id that redeems nothing.
func fakeOTPResponse(e *core.RecordCreateOTPRequestEvent) error {
	return e.JSON(http.StatusOK, map[string]string{"otpId": core.GenerateDefaultRandomId()})
}

// bindHostedSignIn is the AccountsMulti sign-in request hook. It runs after the
// public sign-in limits and before PocketBase issues the OTP, and replaces
// PocketBase's case-sensitive account lookup. Every outcome that sends nothing
// answers like an unknown address, and every request takes at least
// minDuration, so the response does not show which addresses exist or are
// allowed.
func bindHostedSignIn(rt *Runtime, app core.App, owner string) {
	s := hostedSignInFor(app)
	app.OnRecordRequestOTPRequest("users").Bind(&hook.Handler[*core.RecordCreateOTPRequestEvent]{Id: "hostedEmailCooldown", Func: func(e *core.RecordCreateOTPRequestEvent) error {
		start := time.Now()
		// The response stays buffered until the handler returns, so padding
		// after it is written still delays it.
		defer func() {
			if wait := s.minDuration - time.Since(start); wait > 0 {
				time.Sleep(wait)
			}
		}()
		record := s.resolve(rt, e, owner)
		if record == nil {
			return fakeOTPResponse(e)
		}
		e.Record = record
		return e.Next()
	}})
}

// resolve returns the account to send a sign-in email to, or nil to send
// nothing. Failures are logged without the address or the error text.
func (s *hostedSignIn) resolve(rt *Runtime, e *core.RecordCreateOTPRequestEvent, owner string) *core.Record {
	// PocketBase has already read and validated this body; it can be read again.
	var form struct {
		Email string `json:"email" form:"email"`
	}
	if err := e.BindBody(&form); err != nil {
		return nil
	}
	email, ok := canonicalEmail(form.Email)
	if !ok || email == lowerASCII(rt.cfg.Identity.LocalAccountEmail) || !s.history.allow(email) {
		return nil
	}
	// The hook runs for every address, existing accounts included, so its
	// cost does not tell them apart; its answer matters only for new ones.
	allowed, hookFailed := false, false
	if allow := rt.cfg.Hooks.AllowSignIn; allow != nil {
		var err error
		if allowed, err = allow(e.App, email); err != nil {
			allowed, hookFailed = false, true
			e.App.Logger().Error("Hosted sign-in check failed", "collection", "users")
		}
	}
	found, err := findAccountsByEmail(e.App, email)
	if err != nil {
		e.App.Logger().Error("Hosted sign-in account lookup failed", "collection", "users")
		return nil
	}
	if len(found) > 1 {
		e.App.Logger().Error("Hosted sign-in address matches several accounts", "collection", "users")
		return nil
	}
	if len(found) == 1 {
		if pendingOTPs(e.App, found[0]) >= hostedSendsPerWindow {
			return nil
		}
		return found[0]
	}
	if hookFailed || !allowed {
		return nil
	}
	return s.createAccount(rt, e, email, owner)
}

func pendingOTPs(app core.App, record *core.Record) int {
	otps, err := app.FindAllOTPsByRecord(record)
	if err != nil {
		return hostedSendsPerWindow // fail closed
	}
	n := 0
	for _, otp := range otps {
		if !otp.HasExpired(hostedOTPDuration) {
			n++
		}
	}
	return n
}

func (s *hostedSignIn) createAccount(rt *Runtime, e *core.RecordCreateOTPRequestEvent, email, owner string) *core.Record {
	s.create.Lock()
	defer s.create.Unlock()
	if found, err := findAccountsByEmail(e.App, email); err != nil || len(found) != 0 {
		return nil // created meanwhile; its own request sends
	}
	if _, err := pruneHostedAccounts(e.App, owner, time.Now()); err != nil {
		e.App.Logger().Error("Hosted account pruning failed", "collection", "users")
	}
	unverified, err := e.App.CountRecords("users", dbx.HashExp{"verified": false})
	if err != nil || int(unverified) >= s.unverifiedLimit {
		e.App.Logger().Warn("Hosted sign-in account not created: unverified account limit", "collection", "users")
		return nil
	}
	record := newHostedAccount(e.Collection, email, rt.cfg.Text.AccountName)
	if err := e.App.Save(record); err != nil {
		e.App.Logger().Error("Hosted sign-in account not created", "collection", "users")
		return nil
	}
	e.App.Logger().Info("Hosted sign-in account created", "collection", "users", "record", record.Id)
	return record
}

// pruneHostedAccounts deletes up to hostedPruneBatch accounts that never
// signed in: unverified (every successful sign-in verifies, failing closed),
// created more than one OTP lifetime ago and with no pending OTP. It never
// deletes the owner or a verified account, and does nothing without an owner.
func pruneHostedAccounts(app core.App, owner string, now time.Time) (int, error) {
	if owner == "" {
		return 0, nil
	}
	cutoff, err := types.ParseDateTime(now.Add(-hostedOTPDuration))
	if err != nil {
		return 0, err
	}
	var records []*core.Record
	err = app.RecordQuery("users").
		AndWhere(dbx.HashExp{"verified": false}).
		AndWhere(dbx.NewExp("[[created]] < {:cutoff}", dbx.Params{"cutoff": cutoff.String()})).
		AndWhere(dbx.NewExp("LOWER([[email]]) != {:owner}", dbx.Params{"owner": owner})).
		Limit(hostedPruneBatch).All(&records)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	deleted := 0
	for _, record := range records {
		if record.Verified() || lowerASCII(record.Email()) == owner || pendingOTPs(app, record) > 0 {
			continue
		}
		if err := app.Delete(record); err != nil {
			app.Logger().Error("Hosted account pruning could not delete an account", "collection", "users", "record", record.Id)
			continue
		}
		deleted++
	}
	return deleted, nil
}

// runHostedAccountPruning prunes at start and every hostedPruneInterval until
// ctx ends.
func runHostedAccountPruning(ctx context.Context, app core.App, owner string) {
	ticker := time.NewTicker(hostedPruneInterval)
	defer ticker.Stop()
	for {
		if n, err := pruneHostedAccounts(app, owner, time.Now()); err != nil {
			app.Logger().Error("Hosted account pruning failed", "collection", "users")
		} else if n > 0 {
			app.Logger().Info("Hosted accounts pruned", "collection", "users", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
