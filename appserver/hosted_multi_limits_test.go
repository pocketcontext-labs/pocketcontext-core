package appserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/dbx"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/types"
)

// requestOTPFrom sends a sign-in request from its own client address, so the
// per-client sign-in budget of AccountsMulti does not shape the test.
func requestOTPFrom(h http.Handler, email string, client int) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://knowledge.example.com/api/collections/users/request-otp", strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", client%250+1)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// fakeClock drives the send history.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

func useFakeClock(app core.App) *fakeClock {
	clock := &fakeClock{now: time.Now()}
	hostedSignInFor(app).history.now = clock.Now
	return clock
}

func noMail(t *testing.T, sent chan sentOTP) {
	t.Helper()
	select {
	case m := <-sent:
		t.Fatal("email sent to", m.email)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestHostedMultiCaseVariants(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	rt := multiRT(t, func(_ core.App, email string) (bool, error) {
		mu.Lock()
		asked = append(asked, email)
		mu.Unlock()
		return email == "new@example.test", nil
	})
	a, h := multiHostedTestApp(t, rt)
	clock := useFakeClock(a.app)
	sent := captureOTPMail(a.app)
	member := addUser(t, a.app, "member@example.test", true)
	for i, tc := range []struct{ request, account string }{
		{"Member@Example.TEST", "member@example.test"},
		{"OWNER@example.test", "owner@example.test"},
		{"New@Example.Test", "new@example.test"},
	} {
		if w := requestOTPFrom(h, tc.request, i); w.Code != 200 {
			t.Fatalf("%q: %d %s", tc.request, w.Code, w.Body)
		}
		if got := waitOTPMail(t, sent).email; got != tc.account {
			t.Fatalf("%q sent to %q", tc.request, got)
		}
	}
	// Variants share one cooldown, and later variants reach the same account.
	if w := requestOTPFrom(h, "NEW@example.test", 10); w.Code != 200 {
		t.Fatal(w.Code)
	}
	noMail(t, sent)
	clock.Add(2 * time.Minute)
	if w := requestOTPFrom(h, "nEw@EXAMPLE.test", 11); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if got := waitOTPMail(t, sent).email; got != "new@example.test" {
		t.Fatal("variant sent to", got)
	}
	users, err := a.app.FindAllRecords("users")
	if err != nil || len(users) != 3 {
		t.Fatal("case variants created accounts", len(users), err)
	}
	if otps, _ := a.app.FindAllOTPsByRecord(member); len(otps) != 1 {
		t.Fatal("member OTPs", len(otps))
	}
	mu.Lock()
	defer mu.Unlock()
	for _, email := range asked {
		if email != strings.ToLower(strings.TrimSpace(email)) {
			t.Fatal("hook received a non-canonical address", email)
		}
	}
}

func TestHostedMultiNonASCIIAddressesSendNothing(t *testing.T) {
	calls := 0
	rt := multiRT(t, func(core.App, string) (bool, error) { calls++; return true, nil })
	a, h := multiHostedTestApp(t, rt)
	sent := captureOTPMail(a.app)
	addUser(t, a.app, "kate@example.test", true)
	addUser(t, a.app, "sam@example.test", true)
	// U+212A folds to k and U+017F to s under Unicode case folding; the
	// database keeps them apart, so core never treats them as those accounts.
	for i, email := range []string{"Kate@example.test", "ſam@example.test", "josé@example.test", "néw@example.test"} {
		w := requestOTPFrom(h, email, i)
		switch w.Code {
		case 200:
			otpResponseShape(t, w)
		case 400: // PocketBase's own address validation, the same for every caller
		default:
			t.Fatalf("%q: %d %s", email, w.Code, w.Body)
		}
	}
	noMail(t, sent)
	if n, _ := a.app.CountRecords("users"); n != 3 {
		t.Fatal("non-ASCII address created an account", n)
	}
	if n, _ := a.app.CountRecords(core.CollectionNameOTPs); n != 0 {
		t.Fatal("non-ASCII address issued an OTP", n)
	}
	if calls != 0 {
		t.Fatal("hook asked about a non-ASCII address", calls)
	}
}

func TestHostedMultiSendCapKeepsOTPIDsUnique(t *testing.T) {
	a, h := multiHostedTestApp(t, multiRT(t, nil))
	clock := useFakeClock(a.app)
	sent := captureOTPMail(a.app)
	seen := map[string]bool{}
	for i := 0; i < 12; i++ {
		clock.Add(61 * time.Second)
		w := requestOTPFrom(h, "owner@example.test", i)
		var out map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &out); w.Code != 200 || err != nil {
			t.Fatalf("request %d: %d %s", i, w.Code, w.Body)
		}
		if seen[out["otpId"]] {
			t.Fatalf("request %d repeated an otpId", i)
		}
		seen[out["otpId"]] = true
		if i < hostedSendsPerWindow {
			waitOTPMail(t, sent)
		}
	}
	noMail(t, sent)
	if otps, _ := a.app.FindAllOTPsByRecord(a.user); len(otps) != hostedSendsPerWindow {
		t.Fatal("OTPs issued", len(otps))
	}
	// A forgotten history (a restart, an eviction) still sends nothing while
	// the database holds the cap of pending OTPs.
	hostedSignInFor(a.app).history.sends = map[[32]byte][]time.Time{}
	w := requestOTPFrom(h, "owner@example.test", 99)
	otpResponseShape(t, w)
	noMail(t, sent)
	if otps, _ := a.app.FindAllOTPsByRecord(a.user); len(otps) != hostedSendsPerWindow {
		t.Fatal("OTPs beyond the cap", len(otps))
	}
}

func TestHostedMultiSignInTiming(t *testing.T) {
	rt := multiRT(t, func(_ core.App, email string) (bool, error) {
		switch email {
		case "new@example.test":
			return true, nil
		case "broken@example.test":
			return false, errors.New("synthetic failure")
		}
		return false, nil
	})
	a, h := multiHostedTestApp(t, rt)
	sent := captureOTPMail(a.app)
	const floor = 150 * time.Millisecond
	hostedSignInFor(a.app).minDuration = floor
	for i, email := range []string{"owner@example.test", "new@example.test", "denied@example.test", "broken@example.test", "owner@example.test", "josé@example.test"} {
		start := time.Now()
		w := requestOTPFrom(h, email, i)
		if elapsed := time.Since(start); w.Code == 200 && elapsed < floor {
			t.Fatalf("%q answered in %v, under %v", email, elapsed, floor)
		}
	}
	waitOTPMail(t, sent)
	waitOTPMail(t, sent)
}

// ageAccount moves an account's creation back by d.
func ageAccount(t *testing.T, app core.App, record *core.Record, d time.Duration) {
	t.Helper()
	created, err := types.ParseDateTime(time.Now().Add(-d))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB().Update("users", dbx.Params{"created": created.String()}, dbx.HashExp{"id": record.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestHostedMultiUnverifiedCapAndPruning(t *testing.T) {
	a, h := multiHostedTestApp(t, multiRT(t, func(core.App, string) (bool, error) { return true, nil }))
	clock := useFakeClock(a.app)
	sent := captureOTPMail(a.app)
	app := a.app
	// The owner, unverified and old, is never pruned.
	a.user.SetVerified(false)
	if err := app.Save(a.user); err != nil {
		t.Fatal(err)
	}
	ageAccount(t, app, a.user, time.Hour)
	verifiedOld := addUser(t, app, "verified@example.test", true)
	ageAccount(t, app, verifiedOld, time.Hour)
	pendingOld := addUser(t, app, "pending@example.test", false)
	ageAccount(t, app, pendingOld, time.Hour)
	otp := core.NewOTP(app)
	otp.SetCollectionRef(pendingOld.Collection().Id)
	otp.SetRecordRef(pendingOld.Id)
	otp.SetPassword(strings.Repeat("5", 32))
	if err := app.Save(otp); err != nil {
		t.Fatal(err)
	}
	fresh := addUser(t, app, "fresh@example.test", false)
	unverified, err := app.CountRecords("users", dbx.HashExp{"verified": false})
	if err != nil {
		t.Fatal(err)
	}
	hostedSignInFor(app).unverifiedLimit = int(unverified) + 1
	requestOTPFrom(h, "first@example.test", 1)
	waitOTPMail(t, sent)
	first, err := app.FindAuthRecordByEmail("users", "first@example.test")
	if err != nil {
		t.Fatal("allowed account not created", err)
	}
	// The cap is reached: the usual answer, no account, no email.
	otpResponseShape(t, requestOTPFrom(h, "second@example.test", 2))
	noMail(t, sent)
	if _, err := app.FindAuthRecordByEmail("users", "second@example.test"); err == nil {
		t.Fatal("account created beyond the unverified cap")
	}
	// Once first is older than an OTP lifetime with no pending OTP, it is
	// pruned and second can be created.
	ageAccount(t, app, first, 20*time.Minute)
	if _, err := app.DB().Delete(core.CollectionNameOTPs, dbx.HashExp{"recordRef": first.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	clock.Add(2 * time.Minute)
	requestOTPFrom(h, "second@example.test", 3)
	if waitOTPMail(t, sent).email != "second@example.test" {
		t.Fatal("second account not created after pruning")
	}
	if _, err := app.FindRecordById("users", first.Id); err == nil {
		t.Fatal("stale unverified account not pruned")
	}
	for _, kept := range []*core.Record{a.user, verifiedOld, pendingOld, fresh} {
		if _, err := app.FindRecordById("users", kept.Id); err != nil {
			t.Fatalf("pruning deleted %s", kept.Email())
		}
	}
	// Pruning without an owner does nothing.
	ageAccount(t, app, fresh, time.Hour)
	if n, err := pruneHostedAccounts(app, "", time.Now()); err != nil || n != 0 {
		t.Fatal("pruned without an owner", n, err)
	}
	if n, err := pruneHostedAccounts(app, "owner@example.test", time.Now()); err != nil || n != 1 {
		t.Fatal("pruned", n, err)
	}
	if _, err := app.FindRecordById("users", a.user.Id); err != nil {
		t.Fatal("owner pruned")
	}
}

func TestHostedMultiSaveConflictSendsNothing(t *testing.T) {
	a, h := multiHostedTestApp(t, multiRT(t, func(core.App, string) (bool, error) { return true, nil }))
	sent := captureOTPMail(a.app)
	allowed := otpResponseShape(t, requestOTPFrom(h, "allowed@example.test", 1))
	waitOTPMail(t, sent)
	// Another writer creates the same address between core's lookup and its
	// insert: the insert fails on the unique email index.
	inner := false
	a.app.OnRecordCreate("users").BindFunc(func(e *core.RecordEvent) error {
		if e.Record.Email() == "conflict@example.test" && !inner {
			inner = true
			if err := e.App.Save(newHostedAccount(e.Record.Collection(), "conflict@example.test", "Other writer")); err != nil {
				return err
			}
		}
		return e.Next()
	})
	if got := otpResponseShape(t, requestOTPFrom(h, "conflict@example.test", 2)); got != allowed {
		t.Fatalf("conflict response differs:\n%s\n%s", got, allowed)
	}
	noMail(t, sent)
	if n, _ := a.app.CountRecords(core.CollectionNameOTPs); n != 1 {
		t.Fatal("conflict issued an OTP", n)
	}
}

func TestHostedMultiPerClientEmailLimits(t *testing.T) {
	a := newTestApp(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oauthJSON(w, 200, map[string]string{"otpId": "synthetic"})
	})
	send := func(h http.Handler, path, client string) (int, string) {
		r := httptest.NewRequest("POST", "http://knowledge.example.com"+path, strings.NewReader(`{}`))
		r.RemoteAddr = "10.0.0.7:40000"
		r.Header.Set("X-Forwarded-For", client)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out struct {
			Data struct {
				RateLimit struct {
					Limit string `json:"limit"`
				} `json:"rate_limit"`
			} `json:"data"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out.Data.RateLimit.Limit
	}
	multi := newPublicHandler(multiRT(t, nil), a.app, "knowledge.example.com", next, publicHandlerOptions{hosted: true, proxy: albProxy}, nil)
	for _, tc := range []struct{ path, limit string }{
		{"/api/collections/users/request-otp", "client_email_request"},
		{"/api/collections/users/auth-with-otp", "client_email_redemption"},
	} {
		for i := 0; i < 10; i++ {
			if code, _ := send(multi, tc.path, "203.0.113.1"); code != 200 {
				t.Fatalf("%s %d: %d", tc.path, i, code)
			}
		}
		if code, limit := send(multi, tc.path, "203.0.113.1"); code != 429 || limit != tc.limit {
			t.Fatalf("%s: client over its budget: %d %q", tc.path, code, limit)
		}
		// Another client behind the same proxy is unaffected.
		if code, _ := send(multi, tc.path, "203.0.113.2"); code != 200 {
			t.Fatalf("%s: second client blocked: %d", tc.path, code)
		}
	}
	// The instance-wide ceiling is far above one client's budget: 100 at
	// once. Eleven requests are spent; 89 more clients all pass.
	for i := 3; i < 3+hostedMultiEmailBurst-11; i++ {
		if code, _ := send(multi, "/api/collections/users/request-otp", fmt.Sprintf("203.0.113.%d", i)); code != 200 {
			t.Fatalf("client %d blocked under the instance ceiling: %d", i, code)
		}
	}
	// It still exists: fresh clients soon meet it (it refills one per 100 ms).
	limited := false
	for i := 0; i < 20 && !limited; i++ {
		code, limit := send(multi, "/api/collections/users/request-otp", fmt.Sprintf("198.51.100.%d", i+1))
		limited = code == 429 && limit == "email_request"
	}
	if !limited {
		t.Fatal("no instance-wide ceiling")
	}
	// AccountsSingle keeps one instance-wide budget of ten.
	single := newPublicHandler(testRT, a.app, "knowledge.example.com", next, publicHandlerOptions{hosted: true, proxy: albProxy}, nil)
	for i := 0; i < 10; i++ {
		if code, _ := send(single, "/api/collections/users/request-otp", "203.0.113.1"); code != 200 {
			t.Fatalf("single %d: %d", i, code)
		}
	}
	if code, limit := send(single, "/api/collections/users/request-otp", "203.0.113.2"); code != 429 || limit != "email_request" {
		t.Fatalf("single-account limit changed: %d %q", code, limit)
	}
}

func TestHostedMultiPerAccountOAuthCaps(t *testing.T) {
	m := newMultiOAuth(t)
	future := time.Now().Add(time.Hour).Unix()
	inject := func(user string, grants, tokens int) []string {
		var ids []string
		for i := 0; i < grants; i++ {
			id := fmt.Sprintf("synthetic-%s-%d", user, i)
			m.o.state.Grants[id] = oauthGrant{ID: id, Client: m.client, User: user, Created: time.Now().Unix(), Expires: future}
			ids = append(ids, id)
		}
		for i := 0; i < tokens; i++ {
			m.o.state.Access[fmt.Sprintf("synthetic-access-%s-%d", user, i)] = oauthAccess{Grant: ids[0], Expires: future}
		}
		return ids
	}
	clear := func(ids []string) {
		for _, id := range ids {
			delete(m.o.state.Grants, id)
		}
		for key, a := range m.o.state.Access {
			if strings.HasPrefix(a.Grant, "synthetic-") {
				delete(m.o.state.Access, key)
			}
		}
	}
	// A member at its grant share cannot connect again; the owner can.
	ids := inject(m.member.Id, oauthUserGrants, 0)
	m.connect(m.memberToken, strings.Repeat("a", 64), 503)
	m.connect(m.ownerToken, strings.Repeat("b", 64), 200)
	clear(ids)
	// A member at its access-token share cannot get another.
	ids = inject(m.member.Id, 1, oauthUserAccess)
	m.connect(m.memberToken, strings.Repeat("c", 64), 503)
	clear(ids)
	// Other accounts filling the instance up to the owner's reserve stop
	// every member, never the owner.
	ids = inject("othermember", oauthMaxGrants-oauthUserGrants-len(m.o.state.Grants), 0)
	m.connect(m.memberToken, strings.Repeat("d", 64), 503)
	m.connect(m.ownerToken, strings.Repeat("e", 64), 200)
	clear(ids)
	m.connect(m.memberToken, strings.Repeat("f", 64), 200)
}

func TestHostedSendHistoryEviction(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	h := &hostedSendHistory{sends: map[[32]byte][]time.Time{}, now: clock.Now}
	for i := 0; i < hostedSendHistoryCapacity; i++ {
		clock.Add(time.Millisecond)
		if !h.allow(fmt.Sprintf("member%d@example.test", i)) {
			t.Fatal("refused while filling", i)
		}
	}
	// Full: a new address, the owner's for example, is still served, and the
	// address with the oldest send is forgotten.
	if !h.allow("owner@example.test") || len(h.sends) != hostedSendHistoryCapacity {
		t.Fatal("full history refused a new address", len(h.sends))
	}
	if h.allow("owner@example.test") {
		t.Fatal("cooldown lost for the newest address")
	}
	if h.allow(fmt.Sprintf("member%d@example.test", hostedSendHistoryCapacity-1)) {
		t.Fatal("cooldown lost for a recent address")
	}
	if !h.allow("member0@example.test") {
		t.Fatal("oldest address not evicted")
	}
	// Expired histories go first.
	clock.Add(hostedOTPDuration + time.Second)
	if !h.allow("later@example.test") || len(h.sends) != 1 {
		t.Fatal("expired histories kept", len(h.sends))
	}
}

func TestRuntimeIsOwner(t *testing.T) {
	rt := multiRT(t, nil)
	a, _ := multiHostedTestApp(t, rt)
	member := addUser(t, a.app, "member@example.test", true)
	if !rt.IsOwner(a.app, a.user) || rt.IsOwner(a.app, member) || rt.IsOwner(a.app, nil) {
		t.Fatal("hosted owner misidentified")
	}
	local := newTestApp(t)
	other := core.NewRecord(local.user.Collection())
	other.SetEmail("member@example.test")
	if !testRT.IsOwner(local.app, local.user) || testRT.IsOwner(local.app, other) {
		t.Fatal("local owner misidentified")
	}
}
