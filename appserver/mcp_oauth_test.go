package appserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

type oauthFixture struct {
	t        *testing.T
	a        *testApp
	o        *mcpOAuth
	p        *Project
	h        http.Handler
	requests int
}

func newOAuthFixture(t *testing.T) *oauthFixture {
	a := newTestApp(t)
	p := &Project{rt: testRT, Cache: t.TempDir(), Config: ProjectConfig{Instance: "synthetic-instance"}}
	adapter := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !publicRequest(r) || r.Header.Get("Authorization") != "" || r.Header.Get(keyHeader) != "" {
			t.Error("MCP lost public boundary or leaked credentials")
		}
		record, err := a.app.FindAuthRecordByToken(MCPAuthToken(r.Context()))
		if err != nil || record.Id != a.user.Id {
			t.Error("invalid internal principal")
		}
		oauthJSON(w, 200, map[string]bool{"ok": true})
	})
	o, err := newMCPOAuth(a.app, p, "knowledge.example.com", adapter)
	if err != nil {
		t.Fatal(err)
	}
	f := &oauthFixture{t: t, a: a, o: o, p: p}
	f.h = publicHandler(testRT, a.app, "knowledge.example.com", http.NotFoundHandler(), o)
	return f
}
func (f *oauthFixture) request(method, path, token, body, ctype string, want int) map[string]any {
	f.t.Helper()
	f.requests++
	r := httptest.NewRequest(method, "https://knowledge.example.com"+path, strings.NewReader(body))
	r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", f.requests%250+1)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != want {
		f.t.Fatalf("%s %s = %d, want %d: %s", method, path, w.Code, want, w.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}
func (f *oauthFixture) registration() string {
	return f.request("POST", "/oauth/register", "", `{"client_name":"Synthetic client","redirect_uris":["https://client.example.com/callback"],"token_endpoint_auth_method":"none"}`, "application/json", 201)["client_id"].(string)
}
func (f *oauthFixture) authorization(client, verifier string) url.Values {
	h := sha256.Sum256([]byte(verifier))
	return url.Values{"client_id": {client}, "redirect_uri": {"https://client.example.com/callback"}, "response_type": {"code"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(h[:])}, "resource": {f.o.resource()}, "scope": {"knowledge"}, "state": {"synthetic-state"}}
}
func (f *oauthFixture) code(client, verifier string) string {
	q := f.authorization(client, verifier)
	out := f.request("POST", "/oauth/authorize?"+q.Encode(), f.a.token, `{"approve":true}`, "application/json", 200)
	u, err := url.Parse(out["redirect"].(string))
	if err != nil {
		f.t.Fatal(err)
	}
	if u.Query().Get("state") != "synthetic-state" {
		f.t.Fatal("lost state")
	}
	return u.Query().Get("code")
}
func (f *oauthFixture) exchange(client, code, verifier string, want int) map[string]any {
	q := url.Values{"client_id": {client}, "code": {code}, "redirect_uri": {"https://client.example.com/callback"}, "code_verifier": {verifier}, "resource": {f.o.resource()}, "grant_type": {"authorization_code"}}
	return f.request("POST", "/oauth/token", "", q.Encode(), "application/x-www-form-urlencoded", want)
}
func (f *oauthFixture) refresh(client, token string, want int) map[string]any {
	q := url.Values{"client_id": {client}, "refresh_token": {token}, "resource": {f.o.resource()}, "grant_type": {"refresh_token"}}
	return f.request("POST", "/oauth/token", "", q.Encode(), "application/x-www-form-urlencoded", want)
}
func TestMCPOAuthLifecycle(t *testing.T) {
	f := newOAuthFixture(t)
	client := f.registration()
	verifier := strings.Repeat("v", 64)
	code := f.code(client, verifier)
	result := f.exchange(client, code, verifier, 200)
	access := result["access_token"].(string)
	refresh := result["refresh_token"].(string)
	f.request("POST", "/mcp", access, "{}", "application/json", 200)
	f.request("POST", "/mcp", f.a.token, "{}", "application/json", 401)
	f.exchange(client, code, verifier, 400)
	data, err := os.ReadFile(f.o.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{access, refresh, f.a.token, f.a.user.TokenKey()} {
		if strings.Contains(string(data), secret) {
			t.Fatal("usable credential persisted")
		}
	}
	if info, err := os.Stat(f.o.path); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		t.Fatal("OAuth state must be private")
	}
	// Reload state exactly as a service restart does. Access and refresh survive;
	// unredeemed authorization codes intentionally do not.
	restored, err := newMCPOAuth(f.a.app, f.p, "knowledge.example.com", f.o.mcp)
	if err != nil {
		t.Fatal(err)
	}
	f.o = restored
	f.h = publicHandler(testRT, f.a.app, "knowledge.example.com", http.NotFoundHandler(), restored)
	f.request("POST", "/mcp", access, "{}", "application/json", 200)
	rotated := f.refresh(client, refresh, 200)
	if rotated["refresh_token"] == refresh {
		t.Fatal("refresh must rotate")
	}
	otherClient := f.registration()
	f.refresh(otherClient, refresh, 400)
	f.request("POST", "/mcp", rotated["access_token"].(string), "{}", "application/json", 200) // other client cannot revoke our family
	f.refresh(client, refresh, 400)                                                            // replay revokes new access/refresh as a family
	f.request("POST", "/mcp", rotated["access_token"].(string), "{}", "application/json", 401)
	f.refresh(client, rotated["refresh_token"].(string), 400)
}
func TestMCPOAuthRevocationPasswordExpiry(t *testing.T) {
	f := newOAuthFixture(t)
	client := f.registration()
	v := strings.Repeat("x", 64)
	result := f.exchange(client, f.code(client, v), v, 200)
	list := f.request("GET", "/oauth/connections", f.a.token, "", "", 200)["connections"].([]any)
	id := list[0].(map[string]any)["id"].(string)
	f.request("POST", "/oauth/connections", f.a.token, `{"id":"`+id+`"}`, "application/json", 200)
	f.request("POST", "/mcp", result["access_token"].(string), "{}", "application/json", 401)
	f.refresh(client, result["refresh_token"].(string), 400)
	result = f.exchange(client, f.code(client, v), v, 200)
	f.request("POST", "/oauth/revoke", "", url.Values{"client_id": {client}, "token": {result["refresh_token"].(string)}}.Encode(), "application/x-www-form-urlencoded", 200)
	f.request("POST", "/mcp", result["access_token"].(string), "{}", "application/json", 401)
	result = f.exchange(client, f.code(client, v), v, 200)
	f.o.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	f.request("POST", "/mcp", result["access_token"].(string), "{}", "application/json", 401)
	f.o.now = nil
	f.a.user.RefreshTokenKey()
	if err := f.a.app.Save(f.a.user); err != nil {
		t.Fatal(err)
	}
	f.request("POST", "/mcp", result["access_token"].(string), "{}", "application/json", 401)
	f.refresh(client, result["refresh_token"].(string), 400)
}
func TestMCPOAuthRequestBoundaries(t *testing.T) {
	f := newOAuthFixture(t)
	client := f.registration()
	v := strings.Repeat("q", 64)
	q := f.authorization(client, v)
	f.request("POST", "/oauth/authorize?"+q.Encode(), "", `{"approve":true}`, "application/json", 401)
	for key, value := range map[string]string{"redirect_uri": "https://evil.example.com/callback", "resource": "https://evil.example.com/mcp", "code_challenge_method": "plain", "scope": "admin"} {
		bad := f.authorization(client, v)
		bad.Set(key, value)
		f.request("GET", "/oauth/authorize?"+bad.Encode(), "", "", "", 400)
	}
	f.exchange(client, f.code(client, v), strings.Repeat("w", 64), 400)
	for _, redirect := range []string{"http://client.example.com/callback", "https://*.example.com/", "https://client.example.com/#fragment", "https://localhost/", "https://127.0.0.1/", "https://user@client.example.com/"} {
		body, _ := json.Marshal(map[string]any{"redirect_uris": []string{redirect}})
		f.request("POST", "/oauth/register", "", string(body), "application/json", 400)
	}
	for _, path := range []string{"/oauth/register", "/mcp", "/.well-known/oauth-authorization-server"} {
		r := httptest.NewRequest("POST", "https://knowledge.example.com"+path, strings.NewReader("{}"))
		r.Header.Set("Origin", "https://evil.example.com")
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("cross-origin %s = %d", path, w.Code)
		}
	}
	// The extension is absent without the explicit serve option.
	disabled := publicHandler(testRT, f.a.app, "knowledge.example.com", http.NotFoundHandler())
	for _, path := range []string{"/mcp", "/oauth/connections", "/.well-known/oauth-authorization-server"} {
		r := httptest.NewRequest("GET", "https://knowledge.example.com"+path, nil)
		w := httptest.NewRecorder()
		disabled.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Errorf("disabled %s = %d", path, w.Code)
		}
	}
}
func TestMCPOAuthCodeExpiryAndPersistenceFailure(t *testing.T) {
	f := newOAuthFixture(t)
	client := f.registration()
	v := strings.Repeat("s", 64)
	code := f.code(client, v)
	f.o.now = func() time.Time { return time.Now().Add(3 * time.Minute) }
	f.exchange(client, code, v, 400)
	f.o.now = nil
	code = f.code(client, v)
	old := f.o.path
	f.o.path = old + "/missing/state.json"
	f.exchange(client, code, v, 503)
	if len(f.o.state.Grants) != 0 {
		t.Fatal("failed persistence granted access")
	}
	f.o.path = old
	// Invalid verifier characters are refused, even with the matching hash.
	bad := strings.Repeat("!", 64)
	f.exchange(client, f.code(client, bad), bad, 400)
}

func (f *oauthFixture) clientRequest(path, method, client, supplied string, form url.Values, want int) map[string]any {
	f.t.Helper()
	f.requests++
	copied := url.Values{}
	for k, v := range form {
		copied[k] = append([]string{}, v...)
	}
	if method == "client_secret_post" && supplied != "" {
		copied.Set("client_secret", supplied)
	}
	r := httptest.NewRequest("POST", "https://knowledge.example.com"+path, strings.NewReader(copied.Encode()))
	r.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", f.requests)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if method == "client_secret_basic" && supplied != "" {
		r.SetBasicAuth(client, supplied)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != want {
		f.t.Fatalf("%s returned %d: %s", path, w.Code, w.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func TestMCPOAuthConfidentialClients(t *testing.T) {
	for _, method := range []string{"client_secret_basic", "client_secret_post"} {
		t.Run(method, func(t *testing.T) {
			f := newOAuthFixture(t)
			body := `{"client_name":"Confidential client","redirect_uris":["https://client.example.com/callback"],"token_endpoint_auth_method":"` + method + `"}`
			registration := f.request("POST", "/oauth/register", "", body, "application/json", 201)
			client, secret := registration["client_id"].(string), registration["client_secret"].(string)
			verifier := strings.Repeat("c", 64)
			code := f.code(client, verifier)
			values := url.Values{"client_id": {client}, "code": {code}, "redirect_uri": {"https://client.example.com/callback"}, "code_verifier": {verifier}, "resource": {f.o.resource()}, "grant_type": {"authorization_code"}}
			send := func(path string, form url.Values, supplied string, want int) map[string]any {
				return f.clientRequest(path, method, client, supplied, form, want)
			}
			send("/oauth/token", values, "", 401)
			send("/oauth/token", values, "wrong-secret", 401)
			tokens := send("/oauth/token", values, secret, 200)
			refresh := tokens["refresh_token"].(string)
			form := url.Values{"client_id": {client}, "grant_type": {"refresh_token"}, "resource": {f.o.resource()}, "refresh_token": {refresh}}
			send("/oauth/token", form, "", 401)
			newer := send("/oauth/token", form, secret, 200)
			if newer["refresh_token"] != refresh {
				t.Fatal("confidential persistent linking should retain refresh token")
			}
			f.request("POST", "/mcp", newer["access_token"].(string), "{}", "application/json", 200)
			data, _ := os.ReadFile(f.o.path)
			if strings.Contains(string(data), secret) || strings.Contains(string(data), refresh) {
				t.Fatal("raw credential persisted")
			}
			revoke := url.Values{"client_id": {client}, "token": {refresh}}
			send("/oauth/revoke", revoke, "", 401)
			send("/oauth/revoke", revoke, secret, 200)
			f.request("POST", "/mcp", newer["access_token"].(string), "{}", "application/json", 401)
		})
	}
}

func TestMCPOAuthIdleRegistrationAndCleanup(t *testing.T) {
	f := newOAuthFixture(t)
	client := f.registration()
	v := strings.Repeat("i", 64)
	now := time.Now().Add(25 * time.Hour)
	f.o.now = func() time.Time { return now }
	result := f.exchange(client, f.code(client, v), v, 200)
	updated := f.refresh(client, result["refresh_token"].(string), 200)
	if len(f.o.state.UsedRefresh) != 1 {
		t.Fatal("missing replay history")
	}
	list := f.request("GET", "/oauth/connections", f.a.token, "", "", 200)["connections"].([]any)
	id := list[0].(map[string]any)["id"].(string)
	f.request("POST", "/oauth/connections", f.a.token, `{"id":"`+id+`"}`, "application/json", 200)
	if len(f.o.state.UsedRefresh) != 0 || len(f.o.state.Access) != 0 {
		t.Fatal("revocation retained orphaned token records")
	}
	f.request("POST", "/mcp", updated["access_token"].(string), "{}", "application/json", 401)
}

func TestMCPOAuthRegistrationRateAndMethod(t *testing.T) {
	f := newOAuthFixture(t)
	for i := 0; i < 11; i++ {
		r := httptest.NewRequest("POST", "https://knowledge.example.com/oauth/register", strings.NewReader(`{"redirect_uris":["https://client.example.com/callback"]}`))
		r.RemoteAddr = "203.0.113.5:1234"
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		if i < 10 {
			if w.Code != 201 {
				t.Fatalf("registration %d: %d", i, w.Code)
			}
			var body map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if body["token_endpoint_auth_method"] != "client_secret_basic" || body["client_secret"] == nil {
				t.Fatal("DCR default must be confidential basic")
			}
		} else if w.Code != 429 {
			t.Fatalf("rate limit: %d", w.Code)
		}
	}
}

func TestMCPRequiresExplicitDomain(t *testing.T) {
	if err := ServeContext(context.Background(), nil, ServeOptions{MCP: true}); err == nil || !strings.Contains(err.Error(), "MCP requires") {
		t.Fatal("MCP without a domain must fail before opening a project")
	}
}

func TestMCPOAuthNativeCallbacks(t *testing.T) {
	for _, redirect := range []string{"http://127.0.0.1:49152/callback/server-id", "http://[::1]:49153/callback", "http://127.0.0.1/callback", "http://localhost:8787/callback", "com.example.app:/oauth/callback", "com.example.app:/oauth/callback?channel=desktop"} {
		t.Run(redirect, func(t *testing.T) {
			f := newOAuthFixture(t)
			body, _ := json.Marshal(map[string]any{"redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none"})
			client := f.request("POST", "/oauth/register", "", string(body), "application/json", 201)["client_id"].(string)
			verifier := strings.Repeat("n", 64)
			q := f.authorization(client, verifier)
			q.Set("redirect_uri", redirect)
			f.request("POST", "/oauth/authorize?"+q.Encode(), "", `{"approve":true}`, "application/json", 401)
			for _, mismatch := range []string{redirect + "/other", "http://127.0.0.1:49154/callback", "http://192.168.1.2/callback"} {
				bad := f.authorization(client, verifier)
				bad.Set("redirect_uri", mismatch)
				f.request("GET", "/oauth/authorize?"+bad.Encode(), "", "", "", 400)
			}
			authorize := func() string {
				out := f.request("POST", "/oauth/authorize?"+q.Encode(), f.a.token, `{"approve":true}`, "application/json", 200)
				u, err := url.Parse(out["redirect"].(string))
				if err != nil {
					t.Fatal(err)
				}
				if u.Query().Get("state") != "synthetic-state" {
					t.Fatal("lost state")
				}
				return u.Query().Get("code")
			}
			form := url.Values{"client_id": {client}, "code": {authorize()}, "redirect_uri": {redirect}, "code_verifier": {strings.Repeat("w", 64)}, "resource": {f.o.resource()}, "grant_type": {"authorization_code"}}
			f.request("POST", "/oauth/token", "", form.Encode(), "application/x-www-form-urlencoded", 400)
			form.Set("code", authorize())
			form.Set("code_verifier", verifier)
			form.Set("redirect_uri", redirect+"/other")
			f.request("POST", "/oauth/token", "", form.Encode(), "application/x-www-form-urlencoded", 400)
			form.Set("code", authorize())
			form.Set("redirect_uri", redirect)
			result := f.request("POST", "/oauth/token", "", form.Encode(), "application/x-www-form-urlencoded", 200)
			f.request("POST", "/mcp", result["access_token"].(string), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"native-test","version":"1"}}}`, "application/json", 200)
			f.refresh(client, result["refresh_token"].(string), 200)
		})
	}
	for _, redirect := range []string{"http://localhost.example.com:49152/callback", "http://sub.localhost:49152/callback", "http://localhost.:49152/callback", "http://127.0.0.1.example.com/callback", "http://192.168.1.1/callback", "http://0.0.0.0/callback", "http://[::]/callback", "http://127.0.0.1:0/callback", "http://127.0.0.1:65536/callback", "http://127.0.0.1:/callback", "http://user@127.0.0.1/callback", "http://127.0.0.1/callback#fragment", "custom://callback"} {
		if validOAuthRedirect(redirect) {
			t.Errorf("accepted unsafe callback %q", redirect)
		}
	}
}

// Registering mixed web and native callbacks must preserve every exact URI. A
// client may select any registered callback, but cannot switch during exchange.
func TestMCPOAuthMixedCallbacks(t *testing.T) {
	const legacy = "cursor://anysphere.cursor-mcp/oauth/callback"
	redirects := []string{
		"https://www.cursor.com/agents/mcp/oauth/callback",
		"http://localhost:8787/callback",
		legacy,
	}
	f := newOAuthFixture(t)
	body, _ := json.Marshal(map[string]any{
		"redirect_uris": redirects, "token_endpoint_auth_method": "none",
		// Client-provided metadata must never enable a server exception.
		"redirect_exceptions": []string{legacy},
	})
	denied := f.request("POST", "/oauth/register", "", string(body), "application/json", 400)
	if denied["error"] != "invalid_redirect_uri" || !strings.Contains(fmt.Sprint(denied["error_description"]), "redirect_uris[2]") {
		t.Fatalf("missing failing callback index: %v", denied)
	}
	if strings.Contains(fmt.Sprint(denied), legacy) || len(f.o.state.Clients) != 0 {
		t.Fatal("rejected array leaked its callback or partially registered a client")
	}
	if _, err := os.Stat(f.o.path); !os.IsNotExist(err) {
		t.Fatalf("rejected registration wrote OAuth state: %v", err)
	}
	f.o.redirectExceptions = map[string]bool{legacy: true}
	registered := f.request("POST", "/oauth/register", "", string(body), "application/json", 201)
	stored, _ := json.Marshal(registered["redirect_uris"])
	want, _ := json.Marshal(redirects)
	if string(stored) != string(want) {
		t.Fatalf("registration changed callbacks: %s", stored)
	}
	client := registered["client_id"].(string)
	for i, redirect := range redirects {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			parentT := f.t
			f.t = t
			defer func() { f.t = parentT }()
			verifier := strings.Repeat("m", 64)
			q := f.authorization(client, verifier)
			q.Set("redirect_uri", redirect)
			f.request("GET", "/oauth/authorize?"+q.Encode(), "", "", "", 200)
			f.request("POST", "/oauth/authorize?"+q.Encode(), "", `{"approve":true}`, "application/json", 401)
			for _, mismatch := range []string{redirect + "/", redirect + "?different=true", strings.Replace(redirect, "callback", "other", 1)} {
				bad := f.authorization(client, verifier)
				bad.Set("redirect_uri", mismatch)
				f.request("GET", "/oauth/authorize?"+bad.Encode(), "", "", "", 400)
			}
			issue := func(approve bool) string {
				body, _ := json.Marshal(map[string]bool{"approve": approve})
				out := f.request("POST", "/oauth/authorize?"+q.Encode(), f.a.token, string(body), "application/json", 200)
				u, err := url.Parse(out["redirect"].(string))
				if err != nil {
					t.Fatal(err)
				}
				values := u.Query()
				if values.Get("state") != "synthetic-state" {
					t.Fatal("lost state")
				}
				u.RawQuery = ""
				if u.String() != redirect {
					t.Fatal("authorization changed callback")
				}
				if !approve {
					if values.Get("error") != "access_denied" || values.Get("code") != "" {
						t.Fatal("denied consent issued a code")
					}
					return ""
				}
				return values.Get("code")
			}
			issue(false)
			form := url.Values{"client_id": {client}, "code": {issue(true)}, "redirect_uri": {redirects[(i+1)%len(redirects)]}, "code_verifier": {verifier}, "resource": {f.o.resource()}, "grant_type": {"authorization_code"}}
			f.request("POST", "/oauth/token", "", form.Encode(), "application/x-www-form-urlencoded", 400)
			form.Set("code", issue(true))
			form.Set("redirect_uri", redirect)
			form.Set("code_verifier", strings.Repeat("w", 64))
			f.request("POST", "/oauth/token", "", form.Encode(), "application/x-www-form-urlencoded", 400)
			form.Set("code", issue(true))
			form.Set("code_verifier", verifier)
			result := f.request("POST", "/oauth/token", "", form.Encode(), "application/x-www-form-urlencoded", 200)
			f.request("POST", "/mcp", result["access_token"].(string), "{}", "application/json", 200)
			f.refresh(client, result["refresh_token"].(string), 200)
		})
	}
	// An exception is for one callback, not all callbacks sharing its scheme,
	// authority or path prefix. Failure leaves the prior registration intact.
	for _, redirect := range []string{legacy + "/other", "cursor://other/oauth/callback", legacy + "?next=other", "other://anysphere.cursor-mcp/oauth/callback"} {
		body, _ := json.Marshal(map[string]any{"redirect_uris": []string{redirects[0], redirect}, "token_endpoint_auth_method": "none"})
		f.request("POST", "/oauth/register", "", string(body), "application/json", 400)
		if len(f.o.state.Clients) != 1 {
			t.Fatal("invalid exception variant partially registered a client")
		}
	}
}

func TestMCPOAuthRedirectExceptionConfiguration(t *testing.T) {
	const callback = "cursor://anysphere.cursor-mcp/oauth/callback"
	for _, raw := range []string{"", "[]", `["` + callback + `"]`} {
		exceptions, err := parseOAuthRedirectExceptions("FIXTURE_MCP_REDIRECT_EXCEPTIONS", raw)
		if err != nil {
			t.Fatalf("valid exception configuration: %v", err)
		}
		if raw != "" && raw != "[]" && (!exceptions[callback] || len(exceptions) != 1) {
			t.Fatal("exception did not preserve the exact callback")
		}
	}
	for _, raw := range []string{
		`[`, `null`, `"cursor://app/callback"`, `{}`, `[1]`, `["cursor://app/callback"] {}`,
		`["https://client.example.com/callback"]`, `["http://localhost:8787/callback"]`,
		`["javascript://app/callback"]`, `["data://app/callback"]`, `["file:///callback"]`,
		`["cursor:callback"]`, `["cursor://user@app/callback"]`, `["cursor://app/callback#fragment"]`,
		`["cursor://app/callback*"]`, `["cursor://app/call back"]`, `["cursor://app/call\nback"]`,
	} {
		if _, err := parseOAuthRedirectExceptions("FIXTURE_MCP_REDIRECT_EXCEPTIONS", raw); err == nil {
			t.Errorf("accepted invalid operator exception configuration %q", raw)
		}
	}
	tooMany := make([]string, 33)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("custom://app/callback/%d", i)
	}
	raw, _ := json.Marshal(tooMany)
	if _, err := parseOAuthRedirectExceptions("FIXTURE_MCP_REDIRECT_EXCEPTIONS", string(raw)); err == nil {
		t.Fatal("accepted more than 32 operator exceptions")
	}
	// Invalid configuration must not reveal a callback/query supplied by an
	// operator in startup errors and must fail before reading OAuth state.
	const canary = "private-callback-canary"
	t.Setenv("FIXTURE_MCP_REDIRECT_EXCEPTIONS", `["https://example.com/`+canary+`"]`)
	a := newTestApp(t)
	p := &Project{rt: testRT, Cache: t.TempDir(), Config: ProjectConfig{Instance: "exception-fixture"}}
	if _, err := newMCPOAuth(a.app, p, "knowledge.example.com", http.NotFoundHandler()); err == nil || strings.Contains(err.Error(), canary) {
		t.Fatal("invalid constructor configuration was accepted or disclosed")
	}
	t.Setenv("FIXTURE_MCP_REDIRECT_EXCEPTIONS", `["`+callback+`"]`)
	o, err := newMCPOAuth(a.app, p, "knowledge.example.com", http.NotFoundHandler())
	if err != nil || !o.redirectExceptions[callback] {
		t.Fatalf("constructor did not load operator exceptions: %v", err)
	}
}

func TestMCPOAuthRedirectExceptionRemoval(t *testing.T) {
	const callback = "cursor://anysphere.cursor-mcp/oauth/callback"
	t.Setenv("FIXTURE_MCP_REDIRECT_EXCEPTIONS", `["`+callback+`"]`)
	f := newOAuthFixture(t)
	body, _ := json.Marshal(map[string]any{"redirect_uris": []string{callback}, "token_endpoint_auth_method": "none"})
	client := f.request("POST", "/oauth/register", "", string(body), "application/json", 201)["client_id"].(string)
	q := f.authorization(client, strings.Repeat("v", 64))
	q.Set("redirect_uri", callback)
	f.request("GET", "/oauth/authorize?"+q.Encode(), "", "", "", 200)
	// Reloading persisted client metadata must not preserve a removed operator
	// exception or let that old registration authorize a new grant.
	t.Setenv("FIXTURE_MCP_REDIRECT_EXCEPTIONS", "")
	o, err := newMCPOAuth(f.a.app, f.p, "knowledge.example.com", http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	f.o = o
	f.h = publicHandler(testRT, f.a.app, "knowledge.example.com", http.NotFoundHandler(), o)
	f.request("GET", "/oauth/authorize?"+q.Encode(), "", "", "", 400)
	f.request("POST", "/oauth/authorize?"+q.Encode(), f.a.token, `{"approve":true}`, "application/json", 400)
	if len(o.codes) != 0 || len(o.state.Grants) != 0 {
		t.Fatal("removed exception authorized new access")
	}
}

func TestMCPOAuthUnsafeNativeCallbacks(t *testing.T) {
	for _, redirect := range []string{
		"http://localhost:0/callback", "http://localhost:65536/callback", "http://localhost:/callback",
		"http://localhost@evil.example/callback", "http://evil.example@localhost/callback", "http://localhost\\@evil.example/callback",
		"http://2130706433/callback", "http://127.1/callback", "http://0x7f000001/callback",
		"com.example.app:callback", "com.example.app://callback", "com.example.app:///callback", "com.example.app:",
		"com.example.app:/callback#fragment", "com.example.app:/callback#", "com.example.app:/callback*",
		"com.example.app:/callback%0a", "com.example.app:/callback%5c", "com.example.app:/callback\t",
		"com..example:/callback", ".example:/callback", "com.example.:/callback", "com.-example:/callback",
		"javascript:alert(1)", "javascript://app/callback", "data:text/html,hello", "file:///callback", "https:/callback",
		"cursor://anysphere.cursor-mcp/oauth/callback", "custom://callback",
	} {
		if validOAuthRedirect(redirect) {
			t.Errorf("accepted unsafe or unconfigured callback %q", redirect)
		}
	}
}

func TestMCPOAuthOptionalResourceLifecycle(t *testing.T) {
	for _, method := range []string{"none", "client_secret_basic", "client_secret_post"} {
		for _, mode := range []string{"omitted", "explicit"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				f := newOAuthFixture(t)
				body := `{"client_name":"Optional resource client","redirect_uris":["https://client.example.com/callback"],"token_endpoint_auth_method":"` + method + `"}`
				registration := f.request("POST", "/oauth/register", "", body, "application/json", 201)
				client := registration["client_id"].(string)
				secret, _ := registration["client_secret"].(string)
				verifier := strings.Repeat("r", 64)
				setResource := func(q url.Values) {
					switch mode {
					case "omitted":
						q.Del("resource")
					case "explicit":
						q.Set("resource", f.o.resource())
					}
				}
				q := f.authorization(client, verifier)
				setResource(q)
				f.request("GET", "/oauth/authorize?"+q.Encode(), "", "", "", 200)
				f.request("POST", "/oauth/authorize?"+q.Encode(), "", `{"approve":true}`, "application/json", 401)
				denied := f.request("POST", "/oauth/authorize?"+q.Encode(), f.a.token, `{"approve":false}`, "application/json", 200)
				if !strings.Contains(denied["redirect"].(string), "error=access_denied") || len(f.o.codes) != 0 {
					t.Fatal("denial must not issue a code")
				}
				out := f.request("POST", "/oauth/authorize?"+q.Encode(), f.a.token, `{"approve":true}`, "application/json", 200)
				u, err := url.Parse(out["redirect"].(string))
				if err != nil {
					t.Fatal(err)
				}
				form := url.Values{"client_id": {client}, "code": {u.Query().Get("code")}, "redirect_uri": {q.Get("redirect_uri")}, "code_verifier": {verifier}, "grant_type": {"authorization_code"}}
				setResource(form)
				result := f.clientRequest("/oauth/token", method, client, secret, form, 200)
				access := result["access_token"].(string)
				f.request("POST", "/mcp", access, "{}", "application/json", 200)
				form = url.Values{"client_id": {client}, "refresh_token": {result["refresh_token"].(string)}, "grant_type": {"refresh_token"}}
				setResource(form)
				refreshed := f.clientRequest("/oauth/token", method, client, secret, form, 200)
				f.request("POST", "/mcp", refreshed["access_token"].(string), "{}", "application/json", 200)
				// A second domain sharing the account and cache still has independent,
				// origin-bound OAuth state and cannot accept this endpoint's token.
				other, err := newMCPOAuth(f.a.app, f.p, "other.example.com", f.o.mcp)
				if err != nil {
					t.Fatal(err)
				}
				h := publicHandler(testRT, f.a.app, "other.example.com", http.NotFoundHandler(), other)
				r := httptest.NewRequest("POST", "https://other.example.com/mcp", strings.NewReader("{}"))
				r.Header.Set("Authorization", "Bearer "+access)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != 401 {
					t.Fatalf("token accepted on another domain: %d", w.Code)
				}
			})
		}
	}
}

func TestMCPOAuthResourceRejections(t *testing.T) {
	f := newOAuthFixture(t)
	client := f.registration()
	verifier := strings.Repeat("r", 64)
	for _, resources := range [][]string{{""}, {"https://other.example.com/mcp"}, {" "}, {f.o.resource() + "/"}, {"", f.o.resource()}, {f.o.resource(), f.o.resource()}} {
		q := f.authorization(client, verifier)
		q["resource"] = resources
		f.request("GET", "/oauth/authorize?"+q.Encode(), "", "", "", 400)
		for _, grant := range []string{"authorization_code", "refresh_token"} {
			form := url.Values{"client_id": {client}, "grant_type": {grant}, "resource": resources}
			result := f.request("POST", "/oauth/token", "", form.Encode(), "application/x-www-form-urlencoded", 400)
			want := "invalid_target"
			if len(resources) > 1 {
				want = "invalid_request"
			}
			if result["error"] != want {
				t.Fatalf("resource %q: got %v, want %s", resources, result["error"], want)
			}
		}
	}
}

func TestMCPOAuthAuthorizationErrors(t *testing.T) {
	f := newOAuthFixture(t)
	client := f.registration()
	for _, tc := range []struct{ key, value, message string }{
		{"redirect_uri", "https://other.example.com/callback", "redirect_uri must exactly match a registered callback"},
		{"response_type", "token", "response_type must be code"},
		{"resource", "https://other.example.com/mcp", "resource must be this MCP endpoint"},
		{"code_challenge_method", "plain", "code_challenge_method must be S256"},
		{"code_challenge", "invalid", "code_challenge must be a 43-character base64url-encoded SHA-256 hash"},
		{"state", strings.Repeat("s", 2049), "state must not exceed 2048 bytes"},
		{"scope", "admin", "only knowledge scope is supported"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			q := f.authorization(client, strings.Repeat("r", 64))
			q.Del("resource")
			q.Set(tc.key, tc.value)
			out := f.request("GET", "/oauth/authorize?"+q.Encode(), "", "", "", 400)
			if out["error_description"] != tc.message {
				t.Fatalf("got %v, want %s", out["error_description"], tc.message)
			}
		})
	}
}
