package appserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pocketcontext-labs/pocketcontext-core/atomicfile"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
)

// MCPAuthToken is an internal ordinary-account credential for the authenticated
// MCP request. It must never be returned to an MCP client or persisted by tools.
func MCPAuthToken(ctx context.Context) string {
	token, _ := ctx.Value(mcpAuthKey{}).(string)
	return token
}

type mcpAuthKey struct{}

const mcpScope = "knowledge"
const oauthAccessLifetime = 10 * time.Minute
const oauthRefreshLifetime = 30 * 24 * time.Hour

type oauthClient struct {
	ID         string   `json:"client_id"`
	Name       string   `json:"client_name"`
	Redirects  []string `json:"redirect_uris"`
	Created    int64    `json:"created"`
	Method     string   `json:"method"`
	SecretHash string   `json:"secret_hash,omitempty"`
}
type oauthGrant struct {
	ID          string `json:"id"`
	Client      string `json:"client"`
	User        string `json:"user"`
	KeyHash     string `json:"key_hash"`
	RefreshHash string `json:"refresh_hash"`
	Created     int64  `json:"created"`
	Expires     int64  `json:"expires"`
}
type oauthAccess struct {
	Grant   string `json:"grant"`
	Expires int64  `json:"expires"`
}
type oauthState struct {
	Version     int                    `json:"version"`
	Origin      string                 `json:"origin"`
	Instance    string                 `json:"instance"`
	Clients     map[string]oauthClient `json:"clients"`
	Grants      map[string]oauthGrant  `json:"grants"`
	Access      map[string]oauthAccess `json:"access"`
	UsedRefresh map[string]oauthAccess `json:"used_refresh"`
}
type oauthCode struct {
	Client, Redirect, Challenge, User, KeyHash string
	Expires                                    time.Time
}
type mcpOAuth struct {
	rt           *Runtime
	mu           sync.Mutex
	app          core.App
	origin, path string
	state        oauthState
	codes        map[string]oauthCode
	now          func() time.Time
	mcp          http.Handler
	limiter      publicAuthLimiter
	hosted       bool
	// Operator policy is machine-local and never supplied by a registering client.
	redirectExceptions map[string]bool
}

func oauthHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func (o *mcpOAuth) clock() time.Time {
	if o.now != nil {
		return o.now()
	}
	return time.Now()
}
func (o *mcpOAuth) resource() string { return o.origin + "/mcp" }

// This authorization server serves only its own MCP endpoint. Clients that omit
// resource still receive grants bound to that endpoint
// through this instance's private OAuth state; explicit foreign resources fail.
func (o *mcpOAuth) acceptsResource(values url.Values) bool {
	resources, supplied := values["resource"]
	return !supplied || len(resources) == 1 && resources[0] == o.resource()
}

func newMCPOAuth(app core.App, p *Project, domain string, mcp http.Handler) (*mcpOAuth, error) {
	exceptions, err := parseOAuthRedirectExceptions(p.rt.cfg.Identity.EnvPrefix+"_MCP_REDIRECT_EXCEPTIONS", os.Getenv(p.rt.cfg.Identity.EnvPrefix+"_MCP_REDIRECT_EXCEPTIONS"))
	if err != nil {
		return nil, err
	}
	o := &mcpOAuth{rt: p.rt, app: app, origin: "https://" + domain, codes: map[string]oauthCode{}, mcp: mcp, redirectExceptions: exceptions}
	o.path = filepath.Join(p.Cache, "mcp-oauth-"+oauthHash(o.origin)[:16]+".json")
	o.state = oauthState{Version: 1, Origin: o.origin, Instance: p.Config.Instance, Clients: map[string]oauthClient{}, Grants: map[string]oauthGrant{}, Access: map[string]oauthAccess{}, UsedRefresh: map[string]oauthAccess{}}
	if st, err := os.Lstat(o.path); err == nil {
		if !st.Mode().IsRegular() || st.Size() > 16<<20 {
			return nil, errors.New("invalid MCP authorization state file")
		}
		data, err := os.ReadFile(o.path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &o.state); err != nil {
			return nil, errors.New("invalid MCP authorization state; preserve it and investigate")
		}
		if o.state.Version != 1 || o.state.Origin != o.origin || o.state.Instance != p.Config.Instance || o.state.Clients == nil || o.state.Grants == nil || o.state.Access == nil || o.state.UsedRefresh == nil {
			return nil, errors.New("MCP authorization state belongs to a different instance or format")
		}
		if err := os.Chmod(o.path, 0600); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return o, nil
}

// mutate persists before publishing an authorization change in memory. Failures
// leave the previous state intact, including on a failed revoke or code exchange.
// Caller holds mu. State contains hashes, never usable access/refresh credentials.
func (o *mcpOAuth) mutate(fn func(*oauthState) error) error {
	encoded, err := json.Marshal(o.state)
	if err != nil {
		return err
	}
	var next oauthState
	if err = json.Unmarshal(encoded, &next); err != nil {
		return err
	}
	now := o.clock().Unix()
	for hash, a := range next.Access {
		if a.Expires <= now {
			delete(next.Access, hash)
		}
	}
	for hash, a := range next.UsedRefresh {
		if a.Expires <= now {
			delete(next.UsedRefresh, hash)
		}
	}
	for id, g := range next.Grants {
		if g.Expires <= now {
			delete(next.Grants, id)
		}
	}
	for hash, a := range next.UsedRefresh {
		if _, ok := next.Grants[a.Grant]; !ok {
			delete(next.UsedRefresh, hash)
		}
	}
	for hash, a := range next.Access {
		if _, ok := next.Grants[a.Grant]; !ok {
			delete(next.Access, hash)
		}
	}

	if err = fn(&next); err != nil {
		return err
	}
	for id, c := range next.Clients {
		if c.Created+86400 > now {
			continue
		}
		used := false
		for _, g := range next.Grants {
			if g.Client == id {
				used = true
				break
			}
		}
		for _, code := range o.codes {
			if code.Client == id && code.Expires.After(o.clock()) {
				used = true
				break
			}
		}
		if !used {
			delete(next.Clients, id)
		}
	}
	for hash, a := range next.UsedRefresh {
		if _, ok := next.Grants[a.Grant]; !ok {
			delete(next.UsedRefresh, hash)
		}
	}
	for hash, a := range next.Access {
		if _, ok := next.Grants[a.Grant]; !ok {
			delete(next.Access, hash)
		}
	}
	encoded, err = json.Marshal(next)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(o.path), ".mcp-oauth-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(encoded)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = atomicfile.RenameRetry(temp, o.path)
	}
	if err != nil {
		return err
	}
	o.state = next
	return nil
}

func oauthJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func oauthError(w http.ResponseWriter, status int, code, description string) {
	if out, ok := w.(*oauthResponse); ok && out.reason == "" {
		outcome := "rejected"
		if status >= 500 {
			outcome = "internal_error"
		}
		setOAuthOutcome(w, oauthFailureReason(code, description), outcome)
	}
	oauthJSON(w, status, map[string]string{"error": code, "error_description": description})
}
func oauthDecode(r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("JSON required")
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.Decode(new(any)) != io.EOF {
		return errors.New("one JSON value required")
	}
	return nil
}
func validOAuthRedirect(raw string) bool {
	return oauthRedirectError(raw, nil) == ""
}

// Validate URI syntax before applying transport policy. Never return the URI in
// an error: callback paths and queries may contain client-specific private data.
func parseOAuthRedirect(raw string) (*url.URL, string) {
	u, err := url.Parse(raw)
	if err != nil || raw == "" || len(raw) > 2048 || u.Scheme == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(raw, "\\#*") || strings.IndexFunc(raw, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return nil, "malformed callback URI"
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil || strings.Contains(decoded, "\\") || strings.IndexFunc(decoded, unicode.IsControl) >= 0 {
		return nil, "malformed callback URI"
	}
	if u.Host == "" && strings.HasPrefix(raw[strings.IndexByte(raw, ':')+1:], "//") {
		return nil, "empty callback authority"
	}
	return u, ""
}

func oauthRedirectError(raw string, exceptions map[string]bool) string {
	u, reason := parseOAuthRedirect(raw)
	if reason != "" {
		return reason
	}
	// Native clients receive the authorization code on their own loopback
	// listener. localhost is a compatibility concession; other hostnames and
	// LAN addresses remain forbidden. The server never resolves or fetches it.
	if u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost") {
		host := u.Hostname()
		if host == "::1" {
			host = "[::1]"
		}
		if u.Port() != "" {
			host += ":" + u.Port()
		}
		if u.Host != host {
			return "invalid loopback callback authority"
		}
		if u.Port() == "" {
			if !strings.HasSuffix(u.Host, ":") {
				return ""
			}
		} else if port, err := strconv.Atoi(u.Port()); err == nil && port > 0 && port <= 65535 {
			return ""
		}
		return "invalid loopback callback port"
	}
	if u.Scheme == "http" {
		return "HTTP callbacks require literal loopback or exact localhost"
	}
	if u.Scheme == "https" {
		host := strings.ToLower(u.Hostname())
		if host == "localhost" || !strings.Contains(host, ".") || strings.HasSuffix(host, ".localhost") || net.ParseIP(host) != nil || strings.HasSuffix(u.Host, ":") || u.Port() != "" && u.Port() != "443" {
			return "HTTPS callbacks require a public hostname and the default HTTPS port"
		}
		return ""
	}
	if !safeOAuthPrivateRedirect(u) {
		return "unsupported private callback URI"
	}
	if exceptions[raw] || u.Host == "" && reverseDomainScheme(u.Scheme) {
		return ""
	}
	return "private callback requires a reverse-domain scheme without authority or an exact operator exception"
}

func reverseDomainScheme(scheme string) bool {
	labels := strings.Split(scheme, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || label[0] < 'a' || label[0] > 'z' || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func safeOAuthPrivateRedirect(u *url.URL) bool {
	// An exception permits native app dispatch, never browser scripting, local
	// files or other standard transports. Opaque URIs were rejected above.
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "javascript", "vbscript", "data", "file", "blob", "about", "intent", "ftp", "ftps", "ws", "wss", "mailto", "tel", "sms", "ssh", "shell", "cmd", "powershell", "bash":
		return false
	}
	return strings.HasPrefix(u.Path, "/") && !strings.HasPrefix(u.Path, "//") && (u.Host != "" || u.OmitHost) && u.Host == u.Hostname() && !strings.Contains(u.Host, ":")
}

func parseOAuthRedirectExceptions(name, raw string) (map[string]bool, error) {
	result := map[string]bool{}
	if raw == "" {
		return result, nil
	}
	var redirects []string
	if len(raw) > 64<<10 || json.Unmarshal([]byte(raw), &redirects) != nil || redirects == nil || len(redirects) > 32 {
		return nil, errors.New(name + " must be a JSON array of at most 32 exact private callbacks")
	}
	for i, redirect := range redirects {
		u, reason := parseOAuthRedirect(redirect)
		if reason != "" || !safeOAuthPrivateRedirect(u) {
			return nil, fmt.Errorf("%s[%d]: a safe, absolute private callback is required", name, i)
		}
		result[redirect] = true
	}
	return result, nil
}
func oauthRoute(method, p string) bool {
	switch p {
	case "/mcp":
		return method == "POST" || method == "GET" || method == "DELETE"
	case "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server", "/oauth/app.js":
		return method == "GET"
	case "/oauth/authorize", "/oauth/connections":
		return method == "GET" || method == "POST"
	case "/oauth/register", "/oauth/token", "/oauth/revoke":
		return method == "POST"
	}
	return false
}
func (o *mcpOAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.observe(w, r, o.serveHTTP)
}
func (o *mcpOAuth) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.URL.Path != "/mcp" {
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	}
	if r.URL.Path == "/oauth/register" || r.URL.Path == "/oauth/token" || r.URL.Path == "/oauth/revoke" || r.URL.Path == "/oauth/authorize" && r.Method == "POST" {
		if !o.limiter.allow(r.RemoteAddr) {
			oauthRateLimit(o.app, w, r, o.limiter.rejection(r.RemoteAddr, "oauth_auth"), "slow_down", "Too many authorization attempts.")
			return
		}
	}
	switch r.URL.Path {
	case "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp":
		oauthJSON(w, 200, map[string]any{"resource": o.resource(), "authorization_servers": []string{o.origin}, "scopes_supported": []string{mcpScope}, "bearer_methods_supported": []string{"header"}, "resource_name": o.rt.cfg.Text.OAuthResourceName})
	case "/.well-known/oauth-authorization-server":
		oauthJSON(w, 200, map[string]any{"issuer": o.origin, "authorization_endpoint": o.origin + "/oauth/authorize", "token_endpoint": o.origin + "/oauth/token", "registration_endpoint": o.origin + "/oauth/register", "revocation_endpoint": o.origin + "/oauth/revoke", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{mcpScope}})
	case "/oauth/register":
		o.register(w, r)
	case "/oauth/authorize":
		o.authorize(w, r)
	case "/oauth/token":
		o.token(w, r)
	case "/oauth/revoke":
		o.revoke(w, r)
	case "/oauth/connections":
		o.connections(w, r)
	case "/oauth/app.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = io.WriteString(w, oauthScript(o.rt.cfg.Identity.ReaderStorageKey))
	case "/mcp":
		o.access(w, r)
	default:
		http.NotFound(w, r)
	}
}
func (o *mcpOAuth) register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name          string   `json:"client_name"`
		Redirects     []string `json:"redirect_uris"`
		Method        string   `json:"token_endpoint_auth_method"`
		GrantTypes    []string `json:"grant_types"`
		ResponseTypes []string `json:"response_types"`
	}
	if oauthDecode(r, &in) != nil || len(in.Redirects) == 0 || len(in.Redirects) > 8 || len(in.Name) > 120 || strings.IndexFunc(in.Name, unicode.IsControl) >= 0 || in.Method != "" && in.Method != "none" && in.Method != "client_secret_basic" && in.Method != "client_secret_post" {
		oauthError(w, 400, "invalid_client_metadata", "Use supported exact callback URIs and client authentication.")
		return
	}
	for i, redirect := range in.Redirects {
		if reason := oauthRedirectError(redirect, o.redirectExceptions); reason != "" {
			oauthError(w, 400, "invalid_redirect_uri", fmt.Sprintf("redirect_uris[%d]: %s", i, reason))
			return
		}
	}
	for _, g := range in.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, 400, "invalid_client_metadata", "Unsupported grant type.")
			return
		}
	}
	for _, g := range in.ResponseTypes {
		if g != "code" {
			oauthError(w, 400, "invalid_client_metadata", "Only response_type code is supported.")
			return
		}
	}
	if strings.TrimSpace(in.Name) == "" {
		in.Name = "MCP client"
	}
	if in.Method == "" {
		in.Method = "client_secret_basic"
	}
	var secret string
	c := oauthClient{ID: atomicfile.RandomHex(24), Name: in.Name, Redirects: in.Redirects, Created: o.clock().Unix(), Method: in.Method}
	if in.Method != "none" {
		secret = atomicfile.RandomHex(32)
		c.SecretHash = oauthHash(secret)
	}
	o.mu.Lock()
	err := o.mutate(func(s *oauthState) error {
		if len(s.Clients) >= 256 {
			return errors.New("client limit reached")
		}
		s.Clients[c.ID] = c
		return nil
	})
	o.mu.Unlock()
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable", "Could not register client; try later or remove unused connections.")
		return
	}
	response := map[string]any{"client_id": c.ID, "client_id_issued_at": c.Created, "client_name": c.Name, "redirect_uris": c.Redirects, "token_endpoint_auth_method": c.Method, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "scope": mcpScope}
	if secret != "" {
		response["client_secret"] = secret
		response["client_secret_expires_at"] = 0
	}
	setOAuthOutcome(w, "registration_complete", "success")
	oauthJSON(w, 201, response)
}
func (o *mcpOAuth) authRequest(q url.Values) (oauthClient, error) {
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "resource", "scope", "state"} {
		if len(q[key]) > 1 {
			return oauthClient{}, errors.New("duplicate authorization parameter")
		}
	}
	c, ok := o.state.Clients[q.Get("client_id")]
	if !ok {
		return c, errors.New("unknown client")
	}
	redirect := q.Get("redirect_uri")
	found := false
	for _, v := range c.Redirects {
		if v == redirect {
			found = true
		}
	}
	if !found {
		return c, errors.New("redirect_uri must exactly match a registered callback")
	}
	if oauthRedirectError(redirect, o.redirectExceptions) != "" {
		return c, errors.New("redirect_uri is no longer permitted by operator policy")
	}
	if q.Get("response_type") != "code" {
		return c, errors.New("response_type must be code")
	}
	if !o.acceptsResource(q) {
		return c, errors.New("resource must be this MCP endpoint")
	}
	if q.Get("code_challenge_method") != "S256" {
		return c, errors.New("code_challenge_method must be S256")
	}
	challenge, err := base64.RawURLEncoding.DecodeString(q.Get("code_challenge"))
	if err != nil || len(challenge) != 32 || len(q.Get("code_challenge")) != 43 {
		return c, errors.New("code_challenge must be a 43-character base64url-encoded SHA-256 hash")
	}
	if len(q.Get("state")) > 2048 {
		return c, errors.New("state must not exceed 2048 bytes")
	}
	if q.Get("scope") != "" && q.Get("scope") != mcpScope {
		return c, errors.New("only knowledge scope is supported")
	}
	return c, nil
}
func (o *mcpOAuth) reader(r *http.Request) (*core.Record, error) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	u, err := o.app.FindAuthRecordByToken(token, core.TokenTypeAuth)
	if err != nil || u == nil || u.Collection().Name != "users" {
		return nil, errors.New("sign in to the reader first")
	}
	return u, nil
}
func (o *mcpOAuth) authorize(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	c, err := o.authRequest(r.URL.Query())
	if err != nil {
		oauthError(w, 400, "invalid_request", err.Error())
		return
	}
	if r.Method == "GET" {
		setOAuthOutcome(w, "consent_required", "success")
		o.oauthPage(w, "Authorize a connection", c.Name, r.URL.Query().Get("redirect_uri"), false, o.hosted)
		return
	}
	user, err := o.reader(r)
	if err != nil {
		oauthError(w, 401, "login_required", "Open the reader sign-in link in this browser, then return here.")
		return
	}
	var in struct {
		Approve bool `json:"approve"`
	}
	if oauthDecode(r, &in) != nil {
		oauthError(w, 400, "invalid_request", "JSON approval required.")
		return
	}
	q := r.URL.Query()
	target, _ := url.Parse(q.Get("redirect_uri"))
	params := target.Query()
	if state := q.Get("state"); state != "" {
		params.Set("state", state)
	}
	if !in.Approve {
		setOAuthOutcome(w, "consent_denied", "denied")
		params.Set("error", "access_denied")
	} else {
		now := o.clock()
		for key, code := range o.codes {
			if !now.Before(code.Expires) {
				delete(o.codes, key)
			}
		}
		if len(o.codes) >= 200 {
			oauthRateLimit(o.app, w, r, rateLimitInfo{"oauth_pending", 120, 200, 0, 120}, "temporarily_unavailable", "Too many pending authorizations.")
			return
		}
		code := atomicfile.RandomHex(32)
		o.codes[oauthHash(code)] = oauthCode{Client: c.ID, Redirect: q.Get("redirect_uri"), Challenge: q.Get("code_challenge"), User: user.Id, KeyHash: oauthHash(user.TokenKey()), Expires: now.Add(2 * time.Minute)}
		params.Set("code", code)
		setOAuthOutcome(w, "consent_approved", "success")
	}
	target.RawQuery = params.Encode()
	oauthJSON(w, 200, map[string]string{"redirect": target.String()})
}
func validVerifier(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}
func (o *mcpOAuth) grantUser(g oauthGrant) (*core.Record, error) {
	u, err := o.app.FindRecordById("users", g.User)
	if err != nil || u == nil || subtle.ConstantTimeCompare([]byte(g.KeyHash), []byte(oauthHash(u.TokenKey()))) != 1 {
		return nil, errors.New("grant revoked")
	}
	return u, nil
}

// authenticateClient binds token requests to the registered public or confidential client.
// Caller holds mu and ParseForm has succeeded; mixed authentication is refused.
func (o *mcpOAuth) authenticateClient(r *http.Request) (oauthClient, error) {
	f := r.PostForm
	if len(f["client_id"]) > 1 || len(f["client_secret"]) > 1 {
		return oauthClient{}, errors.New("duplicate client credentials")
	}
	id, secret := f.Get("client_id"), f.Get("client_secret")
	method := "none"
	if r.Header.Get("Authorization") != "" {
		basicID, basicSecret, ok := r.BasicAuth()
		if !ok || secret != "" {
			return oauthClient{}, errors.New("invalid client authentication")
		}
		var err error
		basicID, err = url.QueryUnescape(basicID)
		if err != nil {
			return oauthClient{}, err
		}
		basicSecret, err = url.QueryUnescape(basicSecret)
		if err != nil {
			return oauthClient{}, err
		}
		if id != "" && id != basicID {
			return oauthClient{}, errors.New("conflicting client identity")
		}
		id, secret, method = basicID, basicSecret, "client_secret_basic"
	} else if secret != "" {
		method = "client_secret_post"
	}
	c, ok := o.state.Clients[id]
	if !ok || c.Method != method {
		return c, errors.New("invalid client")
	}
	if method != "none" && subtle.ConstantTimeCompare([]byte(c.SecretHash), []byte(oauthHash(secret))) != 1 {
		return c, errors.New("invalid client secret")
	}
	return c, nil
}

func (o *mcpOAuth) token(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") || r.ParseForm() != nil {
		oauthError(w, 400, "invalid_request", "Form body required.")
		return
	}
	f := r.PostForm
	for _, key := range []string{"grant_type", "client_id", "code", "redirect_uri", "code_verifier", "resource", "refresh_token", "scope"} {
		if len(f[key]) > 1 {
			oauthError(w, 400, "invalid_request", "Duplicate token parameter.")
			return
		}
	}
	if f.Get("scope") != "" && f.Get("scope") != mcpScope {
		oauthError(w, 400, "invalid_scope", "Only knowledge scope is supported.")
		return
	}
	if !o.acceptsResource(f) {
		oauthError(w, 400, "invalid_target", "The resource must be this MCP endpoint.")
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	client, authErr := o.authenticateClient(r)
	if authErr != nil {
		oauthError(w, 401, "invalid_client", "Unknown client.")
		return
	}
	now := o.clock()
	var grant oauthGrant
	var refresh string
	var usedRefresh string
	var usedRefreshExpires int64
	switch f.Get("grant_type") {
	case "authorization_code":
		hash := oauthHash(f.Get("code"))
		code, ok := o.codes[hash]
		// Consume on an attempted exchange, including incorrect PKCE. A lost response
		// requires a fresh consent flow rather than replaying an authorization code.
		delete(o.codes, hash)
		challenge := sha256.Sum256([]byte(f.Get("code_verifier")))
		if !ok || !now.Before(code.Expires) || code.Client != client.ID || code.Redirect != f.Get("redirect_uri") || !validVerifier(f.Get("code_verifier")) || subtle.ConstantTimeCompare([]byte(code.Challenge), []byte(base64.RawURLEncoding.EncodeToString(challenge[:]))) != 1 {
			oauthError(w, 400, "invalid_grant", "Invalid or expired authorization code or PKCE verifier.")
			return
		}
		refresh = atomicfile.RandomHex(32)
		grant = oauthGrant{ID: atomicfile.RandomHex(24), Client: code.Client, User: code.User, KeyHash: code.KeyHash, RefreshHash: oauthHash(refresh), Created: now.Unix(), Expires: now.Add(oauthRefreshLifetime).Unix()}
	case "refresh_token":
		refresh = f.Get("refresh_token")
		hash := oauthHash(refresh)
		if previous, ok := o.state.UsedRefresh[hash]; ok && previous.Expires > now.Unix() {
			if priorGrant, exists := o.state.Grants[previous.Grant]; !exists || priorGrant.Client != client.ID {
				oauthError(w, 400, "invalid_grant", "Invalid refresh token.")
				return
			}
			if err := o.mutate(func(s *oauthState) error { delete(s.Grants, previous.Grant); return nil }); err != nil {
				oauthError(w, 503, "temporarily_unavailable", "Could not save replay revocation.")
				return
			}
			oauthError(w, 400, "invalid_grant", "Refresh token replay; reconnect.")
			return
		}
		for _, g := range o.state.Grants {
			if subtle.ConstantTimeCompare([]byte(g.RefreshHash), []byte(hash)) == 1 {
				grant = g
				break
			}
		}
		if grant.ID == "" || grant.Client != client.ID || grant.Expires <= now.Unix() || grant.Created+365*86400 <= now.Unix() {
			oauthError(w, 400, "invalid_grant", "Invalid or expired refresh token.")
			return
		}
		// Public clients rotate; confidential clients authenticate each exchange
		// and keep persistent linking compatible with hosted clients.
		if client.Method == "none" {
			usedRefresh = hash
			usedRefreshExpires = grant.Expires
			refresh = atomicfile.RandomHex(32)
			grant.RefreshHash = oauthHash(refresh)
		}
		grant.Expires = min(now.Add(oauthRefreshLifetime).Unix(), grant.Created+365*86400)
	default:
		oauthError(w, 400, "unsupported_grant_type", "Use authorization_code or refresh_token.")
		return
	}
	if _, err := o.grantUser(grant); err != nil {
		oauthError(w, 400, "invalid_grant", "Account authorization changed; reconnect.")
		return
	}
	access := atomicfile.RandomHex(32)
	err := o.mutate(func(s *oauthState) error {
		if _, exists := s.Grants[grant.ID]; !exists && len(s.Grants) >= 100 {
			return errors.New("connection limit")
		}
		if len(s.Access) >= 2000 {
			return errors.New("access token limit")
		}
		if usedRefresh != "" {
			count := 0
			for _, used := range s.UsedRefresh {
				if used.Grant == grant.ID {
					count++
				}
			}
			if len(s.UsedRefresh) >= 50000 || count >= 5000 {
				return errors.New("refresh history limit")
			}
			s.UsedRefresh[usedRefresh] = oauthAccess{Grant: grant.ID, Expires: usedRefreshExpires}
		}
		s.Grants[grant.ID] = grant
		s.Access[oauthHash(access)] = oauthAccess{Grant: grant.ID, Expires: now.Add(oauthAccessLifetime).Unix()}
		return nil
	})
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable", "Could not save authorization; revoke unused connections or reconnect if the token limit was reached.")
		return
	}
	if f.Get("grant_type") == "refresh_token" {
		setOAuthOutcome(w, "token_refreshed", "success")
	} else {
		setOAuthOutcome(w, "token_issued", "success")
	}
	oauthJSON(w, 200, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(oauthAccessLifetime.Seconds()), "refresh_token": refresh, "scope": mcpScope})
}
func (o *mcpOAuth) revoke(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") || r.ParseForm() != nil {
		oauthError(w, 400, "invalid_request", "Form body required.")
		return
	}
	if len(r.PostForm["token"]) != 1 {
		oauthError(w, 400, "invalid_request", "One token is required.")
		return
	}
	hash := oauthHash(r.PostForm.Get("token"))
	o.mu.Lock()
	defer o.mu.Unlock()
	client, err := o.authenticateClient(r)
	if err != nil {
		oauthError(w, 401, "invalid_client", "Client authentication required.")
		return
	}
	found := false
	for _, g := range o.state.Grants {
		if g.RefreshHash == hash && g.Client == client.ID {
			found = true
		}
	}
	if a, ok := o.state.Access[hash]; ok && o.state.Grants[a.Grant].Client == client.ID {
		found = true
	}
	if !found {
		setOAuthOutcome(w, "revoked", "success")
		oauthJSON(w, 200, map[string]any{})
		return
	}
	err = o.mutate(func(s *oauthState) error {
		for id, g := range s.Grants {
			if g.RefreshHash == hash {
				delete(s.Grants, id)
			}
		}
		if a, ok := s.Access[hash]; ok {
			delete(s.Grants, a.Grant)
		}
		for key, a := range s.Access {
			if _, ok := s.Grants[a.Grant]; !ok {
				delete(s.Access, key)
			}
		}
		return nil
	})
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable", "Could not save revocation.")
		return
	}
	setOAuthOutcome(w, "revoked", "success")
	oauthJSON(w, 200, map[string]any{})
}
func (o *mcpOAuth) connections(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && !strings.Contains(r.Header.Get("Accept"), "application/json") {
		if target := o.rt.cfg.Text.OAuthConsent.Page.ConnectionsPath; target != "" {
			w.Header().Set("Location", target)
			w.WriteHeader(http.StatusFound)
			return
		}
		o.oauthPage(w, "Connected apps", "", "", true, o.hosted)
		return
	}
	user, err := o.reader(r)
	if err != nil {
		oauthError(w, 401, "login_required", "Sign in to the reader in this browser first.")
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if r.Method == "POST" {
		var in struct {
			ID string `json:"id"`
		}
		if oauthDecode(r, &in) != nil {
			oauthError(w, 400, "invalid_request", "Connection ID required.")
			return
		}
		g, ok := o.state.Grants[in.ID]
		if !ok || g.User != user.Id {
			http.NotFound(w, r)
			return
		}
		if err := o.mutate(func(s *oauthState) error {
			delete(s.Grants, in.ID)
			for key, a := range s.Access {
				if a.Grant == in.ID {
					delete(s.Access, key)
				}
			}
			return nil
		}); err != nil {
			oauthError(w, 503, "temporarily_unavailable", "Could not save revocation.")
			return
		}
		oauthJSON(w, 200, map[string]bool{"revoked": true})
		return
	}
	list := []map[string]any{}
	for _, g := range o.state.Grants {
		if g.User == user.Id && g.Expires > o.clock().Unix() {
			list = append(list, map[string]any{"id": g.ID, "name": o.state.Clients[g.Client].Name, "created": g.Created, "expires": g.Expires})
		}
	}
	setOAuthOutcome(w, "connections_listed", "success")
	oauthJSON(w, 200, map[string]any{"connections": list})
}
func (o *mcpOAuth) access(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if !strings.HasPrefix(token, "Bearer ") {
		token = ""
	} else {
		token = strings.TrimPrefix(token, "Bearer ")
	}
	o.mu.Lock()
	a, ok := o.state.Access[oauthHash(token)]
	g, has := o.state.Grants[a.Grant]
	o.mu.Unlock()
	var user *core.Record
	var err error
	if ok && has && a.Expires > o.clock().Unix() && g.Expires > o.clock().Unix() {
		user, err = o.grantUser(g)
	}
	if user == nil || err != nil {
		if token == "" {
			setOAuthOutcome(w, "auth_required", "expected_probe")
		} else if ok && !has {
			setOAuthOutcome(w, "grant_revoked", "rejected")
		} else if ok && (a.Expires <= o.clock().Unix() || g.Expires <= o.clock().Unix()) {
			setOAuthOutcome(w, "token_expired", "rejected")
		} else {
			setOAuthOutcome(w, "invalid_token", "rejected")
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp", scope="knowledge"`, o.origin))
		oauthError(w, 401, "invalid_token", "Connect and authorize "+o.rt.cfg.Identity.DisplayName+" first.")
		return
	}
	internalToken, err := user.NewAuthToken()
	if err != nil {
		oauthError(w, 503, "temporarily_unavailable", "Account unavailable.")
		return
	}
	// Never forward the external credential or management headers to knowledge
	// operations. The context retains the public transport trust boundary.
	req := r.Clone(context.WithValue(r.Context(), mcpAuthKey{}, internalToken))
	req.Header = r.Header.Clone()
	req.Header.Del("Authorization")
	req.Header.Del(o.rt.cfg.Identity.LocalKeyHeader)
	o.mcp.ServeHTTP(w, req)
}
