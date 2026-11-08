package appserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pocketcontext-labs/pocketcontext-core/mcpobserve"
)

type brokenOAuthLog struct{}

func (brokenOAuthLog) Write([]byte) (int, error) { return 0, errors.New("log sink failed") }

func TestMCPOAuthObservability(t *testing.T) {
	f := newOAuthFixture(t)
	client := f.registration()
	var logs bytes.Buffer
	send := func(method, path, token, body string, want int) map[string]any {
		t.Helper()
		logs.Reset()
		r := httptest.NewRequest(method, "https://knowledge.example.com"+path, strings.NewReader(body))
		r = r.WithContext(mcpobserve.WithWriter(r.Context(), &logs))
		r.Header.Set("X-Request-ID", "attacker-controlled-id")
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("status %d want %d", w.Code, want)
		}
		var e map[string]any
		if err := json.Unmarshal(logs.Bytes(), &e); err != nil {
			t.Fatalf("invalid event: %s: %v", logs.String(), err)
		}
		if e["request_id"] != w.Header().Get("X-Request-ID") || e["request_id"] == "attacker-controlled-id" {
			t.Fatal("request ID was not generated/correlated")
		}
		for _, secret := range []string{"secret-state", "private-callback", "secret-code", "attacker-controlled-id", f.a.token} {
			if strings.Contains(logs.String(), secret) {
				t.Fatalf("sensitive value logged: %s", secret)
			}
		}
		return e
	}
	q := f.authorization(client, strings.Repeat("v", 64))
	q.Set("state", "secret-state")
	e := send("GET", "/oauth/authorize?"+q.Encode(), "", "", 200)
	if e["reason"] != "consent_required" || e["event"] != "oauth_complete" {
		t.Fatal(e)
	}
	q.Set("resource", "https://private-callback.example.com/mcp")
	e = send("GET", "/oauth/authorize?"+q.Encode(), "", "", 400)
	if e["reason"] != "resource_mismatch" {
		t.Fatal(e)
	}
	q.Del("resource")
	e = send("POST", "/oauth/authorize?"+q.Encode(), f.a.token, `{"approve":false}`, 200)
	if e["reason"] != "consent_denied" || e["outcome"] != "denied" {
		t.Fatal(e)
	}
	e = send("POST", "/oauth/authorize?"+q.Encode(), f.a.token, `{"approve":true}`, 200)
	if e["reason"] != "consent_approved" {
		t.Fatal(e)
	}
	e = send("POST", "/mcp", "", "{\"secret-code\":true}", 401)
	if e["reason"] != "auth_required" || e["outcome"] != "expected_probe" {
		t.Fatal(e)
	}
	e = send("POST", "/mcp", "secret-code", "{}", 401)
	if e["reason"] != "invalid_token" {
		t.Fatal(e)
	}
}

func TestMCPOAuthBrokenLogPreservesResponse(t *testing.T) {
	f := newOAuthFixture(t)
	r := httptest.NewRequest("GET", "https://knowledge.example.com/.well-known/oauth-authorization-server", nil)
	r = r.WithContext(mcpobserve.WithWriter(r.Context(), brokenOAuthLog{}))
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "authorization_endpoint") {
		t.Fatal("log error changed discovery response")
	}
}

func TestMCPOAuthTokenObservability(t *testing.T) {
	f := newOAuthFixture(t)
	client := f.registration()
	verifier := strings.Repeat("v", 64)
	code := f.code(client, verifier)
	var logs bytes.Buffer
	original := f.h
	f.h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		original.ServeHTTP(w, r.WithContext(mcpobserve.WithWriter(r.Context(), &logs)))
	})
	check := func(reason string, secrets ...string) {
		t.Helper()
		var e map[string]any
		if err := json.Unmarshal(logs.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		if e["reason"] != reason {
			t.Fatalf("got %v want %s", e, reason)
		}
		for _, s := range secrets {
			if s != "" && strings.Contains(logs.String(), s) {
				t.Fatal("credential logged")
			}
		}
		logs.Reset()
	}
	result := f.exchange(client, code, verifier, 200)
	check("token_issued", code, verifier, client, result["access_token"].(string), result["refresh_token"].(string))
	refreshed := f.refresh(client, result["refresh_token"].(string), 200)
	check("token_refreshed", result["refresh_token"].(string), refreshed["access_token"].(string))
	f.request("POST", "/oauth/token", "", url.Values{"client_id": {client}, "grant_type": {"refresh_token"}, "refresh_token": {"secret-invalid-refresh"}}.Encode(), "application/x-www-form-urlencoded", 400)
	check("invalid_refresh", "secret-invalid-refresh")
	code = f.code(client, verifier)
	check("consent_approved", code)
	f.o.path += "/missing/state.json"
	f.exchange(client, code, verifier, 503)
	check("persistence_failure", code, verifier)
}

type failedOAuthResponse struct {
	header  http.Header
	status  int
	failure error
}

func (w *failedOAuthResponse) Header() http.Header       { return w.header }
func (w *failedOAuthResponse) WriteHeader(status int)    { w.status = status }
func (w *failedOAuthResponse) Write([]byte) (int, error) { return 0, w.failure }

func TestMCPOAuthResponseDeliveryObservability(t *testing.T) {
	var logs bytes.Buffer
	o := &mcpOAuth{rt: testRT, origin: "https://knowledge.example.com"}
	r := httptest.NewRequest("POST", "https://knowledge.example.com/oauth/token", nil)
	r = r.WithContext(mcpobserve.WithWriter(r.Context(), &logs))
	failure := errors.New("private socket error message")
	w := &failedOAuthResponse{header: make(http.Header), failure: failure}
	o.observe(w, r, func(out http.ResponseWriter, r *http.Request) {
		setOAuthOutcome(out, "token_issued", "success")
		out.Header().Set("Content-Type", "application/json")
		out.WriteHeader(200)
		n, err := out.Write([]byte("private token response"))
		if n != 0 || err != failure {
			t.Fatal("wrapper changed write result")
		}
	})
	if w.status != 200 || w.header.Get("Content-Type") != "application/json" || w.header.Get("X-Request-ID") == "" {
		t.Fatal("wrapper changed status or headers")
	}
	var event map[string]any
	if err := json.Unmarshal(logs.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event["outcome"] != "transport_error" || event["reason"] != "response_write_failed" || event["http_status"] != float64(200) {
		t.Fatal(event)
	}
	if strings.Contains(logs.String(), "private") {
		t.Fatal("write failure leaked body or error")
	}
	for _, timeout := range []bool{false, true} {
		logs.Reset()
		ctx, cancel := context.WithCancel(context.Background())
		if timeout {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		} else {
			cancel()
		}
		defer cancel()
		r = httptest.NewRequest("POST", "https://knowledge.example.com/mcp", nil).WithContext(mcpobserve.WithWriter(ctx, &logs))
		recorder := httptest.NewRecorder()
		o.observe(recorder, r, func(out http.ResponseWriter, r *http.Request) { out.WriteHeader(202) })
		if err := json.Unmarshal(logs.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		want := "cancelled"
		if timeout {
			want = "timeout"
		}
		if recorder.Code != 202 || event["outcome"] != want {
			t.Fatal(event)
		}
	}
}
