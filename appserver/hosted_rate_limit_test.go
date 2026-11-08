package appserver

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHostedRateLimitAuthenticatedAndInvalidToken(t *testing.T) {
	a, h := hostedTestApp(t)
	token, err := a.user.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	request := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://knowledge.example.com/api/fixture/read", strings.NewReader(`{}`))
		r.RemoteAddr = "192.0.2.50:1000"
		r.Header.Set("Authorization", token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	// Empty payloads deliberately fail validation; valid authentication, rather
	// than successful writes or merely having an Authorization header, sets budget.
	for i := 0; i < 40; i++ {
		if w := request(token); w.Code != 400 {
			t.Fatalf("authenticated request %d: %s", i, w.Body)
		}
	}
	if w := request("invalid-token"); w.Code != 401 {
		t.Fatalf("invalid token admitted: %d", w.Code)
	}
	var last *httptest.ResponseRecorder
	for i := 0; i < 301; i++ {
		last = request("")
	}
	if last.Code != 429 {
		t.Fatalf("anonymous request got %d: %s", last.Code, last.Body)
	}
	assertRateMetadata(t, last, "pocketbase:/api/", 300, 10)
}

func assertRateMetadata(t *testing.T, w *httptest.ResponseRecorder, label string, capacity, retry int) {
	t.Helper()
	var body struct {
		Data struct {
			Rate rateLimitInfo `json:"rate_limit"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Rate.Limit != label || body.Data.Rate.Capacity != capacity || body.Data.Rate.RetryAfterSeconds != retry {
		t.Fatalf("metadata: %+v, body %s", body.Data.Rate, w.Body)
	}
	for _, header := range []string{"Retry-After", "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset"} {
		if w.Header().Get(header) == "" {
			t.Errorf("missing %s", header)
		}
	}
}

func TestPublicAuthRejectionMetadata(t *testing.T) {
	l := &publicAuthLimiter{}
	for i := 0; i < 10; i++ {
		if !l.allow("192.0.2.1:1") {
			t.Fatal("early rejection")
		}
	}
	if l.allow("192.0.2.1:2") {
		t.Fatal("port changed budget")
	}
	info := l.rejection("192.0.2.1:3", "public_auth")
	if info.RetryAfterSeconds != 6 || info.Capacity != 10 || info.Remaining != 0 {
		t.Fatalf("%+v", info)
	}
}
