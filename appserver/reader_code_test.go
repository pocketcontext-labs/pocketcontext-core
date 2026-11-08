package appserver

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
)

func TestReaderCodeRequiresAccountAndIsSingleUse(t *testing.T) {
	a := newTestApp(t)
	r, err := apis.NewRouter(a.app)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	l := &localRoutes{p: &Project{rt: testRT, Config: ProjectConfig{Port: 8096}}, codes: codeStore{now: func() time.Time { return now }}}
	l.register(&core.ServeEvent{App: a.app, Router: r})
	a.handler, err = r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	base := "http://127.0.0.1:8096"
	a.request(t, "POST", base+"/api/bundle/reader-code", "", "{}", 401)
	a.request(t, "POST", base+"/api/bundle/reader-code", "invalid-token", "{}", 401)
	data := a.request(t, "POST", base+"/api/bundle/reader-code", a.token, "{}", 200)
	link, err := url.Parse(data["url"].(string))
	if err != nil || link.Path != "/bundle/login" || len(link.Fragment) != 48 {
		t.Fatalf("invalid link: %v", err)
	}
	expires, err := time.Parse(time.RFC3339, data["expires"].(string))
	if err != nil || expires.Sub(now) > 120*time.Second || expires.Sub(now) < 119*time.Second {
		t.Fatal("incorrect expiry")
	}
	body, _ := json.Marshal(map[string]string{"code": link.Fragment})
	result := a.request(t, "POST", base+"/api/bundle/redeem", "", string(body), 200)
	if result["token"] == "" || result["token"] == nil {
		t.Fatal("reader did not receive account authentication")
	}
	a.request(t, "POST", base+"/api/bundle/redeem", "", string(body), 401)
	// The handoff consumes only its code, leaving the original CLI session valid.
	second := a.request(t, "POST", base+"/api/bundle/reader-code", a.token, "{}", 200)
	u, _ := url.Parse(second["url"].(string))
	body, _ = json.Marshal(map[string]string{"code": u.Fragment})
	now = now.Add(120 * time.Second)
	a.request(t, "POST", base+"/api/bundle/redeem", "", string(body), 401)
	// A different Host cannot issue a reader credential, even with a valid token.
	a.request(t, "POST", "http://evil.example/api/bundle/reader-code", a.token, "{}", 403)
}
