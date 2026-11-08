// Package routepolicytest pins application public route policies. Core owns the
// frozen negative set; each application supplies its golden allow table for the
// routes it actually exposes.
package routepolicytest

import "testing"

// Case is one method and path with its required decision.
type Case struct {
	Method string
	Path   string
	Allow  bool
}

// CommonDenied is the frozen negative set every application policy must refuse.
// Applications add their own entries; none may be removed.
func CommonDenied() []Case {
	denied := []struct{ method, path string }{
		{"GET", "/_/"}, {"GET", "/_"},
		{"GET", "/api/bundle/instance"}, {"POST", "/api/bundle/token"},
		{"POST", "/api/bundle/stop"}, {"POST", "/api/bundle/account"},
		{"POST", "/api/bundle/login-code"}, {"POST", "/api/bundle/reader-code"},
		{"POST", "/api/bundle/flush"}, {"POST", "/api/bundle/name"},
		{"POST", "/api/bundle/enable-tcp"},
		{"GET", "/api/collections/users/records"}, {"POST", "/api/collections/users/records"},
		{"GET", "/api/collections"},
		{"POST", "/api/batch"}, {"GET", "/api/settings"},
		{"GET", "/api/context/maintenance"}, {"PUT", "/api/context/maintenance"},
	}
	cases := make([]Case, 0, len(denied))
	for _, d := range denied {
		cases = append(cases, Case{d.method, d.path, false})
	}
	return cases
}

// Check asserts each case against the application's public route.
func Check(t *testing.T, route func(method, path string) bool, cases []Case) {
	t.Helper()
	for _, c := range cases {
		if got := route(c.Method, c.Path); got != c.Allow {
			t.Errorf("%s %s: allowed=%v, want %v", c.Method, c.Path, got, c.Allow)
		}
	}
}
