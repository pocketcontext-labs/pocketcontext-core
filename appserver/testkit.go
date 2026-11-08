package appserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/plugins/jsvm"
)

// HooksConfig returns the hook and migration loader the server uses, so an
// application's tests can load its real hooks with its real bindings.
func (rt *Runtime) HooksConfig(appDir, typesDir string) jsvm.Config {
	return hooksConfig(rt, appDir, typesDir)
}

// TestServerOptions selects the real request path to compose for a test.
type TestServerOptions struct {
	Domain       string
	Cache        string // private directory for OAuth state; required with MCPHandler
	Hosted       bool
	MCP          bool
	HostedConfig *HostedConfig
	ReaderDir    string       // serve this built reader when not empty
	MCPHandler   http.Handler // enable OAuth-protected MCP when set
}

// TestServer is the server's own request path built around an application's
// bootstrapped app, for that application's tests. It lets an application assert
// its policy against the real local routes and public handler instead of a copy
// of them. It holds no credentials of its own and opens no listener until
// StartTLS is called.
type TestServer struct {
	rt      *Runtime
	project *Project
	local   *localRoutes
	router  http.Handler
	public  http.Handler
}

// NewTestServer composes the local routes, reader and public handler around app.
func (rt *Runtime) NewTestServer(app core.App, opts TestServerOptions) (*TestServer, error) {
	if opts.Domain == "" {
		return nil, errors.New("test server needs a domain")
	}
	p := &Project{rt: rt, Cache: opts.Cache, Config: ProjectConfig{Port: rt.cfg.Identity.DefaultPort, Instance: "synthetic-test"}}
	if opts.Hosted {
		if err := configureHosted(rt, app, opts.Domain, opts.HostedConfig, false); err != nil {
			return nil, err
		}
	}
	router, err := apis.NewRouter(app)
	if err != nil {
		return nil, err
	}
	local := &localRoutes{p: p, hosted: opts.Hosted, mcp: opts.MCP, publicURL: "https://" + opts.Domain}
	event := &core.ServeEvent{App: app, Router: router}
	if err := local.register(event); err != nil {
		return nil, err
	}
	if opts.ReaderDir != "" {
		registerReader(event, opts.ReaderDir)
	}
	if err := app.OnServe().Trigger(event); err != nil {
		return nil, err
	}
	raw, err := router.BuildMux()
	if err != nil {
		return nil, err
	}
	var oauth []*mcpOAuth
	if opts.MCPHandler != nil {
		o, err := newMCPOAuth(app, p, opts.Domain, opts.MCPHandler)
		if err != nil {
			return nil, err
		}
		o.hosted = opts.Hosted
		oauth = append(oauth, o)
	}
	return &TestServer{rt: rt, project: p, local: local, router: raw, public: publicHandlerMode(rt, app, opts.Domain, raw, opts.Hosted, oauth...)}, nil
}

// Project returns the test server's synthetic project.
func (s *TestServer) Project() *Project { return s.project }

// Router returns the unfiltered router, as public requests reach it after the
// public handler has passed them.
func (s *TestServer) Router() http.Handler { return s.router }

// Public returns the public handler that the server exposes.
func (s *TestServer) Public() http.Handler { return s.public }

// MarkPublic records that a request arrived through the public listener, as the
// public handler does before forwarding it.
func (s *TestServer) MarkPublic(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), publicContextKey{}, true))
}

// IssueCode issues a single-use sign-in code for a user of the test server.
func (s *TestServer) IssueCode(user string, ttl time.Duration) (string, error) {
	code, _ := s.local.codes.issue(user, ttl)
	return code, nil
}

// StartTLS serves the public handler on loopback HTTPS with the given
// certificates and returns its address and a stop function.
func (s *TestServer) StartTLS(ctx context.Context, domain string, config *tls.Config) (address string, shutdown func(context.Context) error, err error) {
	failures := make(chan error, 2)
	servers, err := startPublicListeners(ctx, s.public, publicHTTPHandler(domain, func(h http.Handler) http.Handler { return h }), config, "127.0.0.1:0", "127.0.0.1:0", failures)
	if err != nil {
		return "", nil, err
	}
	return servers.tlsListener.Addr().String(), func(stop context.Context) error {
		defer servers.close()
		return servers.shutdown(stop)
	}, nil
}
