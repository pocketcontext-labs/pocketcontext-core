package appserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/ui"
)

// listenerSet owns both listeners. One http.Server serves the same router and
// authentication hooks on both, and shutdown drains all accepted connections.
type listenerSet struct {
	mu      sync.Mutex
	p       *Project
	server  *http.Server
	socket  net.Listener
	tcp     net.Listener
	closing bool
	errors  chan error
}

func (s *listenerSet) enableTCP() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return errors.New("server is stopping")
	}
	if s.tcp != nil {
		return nil
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.p.Config.Port))
	if err != nil {
		return fmt.Errorf("reader port %d is unavailable; the headless server remains running: %w", s.p.Config.Port, err)
	}
	s.tcp = ln
	go func() { s.errors <- s.server.Serve(ln) }()
	return nil
}
func (s *listenerSet) state() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := ""
	if s.socket != nil {
		path = s.socket.Addr().String()
	}
	return path, s.tcp != nil
}

// serveHTTP preserves the app's migration and OnServe lifecycle without a
// vendored serving patch. The optional public TLS listeners wrap this handler
// with their own route and transport boundary; the account installer is absent.
func serveHTTP(app core.App, p *Project, opts ServeOptions, stop <-chan struct{}, local *localRoutes) error {
	return serveHTTPContext(context.Background(), app, p, opts, stop, local)
}

func serveHTTPContext(parent context.Context, app core.App, p *Project, opts ServeOptions, stop <-chan struct{}, local *localRoutes) error {
	if err := app.RunAllMigrations(); err != nil {
		return err
	}
	router, err := apis.NewRouter(app)
	if err != nil {
		return err
	}
	origins := []string{p.URL(), fmt.Sprintf("http://localhost:%d", p.Config.Port)}
	if opts.HTTPSDomain != "" {
		local.publicURL = "https://" + opts.HTTPSDomain
		origins = append(origins, local.publicURL)
	}
	router.Bind(apis.CORS(apis.CORSConfig{
		AllowOrigins: origins,
		AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
	}))
	// Preserve the embedded dashboard route and its security/cache headers.
	if ui.DistDirFS != nil {
		router.GET("/_/{path...}", apis.Static(ui.DistDirFS, false)).BindFunc(func(e *core.RequestEvent) error {
			if !e.App.IsDev() && e.Request.PathValue(apis.StaticWildcardParam) != "" && e.Response.Header().Get("Cache-Control") == "" {
				e.Response.Header().Set("Cache-Control", "max-age=1209600, stale-while-revalidate=86400")
			}
			if e.Response.Header().Get("Content-Security-Policy") == "" {
				e.Response.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' http://127.0.0.1:* https://tile.openstreetmap.org data: blob:; connect-src 'self' http://127.0.0.1:* https://nominatim.openstreetmap.org; script-src 'self' http://127.0.0.1:*; frame-ancestors 'none'")
			}
			return e.Next()
		}).Bind(apis.Gzip())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", p.Config.Port),
		ReadTimeout: 5 * time.Minute, WriteTimeout: 5 * time.Minute, ReadHeaderTimeout: time.Minute,
		BaseContext: func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, socketContextKey{}, c.LocalAddr().Network() == "unix")
		},
	}
	listeners := &listenerSet{p: p, server: server, errors: make(chan error, 4)}
	local.listeners = listeners
	event := &core.ServeEvent{App: app, Router: router, Server: server}
	err = app.OnServe().Trigger(event, func(e *core.ServeEvent) error {
		handler, err := e.Router.BuildMux()
		if err != nil {
			return err
		}
		server = e.Server
		listeners.server = server
		server.Handler = handler
		return nil
	})
	if err != nil {
		return err
	}
	if server.Handler == nil {
		return errors.New("OnServe did not build the HTTP handler")
	}
	if !opts.TCPOnly {
		ln, err := listenSocket(p)
		if err != nil {
			return err
		}
		listeners.socket = ln
		defer ln.Close()
		go func() { listeners.errors <- server.Serve(ln) }()
	}
	if !opts.Headless || opts.TCPOnly || (opts.UIDev != "" && !opts.PublicUIDev) {
		if err := listeners.enableTCP(); err != nil {
			server.Close()
			return err
		}
	}
	var public *publicServers
	if opts.HTTPSDomain != "" {
		if opts.Hosted {
			public, err = startHostedHTTP(ctx, app, p, opts, server.Handler, listeners.errors)
		} else {
			public, err = startPublicHTTPS(ctx, app, p, opts, server.Handler, listeners.errors)
		}
		if err != nil {
			_ = server.Close()
			return err
		}
		defer public.close()
	}
	app.OnTerminate().BindFunc(func(e *core.TerminateEvent) error {
		cancel()
		_ = server.Close()
		if public != nil {
			public.close()
		}
		return e.Next()
	})
	serveErr := runForegroundService(parent, stop, listeners.errors, opts.Service)
	listeners.mu.Lock()
	listeners.closing = true
	listeners.mu.Unlock()
	cancel() // cancel SSE before waiting for graceful shutdown
	shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	if err := server.Shutdown(shutdown); err != nil {
		_ = server.Close()
		if serveErr == nil {
			serveErr = err
		}
	}
	if public != nil {
		serveErr = errors.Join(serveErr, public.shutdown(shutdown))
	}
	return serveErr
}

// runForegroundService owns the companion service for exactly one HTTP server
// lifetime. It returns only after the companion has released its resources, so
// callers can then drain HTTP and write the final database snapshot.
func runForegroundService(parent context.Context, stop <-chan struct{}, serverErrors <-chan error, service func(context.Context) error) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var serviceDone chan error
	if service != nil && ctx.Err() == nil {
		serviceDone = make(chan error, 1)
		go func() { serviceDone <- service(ctx) }()
	}
	var serverErr, serviceErr error
	select {
	case <-parent.Done():
	case <-stop:
	case serverErr = <-serverErrors:
	case serviceErr = <-serviceDone:
		serviceDone = nil
		if ctx.Err() == nil {
			if serviceErr == nil {
				serviceErr = errors.New("foreground service stopped unexpectedly")
			}
		} else if onlyServiceCancellation(serviceErr) {
			serviceErr = nil
		}
	}
	if serverErr == http.ErrServerClosed {
		serverErr = nil
	}
	cancel()
	if serviceDone != nil {
		serviceErr = <-serviceDone
		if onlyServiceCancellation(serviceErr) {
			serviceErr = nil
		}
	}
	return errors.Join(serverErr, serviceErr)
}

// onlyServiceCancellation keeps a real cleanup error when it was joined with
// cancellation; shutting down a companion must not hide resource-close errors.
func onlyServiceCancellation(err error) bool {
	if err == context.Canceled {
		return true
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		causes := wrapped.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !onlyServiceCancellation(cause) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return onlyServiceCancellation(wrapped.Unwrap())
	default:
		return false
	}
}
