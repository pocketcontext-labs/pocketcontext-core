package appserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"ganigeorgiev.com/pocketbase/dbx"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
	_ "ganigeorgiev.com/pocketbase/pocketbase/migrations" // system migrations
	"ganigeorgiev.com/pocketbase/pocketbase/plugins/jsvm"

	"github.com/pocketcontext-labs/pocketcontext-core/atomicfile"
	"github.com/pocketcontext-labs/pocketcontext-core/database"
	"github.com/pocketcontext-labs/pocketcontext-core/maintenance"
)

// ServeOptions control one foreground server run.
type ServeOptions struct {
	TakeOver       bool
	UIDev          string
	PublicUIDev    bool
	DevHTTPAddress string
	Headless       bool
	TCPOnly        bool
	Port           int
	HTTPSDomain    string
	ACMEEmail      string
	MCP            bool
	Hosted         bool
	HostedInit     bool
	HostedRestore  bool
	HostedConfig   *HostedConfig
	// MCPHandler builds the protocol adapter around the ordinary authenticated API.
	MCPHandler func(http.Handler) http.Handler
	// Service starts after the HTTP listeners are ready. Its failure stops the
	// server; shutdown cancels and waits for it before draining HTTP and flushing.
	Service func(context.Context) error
}

// unpack writes the embedded application files to a content-addressed cache
// directory and returns it. Existing complete directories are reused.
func unpack(p *Project) (string, error) {
	type entry struct {
		name string
		data []byte
	}
	var entries []entry
	h := sha256.New()
	assets := p.rt.cfg.Assets
	err := fs.WalkDir(assets, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(assets, name)
		if err != nil {
			return err
		}
		entries = append(entries, entry{name, data})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	for _, e := range entries {
		fmt.Fprintf(h, "%s\x00%d\x00", e.name, len(e.data))
		h.Write(e.data)
	}
	root := filepath.Join(filepath.Dir(p.Cache), "app")
	dir := filepath.Join(root, hex.EncodeToString(h.Sum(nil))[:16])
	if _, err := os.Stat(filepath.Join(dir, ".complete")); err == nil {
		return dir, nil
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	temp, err := os.MkdirTemp(root, ".unpack-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temp)
	for _, e := range entries {
		path := filepath.Join(temp, filepath.FromSlash(e.name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return "", err
		}
		if err := os.WriteFile(path, e.data, 0600); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(temp, ".complete"), nil, 0600); err != nil {
		return "", err
	}
	if err := os.Rename(temp, dir); err != nil {
		if _, statErr := os.Stat(filepath.Join(dir, ".complete")); statErr == nil {
			return dir, nil // another process unpacked the same version
		}
		return "", err
	}
	return dir, nil
}

// Serve runs the server in the foreground until interrupted or stopped.
func Serve(p *Project, opts ServeOptions) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return ServeContext(ctx, p, opts)
}

// ServeContext runs one owned foreground server. Cancellation follows the same
// graceful drain and snapshot write-back path as an authenticated stop request.
func ServeContext(parent context.Context, p *Project, opts ServeOptions) (resultErr error) {
	if p != nil && !opts.Hosted {
		if err := CheckLocalProject(p); err != nil {
			return err
		}
	}
	if p != nil && !p.rt.cfg.Policy.AllowPublicUIDev && (opts.PublicUIDev || opts.DevHTTPAddress != "") {
		return errors.New("public UI development is not enabled for this application")
	}
	if err := validatePublicUIDev(opts); err != nil {
		return err
	}
	if opts.HostedRestore && (!opts.Hosted || opts.HostedInit) {
		return errors.New("--hosted-restore requires --hosted and excludes --hosted-init")
	}
	if opts.HostedInit && !opts.Hosted {
		return errors.New("--hosted-init requires --hosted")
	}
	if opts.Hosted {
		if !p.rt.cfg.Policy.Hosted.configured() {
			return errNoHostedMode
		}
		if !opts.MCP || opts.HTTPSDomain == "" || !opts.Headless || opts.Service != nil || opts.ACMEEmail != "" {
			return errors.New("hosted mode requires --headless --domain --mcp and excludes tunnels and ACME")
		}
		if opts.HostedConfig == nil {
			var err error
			opts.HostedConfig, err = p.rt.HostedConfigFromEnv()
			if err != nil {
				return err
			}
		}
		_, err := os.Stat(p.DB)
		if opts.HostedInit && !errors.Is(err, os.ErrNotExist) {
			return errors.New("hosted initialization requires a new project; existing database will not be overwritten")
		}
		if !opts.HostedInit && err != nil {
			return errors.New("hosted database is missing or inaccessible; initialize a new instance explicitly or restore its backup")
		}
	}
	if opts.MCP && (opts.HTTPSDomain == "" || opts.MCPHandler == nil) {
		return errors.New("MCP requires --domain and the MCP protocol adapter")
	}
	if opts.HTTPSDomain != "" {
		if err := ValidateHTTPSDomain(opts.HTTPSDomain); err != nil {
			return err
		}
		if !opts.Headless || (opts.UIDev != "" && !opts.PublicUIDev) || opts.TCPOnly || opts.Port != 0 {
			return errors.New("public HTTPS requires headless mode without TCP-only or port overrides; UI development requires --public-ui-dev")
		}
	}

	if err := parent.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(p.Cache, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(p.Cache, "server.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lockFile(lock); err != nil {
		return fmt.Errorf("a %s server for this database is already running on this computer", p.rt.cfg.Identity.DisplayName)
	}
	if opts.TCPOnly {
		if err := removeStaleSocket(p); err != nil {
			return err
		}
	}
	if _, err := os.Stat(p.ConfigPath); errors.Is(err, os.ErrNotExist) {
		if err := p.SaveConfig(); err != nil {
			return err
		}
	}
	if err := p.EnsureInstance(); err != nil {
		return err
	}
	if opts.Hosted {
		p.LeaseHost = "hosted-" + p.Config.Instance
	}
	if err := claimLease(p, opts.TakeOver); err != nil {
		return err
	}
	defer releaseLease(p)
	if opts.Port != 0 {
		if opts.Port < 1024 || opts.Port > 65535 {
			return errors.New("port must be 1024-65535")
		}
		p.Config.Port = opts.Port
	}
	var devUI *uiDevProxy
	if opts.UIDev != "" {
		var err error
		devUI, err = newUIDevProxy(opts.UIDev, p)
		if err == nil && opts.PublicUIDev {
			devUI.allowPublic(opts.HTTPSDomain)
		}
		if err != nil {
			return err
		}
	}
	if opts.Port != 0 {
		if err := p.SaveConfig(); err != nil {
			return err
		}
	}
	store := &Store{p: p}
	if err := store.Open(); err != nil {
		return err
	}
	// Refuse a database from an earlier release before PocketBase opens it, so
	// no migration runs and nothing is written back.
	if _, err := os.Stat(store.livePath()); err == nil {
		if err := checkDatabase(p.rt, store.livePath(), p.DB); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	hooks := p.rt.cfg.Hooks
	if hooks.AfterDatabaseCheck != nil {
		if err := hooks.AfterDatabaseCheck(p, store); err != nil {
			return err
		}
	}
	appDir, err := unpack(p)
	if err != nil {
		return fmt.Errorf("unpacking application files: %w", err)
	}
	// Hooks resolve their embedded application files from this directory.
	if err := os.Chdir(appDir); err != nil {
		return err
	}
	key := atomicfile.RandomHex(32)
	if err := atomicfile.WriteAtomic(p.KeyFile(), []byte(key), 0600); err != nil {
		return err
	}
	defer os.Remove(p.KeyFile())

	live := p.LiveDir()
	controller, err := database.NewController(live)
	if err != nil {
		return fmt.Errorf("maintenance state: %w", err)
	}
	app := core.NewBaseApp(core.BaseAppConfig{
		// storage/ is created beside the database; the databases live in the cache.
		DataDir:      p.Dir,
		QueryTimeout: core.DefaultQueryTimeout,
		DBConnect: func(path string) (*dbx.DB, error) {
			return controller.Connect(filepath.Join(live, filepath.Base(path)))
		},
	})
	// Plugin resources register their own termination hooks; clearing PocketBase
	// alone does not close those independent resources.
	// Cover bootstrap/serve failures too, and run the hooks at most once.
	appClosed := false
	closeApp := func() error {
		appClosed = true
		terminateErr := app.OnTerminate().Trigger(&core.TerminateEvent{App: app})
		return errors.Join(terminateErr, app.ResetBootstrapState())
	}
	defer func() {
		if !appClosed {
			resultErr = errors.Join(resultErr, closeApp())
		}
	}()
	// PocketBase watches DataDir/.notify to coordinate processes that share one
	// pb_data. Here DataDir is the synced folder and each computer has its own
	// working copy, so the watcher would only leak events between computers.
	const notifyWatcher = "__pbNotifyWatcherSystemHook__"
	app.OnBootstrap().Unbind(notifyWatcher)
	app.OnTerminate().Unbind(notifyWatcher)
	app.OnModelAfterCreateSuccess().Unbind(notifyWatcher)
	app.OnModelAfterUpdateSuccess().Unbind(notifyWatcher)
	app.OnCollectionAfterCreateSuccess().Unbind(notifyWatcher)
	app.OnCollectionAfterUpdateSuccess().Unbind(notifyWatcher)
	app.OnCollectionAfterDeleteSuccess().Unbind(notifyWatcher)
	if hooks.PreRegister != nil {
		if err := hooks.PreRegister(app, p, opts); err != nil {
			return err
		}
	}
	maintenance.Register(app, controller, p.rt.cfg.Policy.Maintenance)
	jsvm.MustRegister(app, hooksConfig(p.rt, appDir, p.Cache))
	if hooks.Register != nil {
		if err := hooks.Register(app, RegisterContext{AppDir: appDir, LivePath: store.livePath(), Project: p}); err != nil {
			return err
		}
	}

	changed := func(e *core.ModelEvent) error {
		if _, isLog := e.Model.(*core.Log); !isLog {
			store.Changed()
		}
		return e.Next()
	}
	app.OnModelAfterCreateSuccess().BindFunc(changed)
	app.OnModelAfterUpdateSuccess().BindFunc(changed)
	app.OnModelAfterDeleteSuccess().BindFunc(changed)

	before, err := databaseMigrationCount(store.livePath())
	if err != nil {
		return fmt.Errorf("read migration state before bootstrap: %w", err)
	}
	if err := app.Bootstrap(); err != nil {
		return err
	}
	if store.state.Base == nil {
		store.Changed() // a new database must reach the synced folder
	}
	migrations := func() int {
		var n int
		_ = app.DB().NewQuery("SELECT count(*) FROM _migrations").Row(&n)
		return n
	}

	// The product background task starts only after a successful OnServe and is
	// always stopped and awaited before the app closes.
	backgroundCtx, stopProductBackground := context.WithCancel(parent)
	productBackgroundDone := make(chan struct{})
	productBackgroundStarted := false
	defer func() {
		stopProductBackground()
		if productBackgroundStarted {
			<-productBackgroundDone
		}
	}()
	stop := make(chan struct{}, 1)
	local := &localRoutes{p: p, store: store, key: key, stop: stop, uiDev: opts.UIDev, mcp: opts.MCP, hosted: opts.Hosted}
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		e.InstallerFunc = nil // accounts are created by the application's init command
		if migrations() != before {
			store.Changed()
		}
		if !opts.Hosted {
			records, err := app.FindRecordsByFilter("users", "", "", 1, 0)
			if err != nil {
				return err
			}
			if len(records) > 0 && records[0].Email() != p.rt.cfg.Identity.LocalAccountEmail {
				return errors.New("this hosted project requires explicit --hosted serving; local and tunnel modes are unavailable")
			}
		}
		if opts.Hosted {
			if err := configureHosted(p.rt, app, opts.HTTPSDomain, opts.HostedConfig, opts.HostedInit); err != nil {
				return err
			}
			if err := atomicfile.WriteAtomic(filepath.Join(p.Cache, "hosted.json"), []byte(`{"version":1}`), 0600); err != nil {
				return err
			}
			if opts.HostedRestore {
				if err := invalidateHostedRestore(app, p); err != nil {
					return err
				}
			}
		}
		if hooks.OnServeStart != nil {
			if err := hooks.OnServeStart(e, p); err != nil {
				return err
			}
		}
		if err := local.register(e); err != nil {
			return err
		}
		if devUI != nil {
			devUI.register(e)
		} else {
			registerReader(e, filepath.Join(appDir, "ui", "dist"))
		}
		if err := e.Next(); err != nil {
			return err
		}
		if hooks.Background != nil {
			productBackgroundStarted = true
			go func() { defer close(productBackgroundDone); hooks.Background(backgroundCtx, app) }()
		}
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backgroundDone := make(chan struct{})
	go func() {
		defer close(backgroundDone)
		flush := time.NewTicker(5 * time.Second)
		heartbeat := time.NewTicker(30 * time.Second)
		defer flush.Stop()
		defer heartbeat.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-flush.C:
				if err := store.Flush(3 * time.Second); err != nil {
					log.Printf("write-back: %v", err)
				}
			case <-heartbeat.C:
				_ = writeLease(p)
			}
		}
	}()
	log.Printf("%s %s serving %s", p.rt.cfg.Identity.Command, p.rt.cfg.Version, p.DB)
	serveErr := serveHTTPContext(parent, app, p, opts, stop, local)
	cancel()
	stopProductBackground()
	if productBackgroundStarted {
		<-productBackgroundDone
		productBackgroundStarted = false
	}
	<-backgroundDone
	closeErr := closeApp()
	if err := store.Close(); err != nil {
		log.Printf("final write-back failed: %v", err)
		return errors.Join(serveErr, closeErr, err)
	}
	if err := errors.Join(serveErr, closeErr); err != nil {
		return err
	}
	log.Printf("stopped; %s is up to date", p.DB)
	return nil
}
