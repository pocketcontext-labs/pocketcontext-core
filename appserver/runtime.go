package appserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"github.com/dop251/goja"

	"github.com/pocketcontext-labs/pocketcontext-core/appidentity"
	"github.com/pocketcontext-labs/pocketcontext-core/maintenance"
	"github.com/pocketcontext-labs/pocketcontext-core/mcpobserve"
	"github.com/pocketcontext-labs/pocketcontext-core/profiles"
)

// Config holds everything product-specific that a Runtime needs. It has no
// defaults: New refuses a Config whose identity, assets or policies are missing.
type Config struct {
	Identity appidentity.Identity
	Version  string // the application's release; compared across server and clients
	Commit   string
	Assets   fs.FS // root holding pb_hooks/, pb_migrations/, ui/dist/ and optional server.json
	Policy   Policy
	Hooks    Hooks
	Text     Text
}

// PublicRouteFactory is called once when a public handler is built. The returned
// function is the complete public route allowlist for non-OAuth, non-OTP requests.
// It runs after core's fixed checks (exact Host/Origin, /up, path canonicalization).
type PublicRouteFactory func(app core.App) func(method, path string) bool

// Policy holds the application's public routes, maintenance reads and pricing.
type Policy struct {
	PublicRoute       PublicRouteFactory           // required; the only public allowlist
	Maintenance       maintenance.Policy           // required; explicit empty sets are allowed
	Observe           mcpobserve.Policy            // required; explicit empty lists are allowed
	HostedRequestCost func(*core.RequestEvent) int // nil means every request costs 1
	AllowPublicUIDev  bool                         // only an application that uses it sets this
}

// Hooks are the extension points at the exact places applications diverge.
// A nil hook does nothing.
type Hooks struct {
	AfterDatabaseCheck func(p *Project, store *Store) error
	PreRegister        func(app core.App, p *Project, opts ServeOptions) error // before maintenance.Register
	Register           func(app core.App, ctx RegisterContext) error           // after jsvm.MustRegister
	OnServeStart       func(e *core.ServeEvent, p *Project) error              // before local routes are registered
	Routes             func(e *core.ServeEvent) error                          // inside local route registration
	Background         func(ctx context.Context, app core.App)                 // after a successful OnServe; cancelled and awaited before the app closes
	OnHostedRestore    func(app core.App) error                                // first in restoring a hosted instance
	Bindings           func(vm *goja.Runtime) map[string]any                   // merged into HookGlobal; cannot replace sha256
}

// RegisterContext is the state available to Hooks.Register.
type RegisterContext struct {
	AppDir   string // unpacked assets, for server.json
	LivePath string // private working database
	Project  *Project
}

// Text is product copy shown to people. New requires every field.
type Text struct {
	AccountName        string // the account's name at creation
	LegacyRecreateHint string // final sentence of the earlier-release error
	OAuthResourceName  string
	OAuthConsent       OAuthConsentText
	BudgetExhausted    string // the 429 message
	OTPSubject         string
	OTPSenderName      string
}

// OAuthConsentText is trusted static copy from the application, used as template
// source. {{.Name}} in RequestHTML is the client-supplied name and is escaped.
type OAuthConsentText struct {
	ConnectionsHTML string
	RequestHTML     string
}

// Runtime is the validated configuration for one process. Project values carry
// a pointer to it; there is no package-level state.
type Runtime struct {
	cfg           Config
	oauthTemplate *template.Template
}

// New validates cfg and returns a Runtime. Identity, assets, version, policy and
// text are all required: nothing is defaulted.
func New(cfg Config) (*Runtime, error) {
	if err := cfg.Identity.Validate(); err != nil {
		return nil, err
	}
	if cfg.Version == "" {
		return nil, errors.New("appserver: Version is required")
	}
	if cfg.Assets == nil {
		return nil, errors.New("appserver: Assets is required")
	}
	if cfg.Policy.PublicRoute == nil {
		return nil, errors.New("appserver: Policy.PublicRoute is required")
	}
	if cfg.Policy.Maintenance.ReadPosts == nil || cfg.Policy.Maintenance.ReadGets == nil {
		return nil, errors.New("appserver: Policy.Maintenance is required")
	}
	if cfg.Policy.Observe.Tools == nil || cfg.Policy.Observe.APIRoutes == nil {
		return nil, errors.New("appserver: Policy.Observe is required")
	}
	for name, value := range map[string]string{
		"AccountName": cfg.Text.AccountName, "LegacyRecreateHint": cfg.Text.LegacyRecreateHint,
		"OAuthResourceName": cfg.Text.OAuthResourceName, "BudgetExhausted": cfg.Text.BudgetExhausted,
		"OTPSubject": cfg.Text.OTPSubject, "OTPSenderName": cfg.Text.OTPSenderName,
		"OAuthConsent.ConnectionsHTML": cfg.Text.OAuthConsent.ConnectionsHTML,
		"OAuthConsent.RequestHTML":     cfg.Text.OAuthConsent.RequestHTML,
	} {
		if value == "" {
			return nil, fmt.Errorf("appserver: Text.%s is required", name)
		}
	}
	if cfg.Hooks.Bindings != nil {
		if _, collides := cfg.Hooks.Bindings(goja.New())["sha256"]; collides {
			return nil, errors.New("appserver: Hooks.Bindings must not define sha256")
		}
	}
	tmpl, err := newOAuthTemplate(cfg.Text.OAuthConsent)
	if err != nil {
		return nil, fmt.Errorf("appserver: Text.OAuthConsent: %w", err)
	}
	return &Runtime{cfg: cfg, oauthTemplate: tmpl}, nil
}

// Config returns a copy of the validated configuration.
func (rt *Runtime) Config() Config { return rt.cfg }

// Profiles returns the private profile registry for this application.
func (rt *Runtime) Profiles() *profiles.Store { return profiles.New(rt.cfg.Identity.RegistryNamespace) }

// jsString encodes a value for use as a JavaScript string literal.
func jsString(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err) // a string always marshals
	}
	return string(encoded)
}
