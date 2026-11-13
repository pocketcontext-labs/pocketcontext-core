package appserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/url"
	"strings"

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

// Policy holds the application's public routes, maintenance reads, wire values
// and limits.
type Policy struct {
	PublicRoute PublicRouteFactory // required; the only public allowlist
	Maintenance maintenance.Policy // required; explicit empty sets are allowed
	Observe     mcpobserve.Policy  // required; explicit empty lists are allowed
	// OAuthScope is the one scope of the application's MCP endpoint. Connected
	// clients store it, so changing it later disconnects them.
	OAuthScope string // required
	// PublicBodyLimit is the largest request body, in bytes, a public request
	// outside sign-in and OAuth may carry.
	PublicBodyLimit   int64                        // required
	Legacy            LegacySchema                 // required; explicit empty lists are allowed
	Hosted            HostedBudget                 // zero means the application has no hosted mode
	HostedRequestCost func(*core.RequestEvent) int // nil means every request costs 1
	AllowPublicUIDev  bool                         // only an application that uses it sets this
	// ReaderFramesSelf lets the reader page embed same-origin frames
	// (frame-src 'self'), for example a sandboxed file preview the application
	// serves with its own CSP. Off, the reader embeds no frames at all.
	ReaderFramesSelf bool // only an application that uses it sets this
}

// LegacySchema names what identifies a database of an earlier release that
// this application refuses to open. Both lists must be non-nil.
type LegacySchema struct {
	Migrations []string // migration files only earlier releases recorded
	Tables     []string // tables only earlier releases created
	// Description says in a few words what the earlier releases were, for the
	// refusal message. Required when either list has entries.
	Description string
}

// HostedBudget is the hosted request budget of one signed-in account: Burst
// requests at once, refilled at PerSecond. Label names the limit in 429
// responses, a value clients may match on. The zero value means the
// application cannot be served hosted; a partly set budget is refused.
type HostedBudget struct {
	Label     string
	Burst     int
	PerSecond int
}

func (b HostedBudget) configured() bool { return b != HostedBudget{} }

func (p Policy) validate() error {
	if p.OAuthScope == "" || len(p.OAuthScope) > 64 {
		return errors.New("Policy.OAuthScope is required and at most 64 bytes")
	}
	for _, c := range p.OAuthScope {
		// RFC 6749 scope-token, so it is also safe in a quoted header value.
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return errors.New("Policy.OAuthScope must be one OAuth scope token")
		}
	}
	if p.PublicBodyLimit <= 0 {
		return errors.New("Policy.PublicBodyLimit is required")
	}
	if p.Legacy.Migrations == nil || p.Legacy.Tables == nil {
		return errors.New("Policy.Legacy is required")
	}
	if len(p.Legacy.Migrations)+len(p.Legacy.Tables) > 0 && p.Legacy.Description == "" {
		return errors.New("Policy.Legacy.Description is required with legacy entries")
	}
	if p.Hosted.configured() {
		if p.Hosted.Burst <= 0 || p.Hosted.PerSecond <= 0 || p.Hosted.Label == "" {
			return errors.New("Policy.Hosted needs Label, Burst and PerSecond")
		}
		for _, c := range p.Hosted.Label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				return errors.New("Policy.Hosted.Label must use a-z, 0-9 and _")
			}
		}
	}
	return nil
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
	// OTPLoginPath is the same-origin reader path the hosted sign-in email
	// links to. Core appends "?otpId=...&otp=...", so the path has no query; a
	// fragment route such as "/#/login" is allowed.
	OTPLoginPath string
}

// OAuthConsentText is trusted static copy from the application, used as template
// source. {{.Name}} in RequestHTML is the client-supplied name and is escaped.
type OAuthConsentText struct {
	ConnectionsHTML string
	RequestHTML     string
	// SignInHTML tells a person who is not signed in how to sign in when the
	// application is not hosted, where that depends on the application's own
	// commands. It is inline content of one paragraph; {{.Product}} is the
	// display name. Hosted instances show core's email sign-in text instead.
	SignInHTML string
	Page       OAuthPage
}

// OAuthPage is an application's optional presentation of the server-rendered
// OAuth pages. Every field is trusted static application text, never request
// data. An empty field keeps the plain page's behaviour for that part, so an
// application that sets none renders exactly the plain page.
type OAuthPage struct {
	// CSS replaces the page's whole style sheet. The page's Content-Security-Policy
	// still applies: no images, fonts or other external resources load. Style the
	// [hidden] attribute if a rule would otherwise display a hidden element.
	CSS string
	// BrandHTML replaces the product name line above the title. It is emitted
	// as-is and is not parsed as a template, so it cannot read client values.
	BrandHTML string
	// SignInPath is the same-origin reader path the consent page offers as its
	// Log in action, replacing the instructions to sign in from another tab. The
	// page appends "?next=" and the percent-encoded /oauth/authorize request, so
	// the path has no query; a fragment route such as "/#/signin" is allowed. The
	// application must validate next before navigating to it.
	SignInPath string
	// ConnectionsPath is the application's own connected-apps page. A browser
	// navigation to /oauth/connections redirects there and the consent page
	// links to it; the JSON API at /oauth/connections does not change.
	ConnectionsPath string
}

// validate reports the first unsafe field. These values reach a Location header
// and same-origin navigations, so a typing mistake must not become an open redirect.
func (p OAuthPage) validate() error {
	if strings.Contains(strings.ToLower(p.CSS), "</style") {
		return errors.New("Page.CSS must not close its style element")
	}
	if p.SignInPath != "" {
		if err := validateOAuthAppPath(p.SignInPath); err != nil {
			return fmt.Errorf("Page.SignInPath: %w", err)
		}
		if strings.Contains(p.SignInPath, "?") {
			return errors.New("Page.SignInPath: must not have a query")
		}
	}
	if p.ConnectionsPath != "" {
		if err := validateOAuthAppPath(p.ConnectionsPath); err != nil {
			return fmt.Errorf("Page.ConnectionsPath: %w", err)
		}
		if u, _ := url.Parse(p.ConnectionsPath); u.Path == "/oauth/connections" {
			return errors.New("Page.ConnectionsPath: must not redirect to itself")
		}
	}
	return nil
}

func validateOAuthAppPath(value string) error {
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\\<>\"'` ") {
		return errors.New("must be a same-origin absolute path")
	}
	for _, r := range value {
		if r < 0x21 || r == 0x7f {
			return errors.New("must be a same-origin absolute path")
		}
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") {
		return errors.New("must be a same-origin absolute path")
	}
	return nil
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
	if err := cfg.Policy.validate(); err != nil {
		return nil, fmt.Errorf("appserver: %w", err)
	}
	for name, value := range map[string]string{
		"AccountName": cfg.Text.AccountName, "LegacyRecreateHint": cfg.Text.LegacyRecreateHint,
		"OAuthResourceName": cfg.Text.OAuthResourceName, "BudgetExhausted": cfg.Text.BudgetExhausted,
		"OTPSubject": cfg.Text.OTPSubject, "OTPSenderName": cfg.Text.OTPSenderName,
		"OAuthConsent.ConnectionsHTML": cfg.Text.OAuthConsent.ConnectionsHTML,
		"OAuthConsent.RequestHTML":     cfg.Text.OAuthConsent.RequestHTML,
		"OAuthConsent.SignInHTML":      cfg.Text.OAuthConsent.SignInHTML,
		"OTPLoginPath":                 cfg.Text.OTPLoginPath,
	} {
		if value == "" {
			return nil, fmt.Errorf("appserver: Text.%s is required", name)
		}
	}
	if err := validateOAuthAppPath(cfg.Text.OTPLoginPath); err != nil || strings.Contains(cfg.Text.OTPLoginPath, "?") {
		return nil, errors.New("appserver: Text.OTPLoginPath must be a same-origin absolute path without a query")
	}
	if cfg.Hooks.Bindings != nil {
		if _, collides := cfg.Hooks.Bindings(goja.New())["sha256"]; collides {
			return nil, errors.New("appserver: Hooks.Bindings must not define sha256")
		}
	}
	if err := cfg.Text.OAuthConsent.Page.validate(); err != nil {
		return nil, fmt.Errorf("appserver: Text.OAuthConsent: %w", err)
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
