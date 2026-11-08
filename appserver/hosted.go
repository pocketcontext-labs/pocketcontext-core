package appserver

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/hook"
	"golang.org/x/time/rate"
)

// HostedConfig is process-local deployment configuration, never synced project data.
type HostedConfig struct {
	OwnerEmail string
	SMTP       core.SMTPConfig
	From       string
}

// HostedConfigFromEnv reads <EnvPrefix>_OWNER_EMAIL and the SMTP settings.
func (rt *Runtime) HostedConfigFromEnv() (*HostedConfig, error) {
	prefix := rt.cfg.Identity.EnvPrefix
	get := func(name string) string { return os.Getenv(prefix + "_" + name) }
	c := &HostedConfig{OwnerEmail: get("OWNER_EMAIL"), From: get("SMTP_FROM")}
	for _, address := range []string{c.OwnerEmail, c.From} {
		parsed, err := mail.ParseAddress(address)
		if err != nil || parsed.Address != address || parsed.Name != "" || strings.ContainsAny(address, "\r\n") {
			return nil, errors.New("hosted mode requires plain OWNER_EMAIL and SMTP_FROM addresses")
		}
	}
	port, err := strconv.Atoi(get("SMTP_PORT"))
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New(prefix + "_SMTP_PORT must be 1-65535")
	}
	mode := get("SMTP_TLS")
	if mode == "" {
		mode = "tls"
	}
	if mode != "tls" && mode != "starttls" {
		return nil, errors.New(prefix + "_SMTP_TLS must be tls or starttls")
	}
	c.SMTP = core.SMTPConfig{Enabled: true, Host: get("SMTP_HOST"), Port: port, Username: get("SMTP_USERNAME"), Password: get("SMTP_PASSWORD"), TLS: mode == "tls", AuthMethod: "PLAIN"}
	if c.SMTP.Host == "" || c.SMTP.Username == "" || c.SMTP.Password == "" {
		return nil, errors.New("hosted mode requires SMTP_HOST, SMTP_USERNAME and SMTP_PASSWORD")
	}
	if err := c.SMTP.Validate(); err != nil {
		return nil, errors.New("invalid hosted SMTP configuration")
	}
	return c, nil
}

// configureHosted runs after migrations and before accepting traffic. Credentials
// only modify the in-memory settings; Save(settings) would leak them into the project.
func configureHosted(rt *Runtime, app core.App, domain string, c *HostedConfig, initialize bool) error {
	text := rt.cfg.Text
	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		return err
	}
	records, err := app.FindRecordsByFilter("users", "", "", 2, 0)
	if err != nil {
		return err
	}
	if initialize {
		if len(records) != 0 {
			return errors.New("hosted initialization refuses an existing account")
		}
		user := core.NewRecord(users)
		user.SetEmail(c.OwnerEmail)
		user.SetRandomPassword()
		user.SetVerified(false)
		user.Set("name", text.AccountName)
		if err = app.Save(user); err != nil {
			return fmt.Errorf("initialize hosted account: %w", err)
		}
	} else if len(records) != 1 || records[0].Email() != c.OwnerEmail {
		return errors.New("hosted owner does not match the existing account; owner changes require explicit maintenance")
	}
	users.PasswordAuth.Enabled = false
	users.OTP.Enabled = true
	users.OTP.Duration = 900
	users.OTP.Length = 32
	users.OTP.EmailTemplate = core.EmailTemplate{Subject: text.OTPSubject, Body: `<p>You requested a login link for ` + html.EscapeString(text.OTPSenderName) + `.</p><p><a href="https://` + domain + `/#/login?otpId={OTP_ID}&amp;otp={OTP}">` + html.EscapeString(text.OTPSubject) + `</a></p><p>This link expires in 15 minutes. Open it and confirm Log in. If you did not request it, ignore this email.</p>`}
	if err = app.Save(users); err != nil {
		return err
	}
	// PocketBase 0.41.1 logs a failed OTP deletion and otherwise continues.
	// Fail closed before issuing credentials and recheck after acquiring the lock
	// so simultaneous requests cannot redeem the same validated OTP twice.
	sendCooldown := rate.NewLimiter(rate.Every(time.Minute), 1)
	app.OnRecordRequestOTPRequest("users").Bind(&hook.Handler[*core.RecordCreateOTPRequestEvent]{Id: "hostedEmailCooldown", Func: func(e *core.RecordCreateOTPRequestEvent) error {
		if e.Record != nil && !sendCooldown.Allow() {
			return e.JSON(http.StatusOK, map[string]string{"otpId": core.GenerateDefaultRandomId()})
		}
		return e.Next()
	}})
	var redemption sync.Mutex
	app.OnRecordAuthWithOTPRequest("users").Bind(&hook.Handler[*core.RecordAuthWithOTPRequestEvent]{Id: "hostedSingleUseOTP", Func: func(e *core.RecordAuthWithOTPRequestEvent) error {
		redemption.Lock()
		defer redemption.Unlock()
		fresh, err := e.App.FindOTPById(e.OTP.Id)
		if err != nil {
			return e.BadRequestError("Invalid or expired OTP", nil)
		}
		if err = e.App.Delete(fresh); err != nil {
			return e.InternalServerError("Could not complete login. Please try again.", nil)
		}
		return e.Next()
	}})
	settings := app.Settings()
	settings.SMTP = c.SMTP
	settings.Meta.AppURL = "https://" + domain
	settings.Meta.SenderName = text.OTPSenderName
	settings.Meta.SenderAddress = c.From
	configureHostedRateLimits(app)
	return nil
}

func startHostedHTTP(ctx context.Context, app core.App, p *Project, opts ServeOptions, handler http.Handler, failures chan<- error) (*publicServers, error) {
	oauth, err := newMCPOAuth(app, p, opts.HTTPSDomain, opts.MCPHandler(handler))
	if err != nil {
		return nil, err
	}
	oauth.hosted = true
	address := ":80"
	if opts.DevHTTPAddress != "" {
		address = opts.DevHTTPAddress
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on hosted HTTP address: %w", err)
	}
	server := &http.Server{Handler: publicHandlerModeWithUIDev(p.rt, app, opts.HTTPSDomain, handler, true, opts.PublicUIDev, oauth), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 5 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	s := &publicServers{http: server, plainListener: ln}
	go func() { failures <- server.Serve(ln) }()
	return s, nil
}

// invalidateHostedRestore deliberately invalidates copied browser/OTP/MCP credentials
// before a restored instance accepts any public request. Ordinary restarts retain them.
func invalidateHostedRestore(app core.App, p *Project) error {
	if hook := p.rt.cfg.Hooks.OnHostedRestore; hook != nil {
		if err := hook(app); err != nil {
			return err
		}
	}
	if err := app.RunInTransaction(func(tx core.App) error {
		users, err := tx.FindAllRecords("users")
		if err != nil {
			return err
		}
		for _, user := range users {
			user.RefreshTokenKey()
			if err = tx.Save(user); err != nil {
				return err
			}
		}
		otps, err := tx.FindAllRecords("_otps")
		if err != nil {
			return err
		}
		for _, otp := range otps {
			if err = tx.Delete(otp); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	paths, err := filepath.Glob(filepath.Join(p.Cache, "mcp-oauth-*.json"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

// CheckLocalProject refuses local-only initialization and serving of a hosted
// volume even before the database is opened. The account check after migrations
// also protects copies whose private marker was not retained.
func CheckLocalProject(p *Project) error {
	_, err := os.Stat(filepath.Join(p.Cache, "hosted.json"))
	if err == nil {
		return errors.New("this hosted project requires --hosted; local initialization and private tunnels are unavailable")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
