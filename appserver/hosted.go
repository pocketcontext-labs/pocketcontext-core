package appserver

import (
	"context"
	"database/sql"
	"encoding/json"
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
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/hook"
	"golang.org/x/time/rate"
)

// errNoHostedMode refuses hosted serving for an application that set no
// Policy.Hosted budget; core has no budget of its own to fall back on.
var errNoHostedMode = errors.New("hosted mode is not configured for this application")

// HostedConfig is process-local deployment configuration, never synced project data.
type HostedConfig struct {
	OwnerEmail string
	// OwnerID confirms the original account on the first upgrade of a legacy
	// AccountsMulti database. Later starts use the persisted binding.
	OwnerID string
	SMTP    core.SMTPConfig
	From    string
}

// HostedConfigFromEnv reads the owner and SMTP configuration under EnvPrefix.
func (rt *Runtime) HostedConfigFromEnv() (*HostedConfig, error) {
	prefix := rt.cfg.Identity.EnvPrefix
	get := func(name string) string { return os.Getenv(prefix + "_" + name) }
	c := &HostedConfig{OwnerEmail: get("OWNER_EMAIL"), OwnerID: get("OWNER_ID"), From: get("SMTP_FROM")}
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
	if !rt.cfg.Policy.Hosted.configured() {
		return errNoHostedMode
	}
	text := rt.cfg.Text
	users, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		return err
	}
	multi := rt.cfg.Policy.Accounts == AccountsMulti
	var ownerID string
	if multi {
		if err := app.RunInTransaction(func(tx core.App) error {
			var err error
			ownerID, err = ensureMultiOwner(rt, tx, users, c, initialize)
			return err
		}); err != nil {
			return err
		}
	} else {
		records, err := app.FindRecordsByFilter("users", "", "", 2, 0)
		if err != nil {
			return err
		}
		switch {
		case initialize && len(records) != 0:
			return errors.New("hosted initialization refuses an existing account")
		case initialize:
			record := newHostedAccount(users, c.OwnerEmail, text.AccountName)
			if err = app.Save(record); err != nil {
				return fmt.Errorf("initialize hosted account: %w", err)
			}
			ownerID = record.Id
		case len(records) != 1 || records[0].Email() != c.OwnerEmail:
			return errors.New("hosted owner does not match the existing account; owner changes require explicit maintenance")
		default:
			ownerID = records[0].Id
		}
	}
	app.Store().Set(hostedOwnerIDKey, ownerID)
	users.PasswordAuth.Enabled = false
	if d := rt.cfg.Policy.HostedSession; d > 0 {
		users.AuthToken.Duration = int64(d / time.Second)
	}
	users.OTP.Enabled = true
	users.OTP.Duration = int64(hostedOTPDuration / time.Second)
	users.OTP.Length = 32
	users.OTP.EmailTemplate = core.EmailTemplate{Subject: text.OTPSubject, Body: `<p>You requested a login link for ` + html.EscapeString(text.OTPSenderName) + `.</p><p><a href="https://` + domain + html.EscapeString(text.OTPLoginPath) + `?otpId={OTP_ID}&amp;otp={OTP}">` + html.EscapeString(text.OTPSubject) + `</a></p><p>This link expires in 15 minutes. Open it and confirm Log in. If you did not request it, ignore this email.</p>`}
	if err = app.Save(users); err != nil {
		return err
	}
	// PocketBase 0.41.1 logs a failed OTP deletion and otherwise continues.
	// Fail closed before issuing credentials and recheck after acquiring the lock
	// so simultaneous requests cannot redeem the same validated OTP twice.
	if multi {
		bindHostedSignIn(rt, app, ownerID)
	} else {
		sendCooldown := rate.NewLimiter(rate.Every(time.Minute), 1)
		app.OnRecordRequestOTPRequest("users").Bind(&hook.Handler[*core.RecordCreateOTPRequestEvent]{Id: "hostedEmailCooldown", Func: func(e *core.RecordCreateOTPRequestEvent) error {
			if e.Record != nil && !sendCooldown.Allow() {
				return e.JSON(http.StatusOK, map[string]string{"otpId": core.GenerateDefaultRandomId()})
			}
			return e.Next()
		}})
	}
	redemption := &hostedOTPCodesFor(app).redeem
	app.OnRecordAuthWithOTPRequest("users").Bind(&hook.Handler[*core.RecordAuthWithOTPRequestEvent]{Id: "hostedSingleUseOTP", Func: func(e *core.RecordAuthWithOTPRequestEvent) error {
		redemption.Lock()
		defer redemption.Unlock()
		record, err := consumeHostedOTP(e.App, e.OTP.Id, e.Record.Id, multi)
		if errors.Is(err, sql.ErrNoRows) {
			return e.BadRequestError("Invalid or expired OTP", nil)
		}
		if err != nil {
			return e.InternalServerError("Could not complete login. Please try again.", nil)
		}
		e.Record = record
		return e.Next()
	}})
	bindHostedOTPCode(rt, app, domain)
	settings := app.Settings()
	settings.SMTP = c.SMTP
	settings.Meta.AppURL = "https://" + domain
	settings.Meta.SenderName = text.OTPSenderName
	settings.Meta.SenderAddress = c.From
	configureHostedRateLimits(app)
	// The public handler alone decides the client address (HostedProxy). A
	// stored trusted-proxy setting must never make PocketBase read a header.
	settings.TrustedProxy = core.TrustedProxyConfig{}
	app.OnSettingsReload().Bind(&hook.Handler[*core.SettingsReloadEvent]{Id: "hostedNoTrustedProxy", Func: func(e *core.SettingsReloadEvent) error {
		err := e.Next()
		e.App.Settings().TrustedProxy = core.TrustedProxyConfig{}
		return err
	}})
	return nil
}

func ensureMultiOwner(rt *Runtime, app core.App, users *core.Collection, cfg *HostedConfig, initialize bool) (string, error) {
	owner, ok := canonicalEmail(cfg.OwnerEmail)
	if !ok {
		return "", errors.New("hosted OWNER_EMAIL must be a plain ASCII address")
	}
	if owner == lowerASCII(rt.cfg.Identity.LocalAccountEmail) {
		return "", errors.New("hosted OWNER_EMAIL must not be the local account address")
	}
	total, err := app.CountRecords(users)
	if err != nil {
		return "", err
	}
	if initialize && total != 0 {
		return "", errors.New("hosted initialization refuses an existing account")
	}

	var binding core.Param
	err = app.ModelQuery(&binding).Model(hostedOwnerIDKey, &binding)
	hasBinding := err == nil
	if !hasBinding && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	mismatch := errors.New("hosted owner does not match the existing accounts; owner changes require explicit maintenance")
	var record *core.Record
	if total == 0 {
		if hasBinding || cfg.OwnerID != "" {
			return "", mismatch
		}
		record = newHostedAccount(users, owner, rt.cfg.Text.AccountName)
		if err := app.Save(record); err != nil {
			return "", fmt.Errorf("initialize hosted account: %w", err)
		}
	} else {
		local, err := findAccountsByEmail(app, lowerASCII(rt.cfg.Identity.LocalAccountEmail))
		if err != nil {
			return "", err
		}
		if len(local) != 0 {
			return "", errors.New("this database holds the local account; hosted serving of a local project requires explicit maintenance")
		}
		found, err := findAccountsByEmail(app, owner)
		if err != nil {
			return "", err
		}
		if len(found) != 1 || cfg.OwnerID != "" && cfg.OwnerID != found[0].Id {
			return "", mismatch
		}
		record = found[0]
		if hasBinding {
			var id string
			if err := json.Unmarshal(binding.Value, &id); err != nil || id != record.Id {
				return "", mismatch
			}
			return record.Id, nil
		}
		if total > 1 && cfg.OwnerID == "" {
			return "", fmt.Errorf("legacy hosted database needs its original owner record ID in %s_OWNER_ID to bind ownership", rt.cfg.Identity.EnvPrefix)
		}
	}
	binding.Id = hostedOwnerIDKey
	binding.Value, err = json.Marshal(record.Id)
	if err != nil {
		return "", err
	}
	return record.Id, app.Save(&binding)
}

// newHostedAccount is a hosted account as core creates it: a random password
// (password sign-in is off), not verified until its first email sign-in.
func newHostedAccount(users *core.Collection, email, name string) *core.Record {
	user := core.NewRecord(users)
	user.SetEmail(email)
	user.SetRandomPassword()
	user.SetVerified(false)
	user.Set("name", name)
	return user
}

func startHostedHTTP(ctx context.Context, app core.App, p *Project, opts ServeOptions, handler http.Handler, failures chan<- error) (*publicServers, error) {
	oauth, err := newMCPOAuth(app, p, opts.HTTPSDomain, opts.MCPHandler(handler))
	if err != nil {
		return nil, err
	}
	oauth.hosted = true
	address := ":80"
	switch {
	case opts.HostedHTTPAddress != "":
		address = opts.HostedHTTPAddress
	case opts.DevHTTPAddress != "":
		address = opts.DevHTTPAddress
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on hosted HTTP address: %w", err)
	}
	public := newPublicHandler(p.rt, app, opts.HTTPSDomain, handler, publicHandlerOptions{hosted: true, uiDev: opts.PublicUIDev, proxy: opts.HostedProxy}, oauth)
	server := &http.Server{Handler: public, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 5 * time.Minute, IdleTimeout: hostedIdleTimeout, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
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
// (checkLocalAccounts) also protects copies whose private marker was not retained.
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

// checkLocalAccounts refuses local and tunnel serving of a database that a
// hosted instance has used. A local database holds at most one account, the
// identity's local address, in both account modes; a hosted database always
// holds the OWNER_EMAIL account, which is never that address with AccountsMulti.
// The check reads only the database, so it holds for copies that lost the
// private hosted marker, and it does not depend on Policy.Accounts.
func checkLocalAccounts(app core.App, localEmail string) error {
	records, err := app.FindRecordsByFilter("users", "", "", 2, 0)
	if err != nil {
		return err
	}
	if len(records) > 1 || len(records) == 1 && lowerASCII(records[0].Email()) != lowerASCII(localEmail) {
		return errors.New("this hosted project requires explicit --hosted serving; local and tunnel modes are unavailable")
	}
	return nil
}
