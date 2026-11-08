package appserver

import (
	"crypto/subtle"
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/hook"

	"github.com/pocketcontext-labs/pocketcontext-core/appidentity"
	"github.com/pocketcontext-labs/pocketcontext-core/atomicfile"
)

// Local routes provide sign-in without an identity provider. Reading the private key file proves the
// caller is this computer's user, who can already read the database file.
// Every other API still requires an ordinary users token.

type localRoutes struct {
	p         *Project
	store     *Store
	key       string
	stop      chan struct{}
	codes     codeStore
	uiDev     string
	listeners *listenerSet
	nameMu    sync.RWMutex
	publicURL string
	mcp       bool
	hosted    bool
}

// Sign-in code lifetimes in seconds. Codes live only in server memory.
const (
	MinCodeTTL     = 30
	MaxCodeTTL     = 600
	DefaultCodeTTL = 120
)

// ValidCodeTTL reports whether seconds is an allowed sign-in code lifetime.
func ValidCodeTTL(seconds int) bool { return seconds >= MinCodeTTL && seconds <= MaxCodeTTL }

type loginCode struct {
	user    string
	expires time.Time
}

// codeStore holds single-use sign-in codes in memory.
type codeStore struct {
	mu    sync.Mutex
	codes map[string]loginCode
	now   func() time.Time
}

func (s *codeStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// issue creates a code for the user and purges expired ones.
func (s *codeStore) issue(user string, ttl time.Duration) (string, time.Time) {
	code := atomicfile.RandomHex(24)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	if s.codes == nil {
		s.codes = map[string]loginCode{}
	}
	for c, v := range s.codes {
		if now.After(v.expires) {
			delete(s.codes, c)
		}
	}
	expires := now.Add(ttl)
	s.codes[code] = loginCode{user, expires}
	return code, expires
}

// take consumes a code and returns its user when it was valid.
func (s *codeStore) take(code string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.codes[code]
	delete(s.codes, code) // single use
	if !ok || !s.clock().Before(v.expires) {
		return "", false
	}
	return v.user, true
}

func loopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (l *localRoutes) allowedHost(host string) bool {
	port := strings.TrimPrefix(l.p.URL(), "http://127.0.0.1")
	return host == "127.0.0.1"+port || host == "localhost"+port
}

func (l *localRoutes) requireKey(e *core.RequestEvent) error {
	given := e.Request.Header.Get(l.p.rt.cfg.Identity.LocalKeyHeader)
	if publicRequest(e.Request) {
		return e.ForbiddenError("Local management is unavailable on public HTTPS.", nil)
	}
	if (!loopback(e.Request) && !socketRequest(e.Request)) || subtle.ConstantTimeCompare([]byte(given), []byte(l.key)) != 1 {
		return e.ForbiddenError("A local key is required.", nil)
	}
	return nil
}

// account returns the project's one account.
func (l *localRoutes) account(app core.App) (*core.Record, error) {
	records, err := app.FindRecordsByFilter("users", "", "created", 1, 0)
	if err != nil {
		return nil, err
	}
	if len(records) != 1 {
		return nil, apis.NewBadRequestError(fmt.Sprintf("No account yet; run `%s init`.", l.p.rt.cfg.Identity.Command), nil)
	}
	return records[0], nil
}

func (l *localRoutes) register(e *core.ServeEvent) error {
	rt := l.p.rt
	id := rt.cfg.Identity
	if l.hosted {
		registerHostedRateLimits(e, rt)
	}
	// DNS rebinding protection: a web page cannot reach this server under another name.
	e.Router.Bind(&hook.Handler[*core.RequestEvent]{
		Id: "contextLocalHost", Priority: -99999,
		Func: func(re *core.RequestEvent) error {
			if publicRequest(re.Request) {
				if l.publicURL == "" || ("https://"+re.Request.Host != l.publicURL && "https://"+strings.TrimSuffix(re.Request.Host, ":443") != l.publicURL) {
					return re.ForbiddenError("Unexpected host.", nil)
				}
				return re.Next()
			}
			if !l.allowedHost(re.Request.Host) && !(socketRequest(re.Request) && re.Request.Host == id.SocketHost) {
				return re.ForbiddenError("Unexpected host.", nil)
			}
			return re.Next()
		},
	})

	e.Router.GET("/api/bundle/auth-mode", func(re *core.RequestEvent) error {
		mode := "password"
		if l.hosted {
			mode = "email"
		}
		re.Response.Header().Set("Cache-Control", "no-store")
		return re.JSON(http.StatusOK, map[string]string{"mode": mode})
	})
	if rt.cfg.Hooks.Routes != nil {
		if err := rt.cfg.Hooks.Routes(e); err != nil {
			return err
		}
	}
	e.Router.GET("/api/bundle/instance", func(re *core.RequestEvent) error {
		l.nameMu.RLock()
		defer l.nameMu.RUnlock()
		info := map[string]any{
			"app": id.AppID, "version": rt.cfg.Version, "instance": l.p.Config.Instance, "key": l.p.Key, "name": l.p.Config.Name, "port": l.p.Config.Port,
			"databaseFormat": DatabaseFormat, "hosted": l.hosted,
		}
		if l.publicURL != "" {
			info["publicURL"] = l.publicURL
			if l.mcp {
				info["mcpURL"] = l.publicURL + "/mcp"
			}
		}
		if l.listeners != nil {
			socket, tcp := l.listeners.state()
			info["socket"], info["tcp"], info["headless"] = socket, tcp, !tcp
		}
		if l.uiDev != "" {
			// The repository launcher verifies the exact child before it may
			// stop it; an existing server on this port is never adopted.
			info["uiDev"], info["pid"] = l.uiDev, os.Getpid()
		}
		return re.JSON(http.StatusOK, info)
	})

	e.Router.POST("/api/bundle/name", func(re *core.RequestEvent) error {
		if err := l.requireKey(re); err != nil {
			return err
		}
		var body struct {
			Name string `json:"name"`
		}
		if err := re.BindBody(&body); err != nil {
			return re.BadRequestError("Invalid name.", nil)
		}
		name := strings.TrimSpace(body.Name)
		if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 80 || strings.ContainsAny(name, "/\\") || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			return re.BadRequestError("Name must be 1-80 characters without slashes or control characters.", nil)
		}
		l.nameMu.Lock()
		defer l.nameMu.Unlock()
		old := l.p.Config.Name
		l.p.Config.Name = name
		if err := l.p.SaveConfig(); err != nil {
			l.p.Config.Name = old
			return re.InternalServerError("Could not save name.", err)
		}
		return re.JSON(http.StatusOK, map[string]any{"name": name, "instance": l.p.Config.Instance})
	})

	e.Router.POST("/api/bundle/enable-tcp", func(re *core.RequestEvent) error {
		if err := l.requireKey(re); err != nil {
			return err
		}
		if l.hosted {
			return re.ForbiddenError("Hosted mode has no private TCP reader.", nil)
		}
		if l.listeners == nil {
			return re.InternalServerError("listener manager unavailable", nil)
		}
		if err := l.listeners.enableTCP(); err != nil {
			return re.BadRequestError(err.Error(), nil)
		}
		return re.JSON(http.StatusOK, map[string]any{"tcp": true, "port": l.p.Config.Port, "url": l.p.URL()})
	})

	e.Router.POST("/api/bundle/token", func(re *core.RequestEvent) error {
		if err := l.requireKey(re); err != nil {
			return err
		}
		user, err := l.account(re.App)
		if err != nil {
			return re.BadRequestError(fmt.Sprintf("No local account; run `%s init`.", id.Command), nil)
		}
		return apis.RecordAuthResponse(re, user, "local", nil)
	})

	e.Router.POST("/api/bundle/account", func(re *core.RequestEvent) error {
		if err := l.requireKey(re); err != nil {
			return err
		}
		if l.hosted {
			return re.ForbiddenError("Hosted mode uses email authentication.", nil)
		}
		// Creates the project's one account, or changes its password. A second
		// account is refused by the hooks as well.
		var body struct {
			Password string `json:"password"`
		}
		if err := re.BindBody(&body); err != nil {
			return re.BadRequestError("Invalid account.", nil)
		}
		if len(body.Password) < 8 {
			return re.BadRequestError("The password needs at least 8 characters.", nil)
		}
		user, err := l.account(re.App)
		created := err != nil
		if created {
			users, err := re.App.FindCollectionByNameOrId("users")
			if err != nil {
				return err
			}
			user = core.NewRecord(users)
			user.SetEmail(id.LocalAccountEmail)
			user.SetVerified(true)
			user.Set("name", rt.cfg.Text.AccountName)
		}
		user.SetPassword(body.Password)
		if err := re.App.Save(user); err != nil {
			return re.BadRequestError("Could not save the account: "+err.Error(), nil)
		}
		return re.JSON(http.StatusOK, map[string]any{"id": user.Id, "created": created})
	})

	e.Router.POST("/api/bundle/login-code", func(re *core.RequestEvent) error {
		if err := l.requireKey(re); err != nil {
			return err
		}
		var body struct {
			TTL    *int `json:"ttl"`
			Public bool `json:"public"`
		}
		if re.Request.ContentLength != 0 {
			if err := re.BindBody(&body); err != nil {
				return re.BadRequestError("Invalid request.", nil)
			}
		}
		baseURL := l.p.URL()
		if body.Public {
			if l.publicURL == "" {
				return re.BadRequestError("Public HTTPS is not enabled on this server.", nil)
			}
			baseURL = l.publicURL
		}
		ttl := DefaultCodeTTL
		if body.TTL != nil {
			ttl = *body.TTL
		}
		if !ValidCodeTTL(ttl) {
			return re.BadRequestError(fmt.Sprintf("ttl must be %d-%d seconds.", MinCodeTTL, MaxCodeTTL), nil)
		}
		user, err := l.account(re.App)
		if err != nil {
			return re.BadRequestError(fmt.Sprintf("No local account; run `%s init`.", id.Command), nil)
		}
		code, expires := l.codes.issue(user.Id, time.Duration(ttl)*time.Second)
		return re.JSON(http.StatusOK, map[string]string{
			"url":     baseURL + "/bundle/login#" + code,
			"code":    code,
			"expires": expires.UTC().Format(time.RFC3339),
		})
	})

	// An authenticated client can hand its own account to the browser without
	// disclosing the client's reusable token or requiring the server's local key.
	e.Router.POST("/api/bundle/reader-code", func(re *core.RequestEvent) error {
		code, expires := l.codes.issue(re.Auth.Id, DefaultCodeTTL*time.Second)
		re.Response.Header().Set("Cache-Control", "no-store")
		return re.JSON(http.StatusOK, map[string]string{
			"url":     l.p.URL() + "/bundle/login#" + code,
			"expires": expires.UTC().Format(time.RFC3339),
		})
	}).Bind(apis.RequireAuth("users"))

	e.Router.POST("/api/bundle/redeem", func(re *core.RequestEvent) error {
		var body struct {
			Code string `json:"code"`
		}
		if err := re.BindBody(&body); err != nil {
			return re.BadRequestError("Invalid code.", nil)
		}
		id, ok := l.codes.take(body.Code)
		if !ok {
			return re.UnauthorizedError("This sign-in code is used or expired.", nil)
		}
		user, err := re.App.FindRecordById("users", id)
		if err != nil {
			return re.UnauthorizedError("This sign-in code is used or expired: the account no longer exists.", nil)
		}
		return apis.RecordAuthResponse(re, user, "local", nil)
	})

	e.Router.POST("/api/bundle/flush", func(re *core.RequestEvent) error {
		if err := l.requireKey(re); err != nil {
			return err
		}
		l.store.mu.Lock()
		err := l.store.writeBack()
		l.store.mu.Unlock()
		if err != nil {
			return re.InternalServerError("Write-back failed: "+err.Error(), nil)
		}
		return re.JSON(http.StatusOK, map[string]string{"db": l.p.DB})
	})

	e.Router.POST("/api/bundle/stop", func(re *core.RequestEvent) error {
		if err := l.requireKey(re); err != nil {
			return err
		}
		select {
		case l.stop <- struct{}{}:
		default:
		}
		return re.JSON(http.StatusOK, map[string]bool{"stopping": true})
	})

	page := func(re *core.RequestEvent, contentType, body string) error {
		h := re.Response.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		return re.Blob(http.StatusOK, contentType, []byte(body))
	}
	e.Router.GET("/bundle/login", func(re *core.RequestEvent) error {
		return page(re, "text/html; charset=utf-8", loginHTML(id))
	})
	e.Router.GET("/bundle/login.js", func(re *core.RequestEvent) error {
		return page(re, "text/javascript; charset=utf-8", loginJS(id))
	})
	return nil
}

func loginHTML(id appidentity.Identity) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>` + html.EscapeString(id.DisplayName) + ` sign-in</title></head>
<body><p id="status">Signing in…</p><script src="/bundle/login.js"></script></body></html>`
}

// The code travels in the fragment, so it never reaches logs or the Referer.
func loginJS(id appidentity.Identity) string {
	return `(async () => {
  const status = document.getElementById("status");
  const code = location.hash.slice(1);
  history.replaceState(null, "", "/bundle/login");
  try {
    const response = await fetch("/api/bundle/redeem", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({code})});
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || "Sign-in failed.");
    localStorage.setItem(` + jsString(id.ReaderStorageKey) + `, JSON.stringify({token: data.token, record: data.record}));
    location.replace("/");
  } catch (error) {
    status.textContent = error.message + " Ask your setup agent for a fresh sign-in link, or sign in with your password.";
  }
})();`
}
