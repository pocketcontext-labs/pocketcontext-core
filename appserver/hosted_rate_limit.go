package appserver

import (
	"crypto/sha256"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"ganigeorgiev.com/pocketbase/pocketbase/apis"
	"ganigeorgiev.com/pocketbase/pocketbase/core"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/hook"
	"ganigeorgiev.com/pocketbase/pocketbase/tools/router"
	"golang.org/x/time/rate"
)

// Rate metadata is also carried in the body because MCP tools do not expose the
// headers of their internal HTTP requests. Reset is seconds until the bucket is full.
type rateLimitInfo struct {
	Limit             string `json:"limit"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
	Capacity          int    `json:"capacity"`
	Remaining         int    `json:"remaining"`
	ResetAfterSeconds int    `json:"reset_after_seconds"`
}

func (i rateLimitInfo) headers(h http.Header) {
	h.Set("Retry-After", strconv.Itoa(i.RetryAfterSeconds))
	h.Set("RateLimit-Limit", strconv.Itoa(i.Capacity))
	h.Set("RateLimit-Remaining", strconv.Itoa(i.Remaining))
	h.Set("RateLimit-Reset", strconv.Itoa(i.ResetAfterSeconds))
	h.Set("Cache-Control", "no-store")
}
func rateLimitKey(key string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(key)))[:16] }
func logRateLimit(app core.App, key, route string, info rateLimitInfo) {
	if host, _, err := net.SplitHostPort(key); err == nil {
		key = host
	}
	app.Logger().Warn("Request rate limited", "key", rateLimitKey(key), "route", route, "limit", info.Limit, "remaining", info.Remaining, "retry_after_seconds", info.RetryAfterSeconds)
}
func writeRateLimit(app core.App, w http.ResponseWriter, r *http.Request, info rateLimitInfo, message string) {
	info.headers(w.Header())
	key := r.RemoteAddr
	if strings.HasPrefix(info.Limit, "email_") || info.Limit == "oauth_pending" || strings.HasSuffix(info.Limit, "_capacity") {
		key = info.Limit
	}
	logRateLimit(app, key, r.URL.Path, info)
	oauthJSON(w, http.StatusTooManyRequests, map[string]any{"status": 429, "message": message, "data": map[string]any{"rate_limit": info}})
}

// configureHostedRateLimits changes only process-local settings. Authentication
// keeps PocketBase's original rules. API requests with valid users tokens
// instead use the application's bounded account budget (Policy.Hosted),
// independent of token, client or run key.
func configureHostedRateLimits(app core.App) {
	settings := app.Settings()
	settings.RateLimits.Enabled = true
	rules := append([]core.RateLimitRule(nil), settings.RateLimits.Rules...)
	for i := range rules {
		if rules[i].Audience == core.RateLimitRuleAudienceAll && (rules[i].Label == "*:create" || rules[i].Label == "/api/batch" || rules[i].Label == "/api/") {
			rules[i].Audience = core.RateLimitRuleAudienceGuest
		}
	}
	settings.RateLimits.Rules = rules
}

func registerHostedRateLimits(e *core.ServeEvent, rt *Runtime) {
	registerHostedRateLimitsClock(e, rt, time.Now)
}

func registerHostedRateLimitsClock(e *core.ServeEvent, rt *Runtime, clock func() time.Time) {
	var mu sync.Mutex
	buckets := map[string]*rate.Limiter{}
	budget := rt.cfg.Policy.Hosted
	perSecond := float64(budget.PerSecond)
	e.Router.Bind(&hook.Handler[*core.RequestEvent]{Id: "hostedAccountRateLimit", Priority: apis.DefaultLoadAuthTokenMiddlewarePriority + 6, Func: func(re *core.RequestEvent) error {
		if re.Auth != nil && re.Auth.Collection().Name == "users" && strings.HasPrefix(re.Request.URL.Path, "/api/") {
			key := re.Auth.Id
			mu.Lock()
			bucket := buckets[key]
			if bucket == nil {
				bucket = rate.NewLimiter(rate.Limit(perSecond), budget.Burst)
				buckets[key] = bucket
			}
			mu.Unlock()
			// The product policy prices a request before it runs: a bulk route can
			// reserve its maximum size so nested operations are not charged again.
			cost := 1
			if price := rt.cfg.Policy.HostedRequestCost; price != nil {
				cost = max(1, price(re))
			}
			now := clock()
			if !bucket.AllowN(now, cost) {
				tokens := bucket.TokensAt(now)
				retry := max(1, int(math.Ceil((float64(cost)-tokens)/perSecond)))
				info := rateLimitInfo{budget.Label, retry, budget.Burst, max(0, int(tokens)), max(1, int(math.Ceil((float64(budget.Burst)-tokens)/perSecond)))}
				info.headers(re.Response.Header())
				logRateLimit(re.App, key, re.Request.Pattern, info)
				return re.JSON(http.StatusTooManyRequests, map[string]any{"status": 429, "message": rt.cfg.Text.BudgetExhausted, "data": map[string]any{"rate_limit": info}})
			}
		}
		err := re.Next()
		if err == nil {
			return nil
		}
		outerErr := router.ToApiError(err)
		apiErr := findRateLimitError(outerErr, 0)
		if apiErr != nil {
			// PocketBase's fixed-window counters do not expose remaining time. A full
			// matching rule window is a conservative retry delay, never an early retry.
			duration, capacity, label := 1, 1, "pocketbase"
			for _, rule := range re.App.Settings().RateLimits.Rules {
				duration = max(duration, int(rule.Duration))
				capacity = max(capacity, rule.MaxRequests)
			}
			for _, rule := range re.App.Settings().RateLimits.Rules {
				if fmt.Sprint(apiErr.RawData()) == "triggered rate limit rule: "+rule.String() {
					duration, capacity, label = int(rule.Duration), rule.MaxRequests, "pocketbase:"+rule.Label
					break
				}
			}
			info := rateLimitInfo{label, duration, capacity, 0, duration}
			info.headers(re.Response.Header())
			logRateLimit(re.App, re.RealIP(), re.Request.Pattern, info)
			if apiErr.Data == nil {
				apiErr.Data = map[string]any{}
			}
			apiErr.Data["rate_limit"] = info
			if outerErr.Data == nil {
				outerErr.Data = map[string]any{}
			}
			outerErr.Data["rate_limit"] = info
			return outerErr
		}
		return err
	}})
}

func (l *publicAuthLimiter) rejection(address, label string) rateLimitInfo {
	host, _, _ := net.SplitHostPort(address)
	l.mu.Lock()
	defer l.mu.Unlock()
	if entry, ok := l.entries[host]; ok {
		tokens := entry.limiter.Tokens()
		return rateLimitInfo{label, max(1, int(math.Ceil((1-tokens)*6))), 10, max(0, int(tokens)), max(1, int(math.Ceil((10-tokens)*6)))}
	}
	return rateLimitInfo{label + "_capacity", 600, 4096, 0, 600}
}
func oauthRateLimit(app core.App, w http.ResponseWriter, r *http.Request, info rateLimitInfo, code, description string) {
	info.headers(w.Header())
	key := r.RemoteAddr
	if strings.HasPrefix(info.Limit, "email_") || info.Limit == "oauth_pending" || strings.HasSuffix(info.Limit, "_capacity") {
		key = info.Limit
	}
	logRateLimit(app, key, r.URL.Path, info)
	setOAuthOutcome(w, oauthFailureReason(code, description), "rejected")
	oauthJSON(w, http.StatusTooManyRequests, map[string]any{"error": code, "error_description": description, "data": map[string]any{"rate_limit": info}})
}

// PocketBase batch errors embed the original ApiError in their safe response
// data. Preserve its status and validation structure while annotating throttles.
func findRateLimitError(value any, depth int) *router.ApiError {
	if depth > 8 {
		return nil
	}
	switch v := value.(type) {
	case *router.ApiError:
		if v.Status == http.StatusTooManyRequests {
			return v
		}
		return findRateLimitError(v.Data, depth+1)
	case map[string]any:
		for _, child := range v {
			if found := findRateLimitError(child, depth+1); found != nil {
				return found
			}
		}
	}
	return nil
}
