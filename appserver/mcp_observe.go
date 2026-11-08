package appserver

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/pocketcontext-labs/pocketcontext-core/mcpobserve"
)

// oauthResponse records metadata without copying response bodies (which can
// contain credentials or knowledge). Unwrap preserves ResponseController use.
type oauthResponse struct {
	http.ResponseWriter
	status          int
	bytes           int64
	writeFailed     bool
	reason, outcome string
}

func (w *oauthResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *oauthResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *oauthResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	if err != nil || n < len(p) {
		w.writeFailed = true
	}
	return n, err
}
func setOAuthOutcome(w http.ResponseWriter, reason, outcome string) {
	if r, ok := w.(*oauthResponse); ok {
		r.reason, r.outcome = reason, outcome
	}
}

func oauthFailureReason(code, description string) string {
	// Match only server-owned descriptions. Never write the text of an error.
	switch description {
	case "duplicate authorization parameter", "Duplicate token parameter.":
		return "duplicate_parameter"
	case "unknown client", "Unknown client.":
		return "unknown_client"
	case "redirect_uri must exactly match a registered callback":
		return "redirect_mismatch"
	case "redirect_uri is no longer permitted by operator policy":
		return "redirect_policy"
	case "response_type must be code", "Only response_type code is supported.":
		return "unsupported_response_type"
	case "resource must be this MCP endpoint", "The resource must be this MCP endpoint.":
		return "resource_mismatch"
	case "code_challenge_method must be S256":
		return "pkce_method"
	case "code_challenge must be a 43-character base64url-encoded SHA-256 hash":
		return "pkce_challenge"
	case "state must not exceed 2048 bytes":
		return "state_too_large"
	case "only knowledge scope is supported", "Only knowledge scope is supported.":
		return "invalid_scope"
	case "Could not register client; try later or remove unused connections.":
		return "registration_unavailable"
	case "JSON approval required.":
		return "approval_required"
	case "Too many pending authorizations.":
		return "pending_limit"
	case "Form body required.":
		return "form_required"
	case "Invalid refresh token.", "Invalid or expired refresh token.":
		return "invalid_refresh"
	case "Refresh token replay; reconnect.":
		return "refresh_replay"
	case "Could not save replay revocation.", "Could not save authorization; revoke unused connections or reconnect if the token limit was reached.", "Could not save revocation.":
		return "persistence_failure"
	case "Account authorization changed; reconnect.":
		return "grant_revoked"
	case "One token is required.":
		return "token_required"
	case "Connection ID required.":
		return "connection_required"
	case "Account unavailable.":
		return "account_unavailable"
	case "Too many authorization attempts.":
		return "rate_limited"
	}
	switch code {
	case "invalid_client_metadata", "invalid_redirect_uri", "unsupported_grant_type", "login_required", "invalid_client", "invalid_grant", "invalid_token", "invalid_request":
		return code
	default:
		return "internal_error"
	}
}

func (o *mcpOAuth) observe(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ctx, id := mcpobserve.WithRequest(r.Context(), o.rt.cfg.Policy.Observe, o.origin[len("https://"):], o.rt.cfg.Version)
	r = r.WithContext(ctx)
	w.Header().Set("X-Request-ID", id)
	out := &oauthResponse{ResponseWriter: w}
	start := time.Now()
	completed := false
	defer func() {
		status := out.status
		if status == 0 && completed {
			status = 200
		}
		event := "oauth_complete"
		if r.URL.Path == "/mcp" {
			event = "mcp_http"
		}
		outcome, reason := out.outcome, out.reason
		if !completed {
			outcome, reason = "internal_error", "internal_error"
		} else if out.writeFailed {
			outcome, reason = "transport_error", "response_write_failed"
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			outcome, reason = "timeout", "timeout"
		} else if errors.Is(ctx.Err(), context.Canceled) {
			outcome, reason = "cancelled", "cancelled"
		}
		if outcome == "" {
			switch {
			case status == 405:
				outcome, reason = "expected_probe", "method_not_allowed"
			case status >= 500:
				outcome, reason = "internal_error", "internal_error"
			case status >= 400:
				outcome, reason = "rejected", "invalid_request"
			default:
				outcome, reason = "success", "ok"
			}
		}
		mcpobserve.Emit(ctx, mcpobserve.Event{Event: event, Method: r.Method, APIRoute: r.URL.Path, Outcome: outcome, Reason: reason, HTTPStatus: status, DurationMS: time.Since(start).Milliseconds(), ResponseBytes: out.bytes})
	}()
	next(out, r)
	completed = true
}
