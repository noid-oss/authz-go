package authz

import (
	"context"
	"net/http"
	"strings"
)

// Mode selects how a guarded route decides.
type Mode string

const (
	// ModeLive is the default: the full Perms.Can algorithm. Writes are always
	// checked live; reads are decided from the claim (plus a live object check
	// when an object is resolved).
	ModeLive Mode = "live"
	// ModeHint decides from the token claim only. It is an explicit opt-out
	// that is only allowed for permissions listed under reads, and cannot be
	// combined with an object. Misuse panics at route-registration time.
	ModeHint Mode = "hint"
)

// ObjectFunc resolves the object a request targets, e.g. from the URL path.
// Return ok=false when the route has no object. Anything it returns is
// validated against the grammars before use.
type ObjectFunc func(r *http.Request) (Object, bool)

// Guard is net/http middleware: it verifies the bearer token, then asks Perms.
type Guard struct {
	verifier *Verifier
	perms    *Perms
}

// NewGuard builds a Guard.
func NewGuard(v *Verifier, p *Perms) *Guard { return &Guard{verifier: v, perms: p} }

// RouteOption customizes one guarded route.
type RouteOption func(*routeOptions)

type routeOptions struct {
	mode   Mode
	object ObjectFunc
}

// WithMode sets the route mode. See ModeHint for the restrictions.
func WithMode(m Mode) RouteOption { return func(o *routeOptions) { o.mode = m } }

// WithObjectFunc resolves the object for the route.
func WithObjectFunc(f ObjectFunc) RouteOption { return func(o *routeOptions) { o.object = f } }

type ctxKey struct{}

// UserFromContext returns the verified claims set by Guard.
func UserFromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(Claims)
	return c, ok
}

// DecisionFromContext returns the decision that allowed the request.
func DecisionFromContext(ctx context.Context) (Decision, bool) {
	d, ok := ctx.Value(decisionKey{}).(Decision)
	return d, ok
}

type decisionKey struct{}

// Require returns middleware that lets a request through only when the bearer
// token is valid and the user holds permission. Responses: 401 for a missing or
// invalid token, 403 for a denial, 503 when the live check failed or timed out.
// All of them are denials; nothing falls through to the handler.
func (g *Guard) Require(permission string, opts ...RouteOption) func(http.Handler) http.Handler {
	ro := routeOptions{mode: ModeLive}
	for _, opt := range opts {
		opt(&ro)
	}
	if !ValidPermission(permission) {
		panic("authz: invalid permission name " + permission)
	}
	switch ro.mode {
	case ModeLive:
	case ModeHint:
		if !g.perms.IsRead(permission) {
			panic("authz: ModeHint is only allowed for reads, " + permission + " is a write")
		}
		if ro.object != nil {
			panic("authz: ModeHint cannot be combined with an object")
		}
	default:
		panic("authz: unknown mode " + string(ro.mode))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.serve(w, r, next, permission, ro)
		})
	}
}

// RequireFunc is Require for a single handler function.
func (g *Guard) RequireFunc(permission string, h http.HandlerFunc, opts ...RouteOption) http.Handler {
	return g.Require(permission, opts...)(h)
}

func (g *Guard) serve(w http.ResponseWriter, r *http.Request, next http.Handler, permission string, ro routeOptions) {
	token, ok := bearer(r)
	if !ok {
		deny(w, http.StatusUnauthorized, "unauthorized", true)
		return
	}
	user, err := g.verifier.Verify(r.Context(), token)
	if err != nil {
		deny(w, http.StatusUnauthorized, "unauthorized", true)
		return
	}

	var d Decision
	if ro.mode == ModeHint {
		d = g.hintDecision(user, permission)
	} else {
		var callOpts []Option
		if ro.object != nil {
			if o, has := ro.object(r); has {
				callOpts = append(callOpts, WithObject(o.Type, o.ID))
			}
		}
		d = g.perms.Explain(r.Context(), user, permission, callOpts...)
	}
	if !d.Allowed {
		switch d.Reason { //nolint:exhaustive // every other reason is a plain 403
		case ReasonCheckError, ReasonCheckTimeout:
			deny(w, http.StatusServiceUnavailable, "authorization_unavailable", false)
		default:
			deny(w, http.StatusForbidden, "forbidden", false)
		}
		return
	}
	ctx := context.WithValue(r.Context(), ctxKey{}, user)
	ctx = context.WithValue(ctx, decisionKey{}, d)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// hintDecision runs the claim-only path: token and request checks, then the hint.
func (g *Guard) hintDecision(user Claims, permission string) Decision {
	if reason, ok := g.perms.checkToken(user); !ok {
		return Decision{Reason: reason, Step: StepToken}
	}
	if !Hint(user).Can(permission) {
		return Decision{Reason: ReasonPermissionNotInClaim, Step: StepClaim}
	}
	return Decision{Allowed: true, Reason: ReasonAllowedClaim, Step: StepAllowed}
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	t := strings.TrimSpace(h[len(prefix):])
	return t, t != ""
}

func deny(w http.ResponseWriter, status int, code string, challenge bool) {
	if challenge {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}
