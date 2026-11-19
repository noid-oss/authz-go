package authz

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// PermsConfig is the static identity of the app the SDK runs in.
type PermsConfig struct {
	// Brand and App are sent with every live call, never taken from callers.
	Brand string
	App   string
	// Issuer must equal the token "iss" exactly.
	Issuer string
	// TenantID must equal the token "tenant_id".
	TenantID string
	// Reads are the permissions decidable from the claim alone (manifest
	// "reads"). Every other permission is a write.
	Reads []string
	// Resources are the object types declared in the manifest "resources".
	// When non-empty, an object whose type is not listed is denied with
	// invalid_object. Empty means any well-formed type is accepted.
	Resources []string
	// Checker performs live checks. Required.
	Checker Checker
	// Now returns Unix seconds. Defaults to the wall clock.
	Now func() int64
}

// Perms evaluates permissions. It is safe for concurrent use.
type Perms struct {
	cfg   PermsConfig
	reads map[string]struct{}
	types map[string]struct{}
}

// NewPerms validates cfg.
func NewPerms(cfg PermsConfig) (*Perms, error) {
	if cfg.Checker == nil {
		return nil, errors.New("authz: Checker is required")
	}
	if !ValidBrand(cfg.Brand) || !ValidApp(cfg.App) {
		return nil, fmt.Errorf("%w: Brand must match ^[a-z0-9][a-z0-9-]{0,62}$ and App (the OAuth client_id) ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ without \"..\"", ErrInvalidConfig)
	}
	if cfg.Issuer == "" || cfg.TenantID == "" {
		return nil, errors.New("authz: Issuer and TenantID are required")
	}
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	reads := make(map[string]struct{}, len(cfg.Reads))
	for _, r := range cfg.Reads {
		reads[r] = struct{}{}
	}
	var types map[string]struct{}
	if len(cfg.Resources) > 0 {
		types = make(map[string]struct{}, len(cfg.Resources))
		for _, t := range cfg.Resources {
			types[t] = struct{}{}
		}
	}
	cfg.Reads, cfg.Resources = nil, nil
	return &Perms{cfg: cfg, reads: reads, types: types}, nil
}

// IsRead reports whether the permission is classified as a read. Everything
// else, including unknown names, is a write.
func (p *Perms) IsRead(permission string) bool {
	_, ok := p.reads[permission]
	return ok
}

// Option customizes one Can / Explain call.
type Option func(*callOptions)

type callOptions struct{ object *Object }

// WithObject scopes the check to one object, e.g. WithObject("invoice", "inv-001").
// A live object check runs even for read permissions.
func WithObject(objectType, id string) Option {
	return func(o *callOptions) { o.object = &Object{Type: objectType, ID: id} }
}

// Decision is the full outcome of a check.
type Decision struct {
	Allowed bool
	Reason  Reason
	// Step is the step that decided (the denying step on a deny).
	Step Step
	// LiveCalls are the live calls made, in order.
	LiveCalls []CheckRequest
	// Err is the underlying live-call error for check_error / check_timeout.
	Err error
}

// Can reports whether the verified user holds permission, optionally on an object.
func (p *Perms) Can(ctx context.Context, user Claims, permission string, opts ...Option) bool {
	return p.Explain(ctx, user, permission, opts...).Allowed
}

// Explain runs the algorithm and returns the step that denied (or allowed).
// Steps run in order and the first failing one stops the evaluation:
//
//  1. token: issuer, tenant, subject, expiry
//  2. request: permission and object grammar
//  3. claim: the permission must be listed in the token hint
//  4. live permission check (writes only)
//  5. live object check (when an object is given)
func (p *Perms) Explain(ctx context.Context, user Claims, permission string, opts ...Option) Decision {
	var o callOptions
	for _, opt := range opts {
		opt(&o)
	}
	d := Decision{}
	deny := func(step Step, reason Reason) Decision {
		d.Allowed, d.Step, d.Reason = false, step, reason
		return d
	}

	if r, ok := p.checkToken(user); !ok {
		return deny(StepToken, r)
	}
	if !ValidPermission(permission) {
		return deny(StepRequest, ReasonInvalidRequest)
	}
	if o.object != nil && !p.validObject(*o.object) {
		return deny(StepRequest, ReasonInvalidObject)
	}
	if !Hint(user).Can(permission) {
		return deny(StepClaim, ReasonPermissionNotInClaim)
	}

	sub, _ := user.Subject()
	if !p.IsRead(permission) {
		d.LiveCalls = append(d.LiveCalls, CheckRequest{Permission: permission, Subject: sub})
		if r, step, ok := p.live(ctx, &d, StepLivePermission, ReasonDenied); !ok {
			return deny(step, r)
		}
	}
	if o.object != nil {
		obj := *o.object
		d.LiveCalls = append(d.LiveCalls, CheckRequest{Permission: permission, Subject: sub, Object: &obj})
		if r, step, ok := p.live(ctx, &d, StepLiveObject, ReasonObjectDenied); !ok {
			return deny(step, r)
		}
	}

	d.Allowed, d.Step = true, StepAllowed
	d.Reason = ReasonAllowedClaim
	if len(d.LiveCalls) > 0 {
		d.Reason = ReasonAllowedLive
	}
	return d
}

// live runs the last call appended to d.LiveCalls.
func (p *Perms) live(ctx context.Context, d *Decision, step Step, denied Reason) (Reason, Step, bool) {
	req := d.LiveCalls[len(d.LiveCalls)-1]
	allowed, err := p.cfg.Checker.Check(ctx, req)
	switch {
	case err != nil:
		d.Err = err
		if errors.Is(err, ErrTimeout) {
			return ReasonCheckTimeout, step, false
		}
		return ReasonCheckError, step, false
	case !allowed:
		return denied, step, false
	default:
		return "", step, true
	}
}

func (p *Perms) checkToken(c Claims) (Reason, bool) {
	if iss, ok := c.Issuer(); !ok || iss != p.cfg.Issuer {
		return ReasonInvalidIssuer, false
	}
	if t, ok := c.TenantID(); !ok || t != p.cfg.TenantID {
		return ReasonInvalidTenant, false
	}
	if _, ok := c.Subject(); !ok {
		return ReasonInvalidSubject, false
	}
	if exp, ok := c.Expiry(); !ok || exp <= p.cfg.Now() {
		return ReasonTokenExpired, false
	}
	return "", true
}

// validObject applies the grammar plus the declared resource types, if any.
func (p *Perms) validObject(o Object) bool {
	if !ValidObject(o) {
		return false
	}
	if p.types != nil {
		_, ok := p.types[o.Type]
		return ok
	}
	return true
}
