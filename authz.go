// Package authz is the Go SDK for the noid cross-brand authorization contract
// (see the authz-spec repository).
//
// Tokens carry a "permissions" claim that is only a hint. Anything not listed
// under "reads" in the app manifest is a write and is always checked live via
// POST /v1/check. Every error path denies (fail closed).
package authz

import (
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strings"
)

// Reason explains a decision. The values are fixed by the spec.
type Reason string

// Decision reasons, in the order the steps can produce them.
const (
	ReasonAllowedClaim         Reason = "allowed_claim"
	ReasonAllowedLive          Reason = "allowed_live"
	ReasonInvalidIssuer        Reason = "invalid_issuer"
	ReasonInvalidTenant        Reason = "invalid_tenant"
	ReasonInvalidSubject       Reason = "invalid_subject"
	ReasonTokenExpired         Reason = "token_expired"
	ReasonInvalidRequest       Reason = "invalid_request"
	ReasonInvalidObject        Reason = "invalid_object"
	ReasonPermissionNotInClaim Reason = "permission_not_in_claim"
	ReasonDenied               Reason = "denied"
	ReasonObjectDenied         Reason = "object_denied"
	ReasonCheckError           Reason = "check_error"
	ReasonCheckTimeout         Reason = "check_timeout"
)

// Step names the step of the algorithm that produced the decision.
type Step string

// Steps of Perms.Can.
const (
	StepToken          Step = "token"
	StepRequest        Step = "request"
	StepClaim          Step = "claim"
	StepLivePermission Step = "live_permission"
	StepLiveObject     Step = "live_object"
	StepAllowed        Step = "allowed"
)

// Object identifies a resource. The SDK validates it, then the check service
// namespaces it as <brand>/<app>/<type>/<id>.
type Object struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Claims are the already-verified claims of an access token. Values keep their
// decoded JSON types on purpose, so a wrong-typed claim is denied instead of
// being coerced.
type Claims map[string]any

var (
	permissionRe = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)
	typeRe       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	objectIDRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	brandRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	appRe        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

const (
	maxPermissionLen = 64
	// 2^53: largest range where a float64 holds an exact integer.
	maxExactInt = 1 << 53
)

// ValidPermission reports whether name matches <resource>.<action>.
func ValidPermission(name string) bool {
	return len(name) <= maxPermissionLen && permissionRe.MatchString(name)
}

// ValidBrand reports whether s is a tenant slug: ^[a-z0-9][a-z0-9-]{0,62}$.
func ValidBrand(s string) bool { return brandRe.MatchString(s) }

// ValidApp reports whether s is an app segment, i.e. an OAuth client_id (a
// Hydra UUID fits): ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ without "..".
func ValidApp(s string) bool { return appRe.MatchString(s) && !strings.Contains(s, "..") }

// ValidObject reports whether the object type and id match the grammars.
func ValidObject(o Object) bool {
	return typeRe.MatchString(o.Type) &&
		objectIDRe.MatchString(o.ID) && !strings.Contains(o.ID, "..")
}

// ParseKetoObject splits <brand>/<app>/<type>/<id>. It returns ok=false unless
// there are exactly four segments and each is valid under its own grammar.
func ParseKetoObject(s string) (brand, app string, o Object, ok bool) {
	parts := strings.Split(s, "/")
	if len(parts) != 4 {
		return "", "", Object{}, false
	}
	o = Object{Type: parts[2], ID: parts[3]}
	if !ValidBrand(parts[0]) || !ValidApp(parts[1]) || !ValidObject(o) {
		return "", "", Object{}, false
	}
	return parts[0], parts[1], o, true
}

// Link validation reasons, fixed by the spec (Link rules).
const (
	LinkOK             = "ok"
	LinkInvalidObject  = "invalid_object"
	LinkAppMismatch    = "app_mismatch"
	LinkInvalidParent  = "invalid_parent"
	LinkParentMismatch = "parent_mismatch"
)

// ValidateLink checks a Resource tuple: object must be a valid Keto object,
// appLink (the #app subject, without the "App:" prefix) must equal the app
// segment of the object, and parent (empty when absent) must be a valid Keto
// object in the same brand and app. It returns LinkOK or the failing reason,
// checked in the order object, #app, #parent.
func ValidateLink(object, appLink, parent string) (valid bool, reason string) {
	brand, app, _, ok := ParseKetoObject(object)
	if !ok {
		return false, LinkInvalidObject
	}
	if appLink != app {
		return false, LinkAppMismatch
	}
	if parent != "" {
		pb, pa, _, ok := ParseKetoObject(parent)
		if !ok {
			return false, LinkInvalidParent
		}
		if pb != brand || pa != app {
			return false, LinkParentMismatch
		}
	}
	return true, LinkOK
}

// Subject returns the "sub" claim when it is a non-empty string.
func (c Claims) Subject() (string, bool) {
	s, ok := c["sub"].(string)
	return s, ok && s != ""
}

// Issuer returns the "iss" claim when it is a string.
func (c Claims) Issuer() (string, bool) {
	s, ok := c["iss"].(string)
	return s, ok
}

// TenantID returns the "tenant_id" claim when it is a string.
func (c Claims) TenantID() (string, bool) {
	s, ok := c["tenant_id"].(string)
	return s, ok
}

// Expiry returns "exp" as Unix seconds when it is a JSON integer.
func (c Claims) Expiry() (int64, bool) {
	return asInt(c["exp"])
}

// Permissions returns the permissions claim and whether it is an array.
// Non-string entries are kept out of the result and so can never match.
func (c Claims) Permissions() ([]string, bool) {
	switch v := c["permissions"].(type) {
	case []string:
		return v, true
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out, true
	default:
		return nil, false
	}
}

func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if n != math.Trunc(n) || math.Abs(n) > maxExactInt {
			return 0, false
		}
		return int64(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return asInt(f)
	default:
		return 0, false
	}
}

var (
	// ErrTimeout is returned by a Checker when the live call timed out.
	ErrTimeout = errors.New("authz: check timed out")
	// ErrInvalidConfig is wrapped by NewPerms and NewClient when Brand or App
	// do not match their grammars. The spec reason is invalid_config: nothing
	// may be checked with such a config, so it never reaches a live call.
	ErrInvalidConfig = errors.New("authz: invalid config")
	// ErrCheck is returned by a Checker for any other live-call failure.
	ErrCheck = errors.New("authz: check failed")
)
