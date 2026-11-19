package authz

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Verification errors. Callers should treat any non-nil error as "not authenticated".
var (
	ErrMalformedToken   = errors.New("authz: malformed token")
	ErrUnknownIssuer    = errors.New("authz: unknown issuer")
	ErrBadSignature     = errors.New("authz: signature verification failed")
	ErrUnsupportedAlg   = errors.New("authz: unsupported algorithm")
	ErrTokenExpired     = errors.New("authz: token expired")
	ErrTokenNotYetValid = errors.New("authz: token not yet valid")
	ErrTenantMismatch   = errors.New("authz: tenant mismatch")
	ErrNoSubject        = errors.New("authz: missing subject")
	ErrKeyNotFound      = errors.New("authz: signing key not found")
)

const (
	defaultJWKSTTL      = 10 * time.Minute
	defaultRefetchAfter = 30 * time.Second
	maxJWKSBody         = 1 << 20
	maxTokenLen         = 16 << 10
	clockSkew           = 0 // exp is strict per spec: exp <= now is expired
)

// Issuer is one trusted token issuer (one per brand).
type Issuer struct {
	// URL must equal the token "iss" exactly.
	URL string
	// JWKSURL is where its signing keys live. Defaults to URL + ".well-known/jwks.json".
	JWKSURL string
}

// VerifierConfig configures a Verifier.
type VerifierConfig struct {
	// Issuers is the known issuer list. A token from any other issuer is rejected.
	Issuers []Issuer
	// TenantID must equal the token tenant_id.
	TenantID string
	// Audience, when set, must be present in the token "aud".
	Audience string
	// Now returns Unix seconds. Defaults to the wall clock.
	Now func() int64
	// HTTPClient fetches JWKS. Defaults to a client with a 5s timeout.
	HTTPClient *http.Client
	// JWKSTTL is how long keys are cached. Default 10 minutes.
	JWKSTTL time.Duration
}

// Verifier checks signature, exp, issuer and tenant of access tokens.
// It is safe for concurrent use.
type Verifier struct {
	cfg     VerifierConfig
	issuers map[string]*keySet
}

type keySet struct {
	url string

	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
	lastTry   time.Time
}

// NewVerifier validates cfg.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if len(cfg.Issuers) == 0 || cfg.TenantID == "" {
		return nil, errors.New("authz: Issuers and TenantID are required")
	}
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.JWKSTTL <= 0 {
		cfg.JWKSTTL = defaultJWKSTTL
	}
	v := &Verifier{cfg: cfg, issuers: make(map[string]*keySet, len(cfg.Issuers))}
	for _, is := range cfg.Issuers {
		if is.URL == "" {
			return nil, errors.New("authz: issuer URL is empty")
		}
		u := is.JWKSURL
		if u == "" {
			u = strings.TrimRight(is.URL, "/") + "/.well-known/jwks.json"
		}
		v.issuers[is.URL] = &keySet{url: u}
	}
	return v, nil
}

// Verify checks the token and returns its claims. Standard claims (iss, sub,
// exp, aud) come from the top level only. Custom claims (tenant_id,
// permissions, roles, acr, ...) come from the top level, falling back to "ext",
// and can never override a standard one.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	if len(token) > maxTokenLen {
		return nil, ErrMalformedToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return nil, ErrMalformedToken
	}
	if hdr.Alg != "RS256" && hdr.Alg != "ES256" {
		return nil, ErrUnsupportedAlg
	}
	claims, err := decodeClaims(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}
	iss, ok := claims.Issuer()
	if !ok {
		return nil, ErrUnknownIssuer
	}
	ks, ok := v.issuers[iss]
	if !ok {
		return nil, ErrUnknownIssuer
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformedToken
	}
	key, err := ks.key(ctx, v.cfg.HTTPClient, hdr.Kid, v.cfg.JWKSTTL)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(hdr.Alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, err
	}
	return v.validate(claims)
}

func (v *Verifier) validate(c Claims) (Claims, error) {
	exp, ok := c.Expiry()
	if !ok || exp+clockSkew <= v.cfg.Now() {
		return nil, ErrTokenExpired
	}
	if nbf, ok := asInt(c["nbf"]); ok && nbf > v.cfg.Now() {
		return nil, ErrTokenNotYetValid
	}
	if _, ok := c.Subject(); !ok {
		return nil, ErrNoSubject
	}
	if v.cfg.Audience != "" && !audienceHas(c["aud"], v.cfg.Audience) {
		return nil, errors.New("authz: audience mismatch")
	}
	if t, ok := c.TenantID(); !ok || t != v.cfg.TenantID {
		return nil, ErrTenantMismatch
	}
	return c, nil
}

func audienceHas(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, e := range a {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

var standardClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {}, "scope": {},
}

// decodeClaims decodes the payload, then merges custom claims from "ext".
func decodeClaims(seg string) (Claims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var c Claims
	if err := dec.Decode(&c); err != nil || c == nil {
		return nil, errors.New("authz: payload is not an object")
	}
	if ext, ok := c["ext"].(map[string]any); ok {
		for k, val := range ext {
			if _, std := standardClaims[k]; std {
				continue
			}
			if _, present := c[k]; !present {
				c[k] = val
			}
		}
	}
	return c, nil
}

// UnverifiedHint reads the permissions claim of a token WITHOUT verifying it.
// Use it only for UI hints (hide a button); never to authorize anything.
func UnverifiedHint(token string) *HintSet {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Hint(nil)
	}
	c, err := decodeClaims(parts[1])
	if err != nil {
		return Hint(nil)
	}
	return Hint(c)
}

func decodeSegment(seg string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
	digest := sha256.Sum256(signed)
	switch k := key.(type) {
	case *rsa.PublicKey:
		if alg == "RS256" && rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil {
			return nil
		}
	case *ecdsa.PublicKey:
		if alg == "ES256" && len(sig) == 64 &&
			ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil
		}
	}
	return ErrBadSignature
}

// key returns the key for kid, refetching the JWKS when it is stale or the kid
// is unknown (at most once per defaultRefetchAfter).
func (ks *keySet) key(ctx context.Context, hc *http.Client, kid string, ttl time.Duration) (crypto.PublicKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	now := time.Now()
	if ks.keys != nil && now.Sub(ks.fetchedAt) < ttl {
		if k, ok := pick(ks.keys, kid); ok {
			return k, nil
		}
	}
	if now.Sub(ks.lastTry) < defaultRefetchAfter && ks.keys != nil {
		if k, ok := pick(ks.keys, kid); ok {
			return k, nil
		}
		return nil, ErrKeyNotFound
	}
	ks.lastTry = now
	keys, err := fetchJWKS(ctx, hc, ks.url)
	if err != nil {
		return nil, err
	}
	ks.keys, ks.fetchedAt = keys, now
	if k, ok := pick(keys, kid); ok {
		return k, nil
	}
	return nil, ErrKeyNotFound
}

// pick finds kid; an empty kid is only accepted when the set has one key.
func pick(keys map[string]crypto.PublicKey, kid string) (crypto.PublicKey, bool) {
	if kid == "" {
		if len(keys) == 1 {
			for _, k := range keys {
				return k, true
			}
		}
		return nil, false
	}
	k, ok := keys[kid]
	return k, ok
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func fetchJWKS(ctx context.Context, hc *http.Client, url string) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("authz: jwks request: %w", err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authz: jwks fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authz: jwks fetch: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBody))
	if err != nil {
		return nil, fmt.Errorf("authz: jwks read: %w", err)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("authz: jwks decode: %w", err)
	}
	keys := make(map[string]crypto.PublicKey, len(set.Keys))
	for i, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.public()
		if err != nil {
			continue // skip keys we cannot use
		}
		id := k.Kid
		if id == "" {
			id = fmt.Sprintf("#%d", i)
		}
		keys[id] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("authz: jwks has no usable keys")
	}
	return keys, nil
}

func (k jwk) public() (crypto.PublicKey, error) {
	b64 := base64.RawURLEncoding
	switch k.Kty {
	case "RSA":
		n, err1 := b64.DecodeString(k.N)
		e, err2 := b64.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("bad rsa key") // >= 2048 bits
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, errors.New("unsupported curve")
		}
		x, err1 := b64.DecodeString(k.X)
		y, err2 := b64.DecodeString(k.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad ec key")
		}
		if len(x) != 32 || len(y) != 32 {
			return nil, errors.New("bad ec coordinates")
		}
		// ParseUncompressedPublicKey rejects points that are not on the curve.
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, append(x, y...)...))
	default:
		return nil, errors.New("unsupported kty")
	}
}
