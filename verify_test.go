package authz_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authz "github.com/noid-oss/authz-go"
)

const (
	testNow    = int64(1800000000)
	issIDBI    = "https://auth.idbi.example/"
	issOther   = "https://auth.other.example/"
	testTenant = "idbi"
)

var b64 = base64.RawURLEncoding

type signer struct {
	kid string
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

func newRSASigner(t *testing.T, kid string) *signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{kid: kid, rsa: k}
}

func newECSigner(t *testing.T, kid string) *signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{kid: kid, ec: k}
}

func (s *signer) jwk() map[string]string {
	if s.rsa != nil {
		return map[string]string{
			"kty": "RSA", "kid": s.kid, "use": "sig", "alg": "RS256",
			"n": b64.EncodeToString(s.rsa.N.Bytes()),
			"e": b64.EncodeToString(big.NewInt(int64(s.rsa.E)).Bytes()),
		}
	}
	return map[string]string{
		"kty": "EC", "kid": s.kid, "use": "sig", "alg": "ES256", "crv": "P-256",
		"x": b64.EncodeToString(s.ec.X.FillBytes(make([]byte, 32))),
		"y": b64.EncodeToString(s.ec.Y.FillBytes(make([]byte, 32))),
	}
}

func (s *signer) sign(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	if header == nil {
		header = map[string]any{}
	}
	if _, ok := header["alg"]; !ok {
		header["alg"] = map[bool]string{true: "RS256", false: "ES256"}[s.rsa != nil]
	}
	if _, ok := header["kid"]; !ok {
		header["kid"] = s.kid
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	signed := b64.EncodeToString(hb) + "." + b64.EncodeToString(pb)
	digest := sha256.Sum256([]byte(signed))
	var sig []byte
	var err error
	if s.rsa != nil {
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.rsa, crypto.SHA256, digest[:])
	} else {
		var r, ss *big.Int
		r, ss, err = ecdsa.Sign(rand.Reader, s.ec, digest[:])
		sig = append(r.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...)
	}
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + b64.EncodeToString(sig)
}

func jwksServer(t *testing.T, keys ...*signer) (*httptest.Server, *int) {
	t.Helper()
	hits := new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*hits++
		var list []map[string]string
		for _, k := range keys {
			list = append(list, k.jwk())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": list})
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

func goodClaims() map[string]any {
	return map[string]any{
		"iss": issIDBI, "sub": "ana", "tenant_id": testTenant,
		"exp": testNow + 600, "permissions": []string{"invoice.view"},
	}
}

func newVerifier(t *testing.T, srv *httptest.Server) *authz.Verifier {
	t.Helper()
	v, err := authz.NewVerifier(authz.VerifierConfig{
		Issuers:  []authz.Issuer{{URL: issIDBI, JWKSURL: srv.URL}},
		TenantID: testTenant,
		Now:      func() int64 { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func with(m map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for kk, vv := range m {
		out[kk] = vv
	}
	if v == nil {
		delete(out, k)
	} else {
		out[k] = v
	}
	return out
}

func TestVerify(t *testing.T) {
	rs := newRSASigner(t, "rs1")
	es := newECSigner(t, "es1")
	rogue := newRSASigner(t, "rs1") // same kid, different key
	srv, _ := jwksServer(t, rs, es)
	v := newVerifier(t, srv)

	cases := []struct {
		name  string
		token func() string
		err   error // nil = valid
	}{
		{"rs256 ok", func() string { return rs.sign(t, nil, goodClaims()) }, nil},
		{"es256 ok", func() string { return es.sign(t, nil, goodClaims()) }, nil},
		{"wrong key same kid", func() string { return rogue.sign(t, nil, goodClaims()) }, authz.ErrBadSignature},
		{"unknown kid", func() string { return rs.sign(t, map[string]any{"kid": "nope"}, goodClaims()) }, authz.ErrKeyNotFound},
		{"alg none", func() string {
			h, _ := json.Marshal(map[string]any{"alg": "none"})
			p, _ := json.Marshal(goodClaims())
			return b64.EncodeToString(h) + "." + b64.EncodeToString(p) + "."
		}, authz.ErrUnsupportedAlg},
		{"alg HS256 with public key as secret", func() string {
			h, _ := json.Marshal(map[string]any{"alg": "HS256", "kid": "rs1"})
			p, _ := json.Marshal(goodClaims())
			signed := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
			m := hmac.New(sha256.New, rs.rsa.N.Bytes())
			m.Write([]byte(signed))
			return signed + "." + b64.EncodeToString(m.Sum(nil))
		}, authz.ErrUnsupportedAlg},
		{"alg confusion: header ES256 on rsa key", func() string {
			return rs.sign(t, map[string]any{"alg": "ES256"}, goodClaims())
		}, authz.ErrBadSignature},
		{"expired", func() string { return rs.sign(t, nil, with(goodClaims(), "exp", testNow)) }, authz.ErrTokenExpired},
		{"missing exp", func() string { return rs.sign(t, nil, with(goodClaims(), "exp", nil)) }, authz.ErrTokenExpired},
		{"exp is a string", func() string { return rs.sign(t, nil, with(goodClaims(), "exp", "1800000600")) }, authz.ErrTokenExpired},
		{"not yet valid", func() string { return rs.sign(t, nil, with(goodClaims(), "nbf", testNow+10)) }, authz.ErrTokenNotYetValid},
		{"unknown issuer", func() string { return rs.sign(t, nil, with(goodClaims(), "iss", issOther)) }, authz.ErrUnknownIssuer},
		{"issuer without trailing slash", func() string {
			return rs.sign(t, nil, with(goodClaims(), "iss", strings.TrimSuffix(issIDBI, "/")))
		}, authz.ErrUnknownIssuer},
		{"missing issuer", func() string { return rs.sign(t, nil, with(goodClaims(), "iss", nil)) }, authz.ErrUnknownIssuer},
		{"wrong tenant", func() string { return rs.sign(t, nil, with(goodClaims(), "tenant_id", "acme")) }, authz.ErrTenantMismatch},
		{"missing tenant", func() string { return rs.sign(t, nil, with(goodClaims(), "tenant_id", nil)) }, authz.ErrTenantMismatch},
		{"missing sub", func() string { return rs.sign(t, nil, with(goodClaims(), "sub", nil)) }, authz.ErrNoSubject},
		{"empty sub", func() string { return rs.sign(t, nil, with(goodClaims(), "sub", "")) }, authz.ErrNoSubject},
		{"garbage", func() string { return "not-a-jwt" }, authz.ErrMalformedToken},
		{"empty", func() string { return "" }, authz.ErrMalformedToken},
		{"tampered payload", func() string {
			parts := strings.Split(rs.sign(t, nil, goodClaims()), ".")
			p, _ := json.Marshal(with(goodClaims(), "sub", "mallory"))
			return parts[0] + "." + b64.EncodeToString(p) + "." + parts[2]
		}, authz.ErrBadSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := v.Verify(context.Background(), tc.token())
			if tc.err == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if s, _ := claims.Subject(); s != "ana" {
					t.Fatalf("sub=%q", s)
				}
				return
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("err=%v, want %v", err, tc.err)
			}
			if claims != nil {
				t.Fatal("claims returned alongside an error")
			}
		})
	}
}

func TestVerifyExtFallbackNeverOverridesStandard(t *testing.T) {
	rs := newRSASigner(t, "rs1")
	srv, _ := jwksServer(t, rs)
	v := newVerifier(t, srv)

	p := goodClaims()
	delete(p, "tenant_id")
	delete(p, "permissions")
	p["ext"] = map[string]any{
		"tenant_id": testTenant, "permissions": []string{"invoice.view"},
		"sub": "mallory", "exp": testNow + 99999, "iss": issOther,
	}
	claims, err := v.Verify(context.Background(), rs.sign(t, nil, p))
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := claims.Subject(); s != "ana" {
		t.Fatalf("ext overrode sub: %q", s)
	}
	if exp, _ := claims.Expiry(); exp != testNow+600 {
		t.Fatalf("ext overrode exp: %d", exp)
	}
	if !authz.Hint(claims).Can("invoice.view") {
		t.Fatal("permissions not read from ext")
	}

	// A standard claim only in ext is not a standard claim.
	p2 := goodClaims()
	delete(p2, "sub")
	p2["ext"] = map[string]any{"sub": "mallory"}
	if _, err := v.Verify(context.Background(), rs.sign(t, nil, p2)); !errors.Is(err, authz.ErrNoSubject) {
		t.Fatalf("err=%v, want ErrNoSubject", err)
	}
}

func TestVerifyKnownIssuerList(t *testing.T) {
	a := newRSASigner(t, "k")
	b := newRSASigner(t, "k")
	srvA, _ := jwksServer(t, a)
	srvB, _ := jwksServer(t, b)
	v, err := authz.NewVerifier(authz.VerifierConfig{
		Issuers: []authz.Issuer{
			{URL: issIDBI, JWKSURL: srvA.URL},
			{URL: issOther, JWKSURL: srvB.URL},
		},
		TenantID: testTenant, Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), a.sign(t, nil, goodClaims())); err != nil {
		t.Fatalf("issuer A: %v", err)
	}
	if _, err := v.Verify(context.Background(), b.sign(t, nil, with(goodClaims(), "iss", issOther))); err != nil {
		t.Fatalf("issuer B: %v", err)
	}
	// B's key must not validate a token claiming A's issuer.
	if _, err := v.Verify(context.Background(), b.sign(t, nil, goodClaims())); !errors.Is(err, authz.ErrBadSignature) {
		t.Fatalf("cross-issuer err=%v", err)
	}
}

func TestVerifyJWKSCachingAndRotation(t *testing.T) {
	old := newRSASigner(t, "old")
	srv, hits := jwksServer(t, old)
	v := newVerifier(t, srv)
	for range 3 {
		if _, err := v.Verify(context.Background(), old.sign(t, nil, goodClaims())); err != nil {
			t.Fatal(err)
		}
	}
	if *hits != 1 {
		t.Fatalf("jwks fetched %d times, want 1 (cached)", *hits)
	}
	// Unknown kid right after a fetch must not hammer the JWKS endpoint.
	attacker := newRSASigner(t, "unknown")
	for range 5 {
		_, _ = v.Verify(context.Background(), attacker.sign(t, nil, goodClaims()))
	}
	if *hits != 1 {
		t.Fatalf("unknown kid triggered refetch: %d hits", *hits)
	}
}

func TestVerifyJWKSFailureFailsClosed(t *testing.T) {
	rs := newRSASigner(t, "rs1")
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()
	if _, err := newVerifier(t, down).Verify(context.Background(), rs.sign(t, nil, goodClaims())); err == nil {
		t.Fatal("expected error when JWKS is unavailable")
	}
}

func TestVerifyAudience(t *testing.T) {
	rs := newRSASigner(t, "rs1")
	srv, _ := jwksServer(t, rs)
	v, err := authz.NewVerifier(authz.VerifierConfig{
		Issuers:  []authz.Issuer{{URL: issIDBI, JWKSURL: srv.URL}},
		TenantID: testTenant, Audience: "billing", Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	for aud, ok := range map[string]bool{"billing": true, "other": false} {
		_, err := v.Verify(context.Background(), rs.sign(t, nil, with(goodClaims(), "aud", aud)))
		if (err == nil) != ok {
			t.Errorf("aud=%s err=%v", aud, err)
		}
	}
	if _, err := v.Verify(context.Background(), rs.sign(t, nil, with(goodClaims(), "aud", []string{"x", "billing"}))); err != nil {
		t.Errorf("aud array: %v", err)
	}
	if _, err := v.Verify(context.Background(), rs.sign(t, nil, goodClaims())); err == nil {
		t.Error("missing aud must be rejected when Audience is set")
	}
}

func TestNewVerifierValidation(t *testing.T) {
	if _, err := authz.NewVerifier(authz.VerifierConfig{TenantID: "x"}); err == nil {
		t.Error("no issuers: expected error")
	}
	if _, err := authz.NewVerifier(authz.VerifierConfig{Issuers: []authz.Issuer{{URL: "x"}}}); err == nil {
		t.Error("no tenant: expected error")
	}
}

func TestUnverifiedHint(t *testing.T) {
	rs := newRSASigner(t, "rs1")
	tok := rs.sign(t, nil, goodClaims())
	h := authz.UnverifiedHint(tok)
	if !h.Can("invoice.view") || h.Can("invoice.print") || h.Can("invoice.*") {
		t.Fatal("hint mismatch")
	}
	if authz.UnverifiedHint("garbage").Can("invoice.view") {
		t.Fatal("garbage token must hint nothing")
	}
}
