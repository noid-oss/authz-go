package authz_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	authz "github.com/noid-oss/authz-go"
)

type guardEnv struct {
	signer  *signer
	guard   *authz.Guard
	checker *stubChecker
}

func newGuardEnv(t *testing.T, role, object string) *guardEnv {
	t.Helper()
	s := newRSASigner(t, "rs1")
	srv, _ := jwksServer(t, s)
	stub := &stubChecker{role: role, object: object}
	p, err := authz.NewPerms(authz.PermsConfig{
		Brand: "idbi", App: "billing", Issuer: issIDBI, TenantID: testTenant,
		Reads: []string{"invoice.view"}, Checker: stub, Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &guardEnv{signer: s, guard: authz.NewGuard(newVerifier(t, srv), p), checker: stub}
}

func (e *guardEnv) do(t *testing.T, h http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/invoices/inv-001/print", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func claimsWith(perms ...string) map[string]any { return with(goodClaims(), "permissions", perms) }

func TestGuardWriteIsCheckedLiveByDefault(t *testing.T) {
	cases := []struct {
		name   string
		role   string
		token  func(e *guardEnv) string
		status int
		live   int
	}{
		{"allowed", "allow", func(e *guardEnv) string { return e.signer.sign(t, nil, claimsWith("invoice.print")) }, 200, 1},
		{"keto denies although claim has it", "deny", func(e *guardEnv) string { return e.signer.sign(t, nil, claimsWith("invoice.print")) }, 403, 1},
		{"keto error fails closed", "error", func(e *guardEnv) string { return e.signer.sign(t, nil, claimsWith("invoice.print")) }, 503, 1},
		{"keto timeout fails closed", "timeout", func(e *guardEnv) string { return e.signer.sign(t, nil, claimsWith("invoice.print")) }, 503, 1},
		{"not in claim: no live call", "allow", func(e *guardEnv) string { return e.signer.sign(t, nil, claimsWith("invoice.view")) }, 403, 0},
		{"no token", "allow", func(*guardEnv) string { return "" }, 401, 0},
		{"bad signature", "allow", func(*guardEnv) string {
			return newRSASigner(t, "rs1").sign(t, nil, claimsWith("invoice.print"))
		}, 401, 0},
		{"expired", "allow", func(e *guardEnv) string {
			return e.signer.sign(t, nil, with(claimsWith("invoice.print"), "exp", testNow-1))
		}, 401, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newGuardEnv(t, tc.role, "allow")
			reached := false
			h := e.guard.Require("invoice.print")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				reached = true
				if u, ok := authz.UserFromContext(r.Context()); !ok || u["sub"] != "ana" {
					t.Error("user missing from context")
				}
				if d, ok := authz.DecisionFromContext(r.Context()); !ok || d.Reason != authz.ReasonAllowedLive {
					t.Errorf("decision=%+v", d)
				}
			}))
			rec := e.do(t, h, tc.token(e))
			wantStatus := tc.status
			if wantStatus == 200 && !reached {
				t.Fatalf("status=%d, handler not reached", rec.Code)
			}
			if wantStatus != 200 && reached {
				t.Fatal("handler reached on a deny")
			}
			if wantStatus != 200 && rec.Code != wantStatus {
				t.Fatalf("status=%d want %d", rec.Code, wantStatus)
			}
			if len(e.checker.calls) != tc.live {
				t.Fatalf("live calls=%d want %d", len(e.checker.calls), tc.live)
			}
		})
	}
}

func TestGuardReadDefaultsToClaimAndObjectIsLive(t *testing.T) {
	e := newGuardEnv(t, "error", "allow") // role call would fail, object call allows
	obj := func(*http.Request) (authz.Object, bool) { return authz.Object{Type: "invoice", ID: "inv-001"}, true }
	h := e.guard.Require("invoice.view", authz.WithObjectFunc(obj))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rec := e.do(t, h, e.signer.sign(t, nil, claimsWith("invoice.view")))
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	if len(e.checker.calls) != 1 || e.checker.calls[0].Object == nil {
		t.Fatalf("calls=%+v, want one object call", e.checker.calls)
	}
}

func TestGuardInvalidObjectFromResolverDenies(t *testing.T) {
	e := newGuardEnv(t, "allow", "allow")
	obj := func(*http.Request) (authz.Object, bool) { return authz.Object{Type: "invoice", ID: "../other/x"}, true }
	h := e.guard.Require("invoice.print", authz.WithObjectFunc(obj))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler reached")
	}))
	if rec := e.do(t, h, e.signer.sign(t, nil, claimsWith("invoice.print"))); rec.Code != 403 {
		t.Fatalf("status=%d", rec.Code)
	}
	if len(e.checker.calls) != 0 {
		t.Fatal("invalid object reached the checker")
	}
}

func TestGuardHintModeReadsOnly(t *testing.T) {
	e := newGuardEnv(t, "error", "error")
	ok := e.guard.Require("invoice.view", authz.WithMode(authz.ModeHint))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if rec := e.do(t, ok, e.signer.sign(t, nil, claimsWith("invoice.view"))); rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	if rec := e.do(t, ok, e.signer.sign(t, nil, claimsWith())); rec.Code != 403 {
		t.Fatalf("missing hint: status=%d", rec.Code)
	}
	if len(e.checker.calls) != 0 {
		t.Fatal("hint mode made a live call")
	}

	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: expected panic", name)
			}
		}()
		f()
	}
	mustPanic("write in hint mode", func() { e.guard.Require("invoice.print", authz.WithMode(authz.ModeHint)) })
	mustPanic("unknown permission in hint mode", func() { e.guard.Require("invoice.typo", authz.WithMode(authz.ModeHint)) })
	mustPanic("object in hint mode", func() {
		e.guard.Require("invoice.view", authz.WithMode(authz.ModeHint),
			authz.WithObjectFunc(func(*http.Request) (authz.Object, bool) { return authz.Object{}, false }))
	})
	mustPanic("bad mode", func() { e.guard.Require("invoice.view", authz.WithMode("whatever")) })
	mustPanic("bad permission name", func() { e.guard.Require("Invoice") })
}

func TestGuardHintModeStillChecksTokenClaims(t *testing.T) {
	e := newGuardEnv(t, "allow", "allow")
	h := e.guard.Require("invoice.view", authz.WithMode(authz.ModeHint))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	// Right issuer for the verifier but a tenant the Perms rejects cannot happen via
	// Verify, so check the path through an expired-at-guard-time token instead.
	tok := e.signer.sign(t, nil, with(claimsWith("invoice.view"), "exp", testNow-5))
	if rec := e.do(t, h, tok); rec.Code != 401 {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestGuardBearerParsing(t *testing.T) {
	e := newGuardEnv(t, "allow", "allow")
	h := e.guard.Require("invoice.view", authz.WithMode(authz.ModeHint))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tok := e.signer.sign(t, nil, claimsWith("invoice.view"))
	for header, want := range map[string]int{
		"Bearer " + tok: 200, "bearer " + tok: 200, "Basic " + tok: 401, tok: 401, "Bearer ": 401, "": 401,
	} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("header %.12q: status=%d want %d", header, rec.Code, want)
		}
	}
	// 401 carries a challenge.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate")
	}
}
