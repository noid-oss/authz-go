package authz_test

import (
	"context"
	"strings"
	"testing"

	authz "github.com/noid-oss/authz-go"
)

func newPerms(t *testing.T, stub *stubChecker) *authz.Perms {
	t.Helper()
	p, err := authz.NewPerms(authz.PermsConfig{
		Brand: "idbi", App: "billing", Issuer: issIDBI, TenantID: testTenant,
		Reads: []string{"invoice.view"}, Checker: stub, Now: func() int64 { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExplainReportsDenyingStep(t *testing.T) {
	user := authz.Claims(goodClaims())
	user["permissions"] = []any{"invoice.view", "invoice.print"}
	cases := []struct {
		name   string
		user   authz.Claims
		perm   string
		opts   []authz.Option
		role   string
		object string
		step   authz.Step
		reason authz.Reason
	}{
		{"token", authz.Claims(with(goodClaims(), "iss", "x")), "invoice.view", nil, "", "", authz.StepToken, authz.ReasonInvalidIssuer},
		{"request", user, "Invoice.view", nil, "", "", authz.StepRequest, authz.ReasonInvalidRequest},
		{"bad object", user, "invoice.view", []authz.Option{authz.WithObject("invoice", "a/b")}, "", "", authz.StepRequest, authz.ReasonInvalidObject},
		{"claim", user, "invoice.void", nil, "allow", "", authz.StepClaim, authz.ReasonPermissionNotInClaim},
		{"live permission", user, "invoice.print", nil, "deny", "", authz.StepLivePermission, authz.ReasonDenied},
		{"live object", user, "invoice.print", []authz.Option{authz.WithObject("invoice", "inv-1")}, "allow", "deny", authz.StepLiveObject, authz.ReasonObjectDenied},
		{"read object", user, "invoice.view", []authz.Option{authz.WithObject("invoice", "inv-1")}, "", "deny", authz.StepLiveObject, authz.ReasonObjectDenied},
		{"timeout", user, "invoice.print", nil, "timeout", "", authz.StepLivePermission, authz.ReasonCheckTimeout},
		{"allowed", user, "invoice.view", nil, "", "", authz.StepAllowed, authz.ReasonAllowedClaim},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newPerms(t, &stubChecker{role: tc.role, object: tc.object}).Explain(context.Background(), tc.user, tc.perm, tc.opts...)
			if d.Step != tc.step || d.Reason != tc.reason {
				t.Fatalf("step=%s reason=%s, want %s/%s", d.Step, d.Reason, tc.step, tc.reason)
			}
			if d.Allowed != (tc.step == authz.StepAllowed) {
				t.Fatalf("allowed=%v", d.Allowed)
			}
		})
	}
}

func TestUnknownPermissionIsAWrite(t *testing.T) {
	p := newPerms(t, &stubChecker{role: "deny"})
	if p.IsRead("invoice.typo") || p.IsRead("invoice.print") || !p.IsRead("invoice.view") {
		t.Fatal("read classification wrong")
	}
}

func TestHintIsExactMatch(t *testing.T) {
	h := authz.Hint(authz.Claims{"permissions": []any{"invoice.view", 7, nil}})
	if !h.Can("invoice.view") || h.Can("invoice.*") || h.Can("*") || h.Can("invoice.print") || h.Can("") {
		t.Fatal("hint must be exact")
	}
	for _, c := range []authz.Claims{nil, {}, {"permissions": "invoice.view"}, {"permissions": nil}} {
		if authz.Hint(c).Can("invoice.view") {
			t.Fatalf("claims %v must hint nothing", c)
		}
	}
}

func TestNewPermsValidation(t *testing.T) {
	ok := authz.PermsConfig{Brand: "idbi", App: "billing", Issuer: "i", TenantID: "t", Checker: &stubChecker{}}
	if _, err := authz.NewPerms(ok); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*authz.PermsConfig){
		"no checker": func(c *authz.PermsConfig) { c.Checker = nil },
		"bad brand":  func(c *authz.PermsConfig) { c.Brand = "A/B" },
		"no issuer":  func(c *authz.PermsConfig) { c.Issuer = "" },
		"no tenant":  func(c *authz.PermsConfig) { c.TenantID = "" },
	} {
		c := ok
		mut(&c)
		if _, err := authz.NewPerms(c); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestConfigGrammar(t *testing.T) {
	uuid := "3f2b8c1e-9a4d-4e57-b6a0-1c2d3e4f5a6b"
	cases := []struct {
		brand, app string
		ok         bool
	}{
		{"idbi", "billing", true},
		{"1acme", uuid, true},
		{"idbi", "Client.ID_1-x", true},
		{"Idbi", "billing", false},
		{"idbi", "a..b", false},
		{"idbi", "a/b", false},
		{"idbi", "-x", false},
		{strings.Repeat("a", 64), "billing", false},
		{strings.Repeat("a", 63), strings.Repeat("A", 129), false},
	}
	for _, c := range cases {
		_, err := authz.NewPerms(authz.PermsConfig{
			Brand: c.brand, App: c.app, Issuer: "i", TenantID: "t", Checker: nopChecker{},
		})
		if (err == nil) != c.ok {
			t.Errorf("brand=%q app=%q: err=%v, want ok=%v", c.brand, c.app, err, c.ok)
		}
	}
}

type nopChecker struct{}

func (nopChecker) Check(context.Context, authz.CheckRequest) (bool, error) { return false, nil }
