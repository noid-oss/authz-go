package authz_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	authz "github.com/noid-oss/authz-go"
)

// testdata/vectors.json is a pinned copy of authz-spec/vectors.json.
// Sync with scripts/sync-vectors.sh; never edit by hand.

type vecConfig struct {
	Brand    string `json:"brand"`
	App      string `json:"app"`
	Issuer   string `json:"issuer"`
	TenantID string `json:"tenant_id"`
	Now      int64  `json:"now"`
}

type vecOverride struct {
	Brand    *string `json:"brand"`
	App      *string `json:"app"`
	Issuer   *string `json:"issuer"`
	TenantID *string `json:"tenant_id"`
	Now      *int64  `json:"now"`
}

// vecObject accepts any JSON type for type/id (the vectors include a numeric
// id). A non-string value maps to "", which no grammar accepts, so the SDK
// must deny it as invalid_object.
type vecObject authz.Object

func (o *vecObject) UnmarshalJSON(b []byte) error {
	var raw struct{ Type, ID any }
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	o.Type, _ = raw.Type.(string)
	o.ID, _ = raw.ID.(string)
	return nil
}

type vecCall struct {
	Permission string     `json:"permission"`
	Object     *vecObject `json:"object"`
	KetoObject string     `json:"keto_object"`
}

type vector struct {
	Name     string       `json:"name"`
	Config   *vecOverride `json:"config"`
	Manifest struct {
		Reads     []string        `json:"reads"`
		Resources json.RawMessage `json:"resources"`
	} `json:"manifest"`
	Claims  authz.Claims `json:"claims"`
	Request struct {
		Permission string     `json:"permission"`
		Object     *vecObject `json:"object"`
	} `json:"request"`
	LiveCheck struct {
		Role   string `json:"role"`
		Object string `json:"object"`
	} `json:"liveCheck"`
	Expect struct {
		Allowed   bool         `json:"allowed"`
		Reason    authz.Reason `json:"reason"`
		LiveCalls []vecCall    `json:"liveCalls"`
	} `json:"expect"`
}

type vectorFile struct {
	Version     int          `json:"version"`
	SpecVersion string       `json:"specVersion"`
	Config      vecConfig    `json:"config"`
	Vectors     []vector     `json:"vectors"`
	LinkVectors []linkVector `json:"linkVectors"`
	// RelationVectors and BindingVectors describe the check SERVICE (relation
	// tuples, binding rules), not the SDK. They are decoded only so the file
	// shape is pinned; the SDK does not implement or run them.
	RelationVectors []json.RawMessage `json:"relationVectors"`
	BindingVectors  []json.RawMessage `json:"bindingVectors"`
}

type linkVector struct {
	Name  string `json:"name"`
	Input struct {
		Object string `json:"object"`
		App    string `json:"app"`
		Parent string `json:"parent"`
	} `json:"input"`
	Expect struct {
		Valid  bool   `json:"valid"`
		Reason string `json:"reason"`
	} `json:"expect"`
}

// stubChecker plays back the outcome named by the vector for role/object calls.
type stubChecker struct {
	role, object string
	calls        []authz.CheckRequest
}

func (s *stubChecker) Check(_ context.Context, req authz.CheckRequest) (bool, error) {
	s.calls = append(s.calls, req)
	outcome := s.role
	if req.Object != nil {
		outcome = s.object
	}
	switch outcome {
	case "allow":
		return true, nil
	case "deny":
		return false, nil
	case "timeout":
		return false, fmt.Errorf("%w: stub", authz.ErrTimeout)
	default: // "error", "not_called", "" : an unexpected call fails closed
		return false, fmt.Errorf("%w: stub outcome %q", authz.ErrCheck, outcome)
	}
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile("testdata/vectors.json.sha256")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got, want := hex.EncodeToString(sum[:]), strings.TrimSpace(string(pin)); got != want {
		t.Fatalf("testdata/vectors.json (sha256 %s) does not match the pin %s: run scripts/sync-vectors.sh, do not hand-edit", got, want)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep 1.5 vs 1 vs "1" distinguishable for the exp checks
	var f vectorFile
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 2 || f.SpecVersion != "2.2.0" || len(f.Vectors) == 0 || len(f.LinkVectors) == 0 ||
		len(f.RelationVectors) != 16 || len(f.BindingVectors) != 6 {
		t.Fatalf("unexpected vectors file: version=%d specVersion=%q vectors=%d linkVectors=%d relationVectors=%d bindingVectors=%d",
			f.Version, f.SpecVersion, len(f.Vectors), len(f.LinkVectors), len(f.RelationVectors), len(f.BindingVectors))
	}
	return f
}

func TestVectors(t *testing.T) {
	f := loadVectors(t)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			cfg := f.Config
			if o := v.Config; o != nil {
				if o.Brand != nil {
					cfg.Brand = *o.Brand
				}
				if o.App != nil {
					cfg.App = *o.App
				}
				if o.Issuer != nil {
					cfg.Issuer = *o.Issuer
				}
				if o.TenantID != nil {
					cfg.TenantID = *o.TenantID
				}
				if o.Now != nil {
					cfg.Now = *o.Now
				}
			}
			stub := &stubChecker{role: v.LiveCheck.Role, object: v.LiveCheck.Object}
			p, err := authz.NewPerms(authz.PermsConfig{
				Brand: cfg.Brand, App: cfg.App, Issuer: cfg.Issuer, TenantID: cfg.TenantID,
				Reads: v.Manifest.Reads, Resources: manifestTypes(t, v.Manifest.Resources),
				Checker: stub, Now: func() int64 { return cfg.Now },
			})
			if errors.Is(err, authz.ErrInvalidConfig) {
				// The SDK refuses an invalid brand/app at construction (fail
				// fast); the spec reason for that denial is invalid_config.
				if v.Expect.Allowed || v.Expect.Reason != "invalid_config" || len(v.Expect.LiveCalls) != 0 {
					t.Fatalf("NewPerms rejected the config but the vector expects %+v", v.Expect)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v.Expect.Reason == "invalid_config" {
				t.Fatal("vector expects invalid_config but NewPerms accepted the config")
			}
			var opts []authz.Option
			if o := v.Request.Object; o != nil {
				opts = append(opts, authz.WithObject(o.Type, o.ID))
			}
			d := p.Explain(context.Background(), v.Claims, v.Request.Permission, opts...)

			if d.Allowed != v.Expect.Allowed || d.Reason != v.Expect.Reason {
				t.Fatalf("got allowed=%v reason=%s (step %s), want allowed=%v reason=%s",
					d.Allowed, d.Reason, d.Step, v.Expect.Allowed, v.Expect.Reason)
			}
			if p.Can(context.Background(), v.Claims, v.Request.Permission, opts...) != v.Expect.Allowed {
				t.Fatal("Can disagrees with Explain")
			}
			// Compare only the first run's calls: the stub recorded two runs.
			got := stub.calls[:len(d.LiveCalls)]
			if len(d.LiveCalls) != len(v.Expect.LiveCalls) {
				t.Fatalf("live calls: got %d, want %d (%+v)", len(d.LiveCalls), len(v.Expect.LiveCalls), d.LiveCalls)
			}
			for i, want := range v.Expect.LiveCalls {
				if got[i].Permission != want.Permission || !sameObject(got[i].Object, want.Object) {
					t.Fatalf("live call %d: got %+v, want %+v", i, got[i], want)
				}
				if got[i].Subject == "" {
					t.Fatalf("live call %d has no subject", i)
				}
			}
		})
	}
}

func sameObject(a *authz.Object, b *vecObject) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == authz.Object(*b)
}

func TestLinkVectors(t *testing.T) {
	f := loadVectors(t)
	for _, v := range f.LinkVectors {
		t.Run(v.Name, func(t *testing.T) {
			valid, reason := authz.ValidateLink(v.Input.Object, v.Input.App, v.Input.Parent)
			if valid != v.Expect.Valid || reason != v.Expect.Reason {
				t.Fatalf("got valid=%v reason=%s, want valid=%v reason=%s", valid, reason, v.Expect.Valid, v.Expect.Reason)
			}
		})
	}
}

// manifestTypes reads manifest "resources": a list of types or a map keyed by type.
func manifestTypes(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest resources: %v", err)
	}
	for k := range m {
		list = append(list, k)
	}
	return list
}
