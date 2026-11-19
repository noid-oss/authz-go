package authz_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	authz "github.com/noid-oss/authz-go"
)

func newClient(t *testing.T, h http.HandlerFunc, timeout time.Duration) (*authz.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := authz.NewClient(authz.ClientConfig{
		BaseURL: srv.URL, Brand: "idbi", App: "billing", Credential: "s3cret", Timeout: timeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

func TestClientCheckTable(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		allowed bool
		errIs   error // nil means no error expected
	}{
		{"allow", 200, `{"allowed":true,"reason":"allowed"}`, true, nil},
		{"deny", 200, `{"allowed":false,"reason":"denied"}`, false, nil},
		{"unknown permission", 200, `{"allowed":false,"reason":"unknown_permission"}`, false, nil},
		{"allowed is a string", 200, `{"allowed":"true"}`, false, authz.ErrCheck},
		{"allowed is 1", 200, `{"allowed":1}`, false, authz.ErrCheck},
		{"allowed missing", 200, `{"reason":"allowed"}`, false, authz.ErrCheck},
		{"allowed null", 200, `{"allowed":null}`, false, authz.ErrCheck},
		{"body not an object", 200, `[true]`, false, authz.ErrCheck},
		{"body null", 200, `null`, false, authz.ErrCheck},
		{"invalid json", 200, `{`, false, authz.ErrCheck},
		{"empty body", 200, ``, false, authz.ErrCheck},
		{"201 with allow", 201, `{"allowed":true}`, false, authz.ErrCheck},
		{"400", 400, `{"error":"invalid_request"}`, false, authz.ErrCheck},
		{"401", 401, `{"error":"unauthorized"}`, false, authz.ErrCheck},
		{"403 even with allowed true", 403, `{"allowed":true}`, false, authz.ErrCheck},
		{"429", 429, ``, false, authz.ErrCheck},
		{"500", 500, ``, false, authz.ErrCheck},
		{"502", 502, ``, false, authz.ErrCheck},
		{"503", 503, ``, false, authz.ErrCheck},
		{"504", 504, ``, false, authz.ErrCheck},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c, _ := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}, time.Second)
			got, err := c.Check(context.Background(), authz.CheckRequest{Permission: "invoice.print", Subject: "ana"})
			if got != tc.allowed {
				t.Fatalf("allowed=%v want %v (err=%v)", got, tc.allowed, err)
			}
			if (tc.errIs == nil && err != nil) || (tc.errIs != nil && !errors.Is(err, tc.errIs)) {
				t.Fatalf("err=%v want %v", err, tc.errIs)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls=%d, must not retry", calls.Load())
			}
		})
	}
}

func TestClientSendsWireRequest(t *testing.T) {
	var got map[string]any
	var auth, ctype, method, path string
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		auth, ctype, method, path = r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Method, r.URL.Path
		got = nil
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"allowed":true,"reason":"allowed"}`))
	}, time.Second)

	ok, err := c.Check(context.Background(), authz.CheckRequest{
		Permission: "invoice.print", Subject: "ana", Object: &authz.Object{Type: "invoice", ID: "inv-001"},
	})
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if method != http.MethodPost || path != "/v1/check" || auth != "Bearer s3cret" || ctype != "application/json" {
		t.Fatalf("bad request: %s %s auth=%q ctype=%q", method, path, auth, ctype)
	}
	want := map[string]any{
		"brand": "idbi", "app": "billing", "subject": "ana", "permission": "invoice.print",
		"object": map[string]any{"type": "invoice", "id": "inv-001"},
	}
	wb, _ := json.Marshal(want)
	gb, _ := json.Marshal(got)
	if string(wb) != string(gb) {
		t.Fatalf("body %s, want %s", gb, wb)
	}

	// Without an object the key is absent.
	_, _ = c.Check(context.Background(), authz.CheckRequest{Permission: "invoice.print", Subject: "ana"})
	if _, has := got["object"]; has {
		t.Fatalf("object must be omitted: %v", got)
	}
}

func TestClientTimeoutIsTimeoutError(t *testing.T) {
	release := make(chan struct{})
	c, _ := newClient(t, func(http.ResponseWriter, *http.Request) { <-release }, 50*time.Millisecond)
	defer close(release)
	start := time.Now()
	ok, err := c.Check(context.Background(), authz.CheckRequest{Permission: "invoice.print", Subject: "ana"})
	if ok || !errors.Is(err, authz.ErrTimeout) {
		t.Fatalf("ok=%v err=%v, want ErrTimeout", ok, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("did not time out promptly")
	}
}

func TestClientNetworkErrorIsCheckError(t *testing.T) {
	c, srv := newClient(t, func(http.ResponseWriter, *http.Request) {}, time.Second)
	srv.Close()
	ok, err := c.Check(context.Background(), authz.CheckRequest{Permission: "invoice.print", Subject: "ana"})
	if ok || !errors.Is(err, authz.ErrCheck) {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}))
	defer target.Close()
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}, time.Second)
	ok, err := c.Check(context.Background(), authz.CheckRequest{Permission: "invoice.print", Subject: "ana"})
	if ok || err == nil || hits.Load() != 0 {
		t.Fatalf("ok=%v err=%v redirectHits=%d", ok, err, hits.Load())
	}
}

func TestClientNoCacheForWrites(t *testing.T) {
	var calls atomic.Int32
	c, _ := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}, time.Second)
	for range 3 {
		_, _ = c.Check(context.Background(), authz.CheckRequest{Permission: "invoice.print", Subject: "ana"})
	}
	if calls.Load() != 3 {
		t.Fatalf("calls=%d, want 3 (no cache)", calls.Load())
	}
}

func TestClientRejectsInvalidInputWithoutNetwork(t *testing.T) {
	var calls atomic.Int32
	c, _ := newClient(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) }, time.Second)
	bad := []authz.CheckRequest{
		{Permission: "Invoice.print", Subject: "ana"},
		{Permission: "invoice.print", Subject: ""},
		{Permission: "invoice.print", Subject: "ana", Object: &authz.Object{Type: "invoice", ID: "../x"}},
	}
	for _, r := range bad {
		if ok, err := c.Check(context.Background(), r); ok || err == nil {
			t.Fatalf("%+v: ok=%v err=%v", r, ok, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input reached the network")
	}
}

func TestNewClientValidation(t *testing.T) {
	for name, cfg := range map[string]authz.ClientConfig{
		"no url":    {Brand: "idbi", App: "billing", Credential: "x"},
		"no cred":   {BaseURL: "http://x", Brand: "idbi", App: "billing"},
		"bad brand": {BaseURL: "http://x", Brand: "IDBI", App: "billing", Credential: "x"},
		"bad app":   {BaseURL: "http://x", Brand: "idbi", App: "a/b", Credential: "x"},
	} {
		if _, err := authz.NewClient(cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
