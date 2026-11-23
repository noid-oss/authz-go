# authz-go

> **Status: 0.1.0, early.** Tested against the spec vectors with stubbed HTTP and local keys. It has not been run against a real `/v1/check` service or a real Hydra JWKS endpoint yet. Pin the version and expect breaking changes before 1.0.

Go SDK for the noid cross-brand authorization contract defined in `authz-spec`. Standard library only, no third-party dependencies.

- One account across brands, one issuer per brand.
- Keto is the permission store. Apps never call keto-read; they call `POST /v1/check`.
- The token `permissions` claim is a hint. Anything not listed under `reads` in the app manifest is a write and is always checked live. Every error or timeout denies.

```
go get github.com/noid-oss/authz-go
```

## Setup

```go
verifier, _ := authz.NewVerifier(authz.VerifierConfig{
    Issuers:  []authz.Issuer{{URL: "https://auth.idbi.example/"}}, // known issuers; JWKS at <iss>/.well-known/jwks.json
    TenantID: "idbi",
})

checker, _ := authz.NewClient(authz.ClientConfig{
    BaseURL: "https://authz.example", Brand: "idbi", App: "billing",
    Credential: os.Getenv("AUTHZ_APP_CREDENTIAL"), // timeout defaults to 2s, no retries, no cache
})

perms, _ := authz.NewPerms(authz.PermsConfig{
    Brand: "idbi", App: "billing",
    Issuer: "https://auth.idbi.example/", TenantID: "idbi",
    Reads:   []string{"invoice.view"}, // from permissions.yaml
    Checker: checker,
})
```

## Reading the API in English

```go
// Verify the token: signature, exp, known issuer, tenant.
user, err := verifier.Verify(ctx, rawToken)

// Hint: what does the token claim? No network, never authorizes a write.
authz.Hint(user).Can("invoice.view")          // "does the token claim invoice.view?"
authz.UnverifiedHint(rawToken).Can("invoice.print") // UI only, token NOT verified

// Check: ask the check service right now.
ok, err := checker.Check(ctx, authz.CheckRequest{Permission: "invoice.print", Subject: user["sub"].(string)})

// Can: the full algorithm.
perms.Can(ctx, user, "invoice.print", authz.WithObject("invoice", "inv-001"))
// "can this user print invoice inv-001?"

// Explain: which step said no?
d := perms.Explain(ctx, user, "invoice.print")
// d.Allowed, d.Reason ("denied"), d.Step ("live_permission"), d.LiveCalls, d.Err
```

`Can` runs these steps and stops at the first failure: token checks (issuer, tenant, subject, expiry), request grammar, claim hint (missing means deny), live permission check (writes only), live object check (when an object is given), any error or timeout denies.

## HTTP guard

```go
guard := authz.NewGuard(verifier, perms)

mux.Handle("POST /invoices/{id}/print",
    guard.RequireFunc("invoice.print", printHandler, // write: checked live
        authz.WithObjectFunc(func(r *http.Request) (authz.Object, bool) {
            return authz.Object{Type: "invoice", ID: r.PathValue("id")}, true
        })))

// Explicit opt-out, reads only: decided from the claim, no live call.
mux.Handle("GET /invoices", guard.Require("invoice.view", authz.WithMode(authz.ModeHint))(listHandler))
```

Responses: 401 invalid or missing token, 403 denied, 503 live check failed or timed out. `ModeHint` on a write, on an unknown permission, or together with an object panics at registration. Handlers read the user with `authz.UserFromContext(r.Context())`.

## Conformance vectors

`testdata/vectors.json` is a pinned copy of `authz-spec/vectors.json`; `vectors_test.go` runs every vector through `Perms.Explain` and every `linkVectors` entry through `ValidateLink`. `relationVectors` and `bindingVectors` (spec 2.2.0) cover the check service, not the SDK: the test only checks that they are present and does not run them. The test fails (never skips) when the copy does not match its pin. Spec 2.0.0 grammars: `App` is the OAuth `client_id` (a Hydra UUID is fine), `Brand` is the tenant slug; an invalid one makes `NewPerms`/`NewClient` fail with `ErrInvalidConfig` (spec reason `invalid_config`). `PermsConfig.Resources` carries the manifest's declared object types.

- Sync: `scripts/sync-vectors.sh [path-to-authz-spec]` copies the file and rewrites `testdata/vectors.json.sha256`.
- The test fails if the file does not match the pin, so hand edits are caught. Never edit the copy; change the spec and re-sync.
- `make check-vectors` fails if the copy differs from `../authz-spec`.

## Development

```
make test        # go test
make race        # with the race detector
make lint        # golangci-lint
make ci          # gofmt, vet, lint, race tests
```
