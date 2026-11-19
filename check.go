package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultCheckTimeout is the recommended client timeout from the spec.
const DefaultCheckTimeout = 2 * time.Second

const maxCheckBody = 64 << 10

// CheckRequest is one live permission question. Brand and app are not here:
// the client fills them from its configuration, never from the caller.
type CheckRequest struct {
	Permission string
	Subject    string
	Object     *Object
}

// Checker answers live checks. Implementations must return (true, nil) only for
// an explicit allow; every failure is an error wrapping ErrTimeout or ErrCheck.
type Checker interface {
	Check(ctx context.Context, req CheckRequest) (bool, error)
}

// ClientConfig configures the POST /v1/check client.
type ClientConfig struct {
	// BaseURL of the check service, e.g. https://authz.example.
	BaseURL string
	// Brand and App identify the calling app. They are sent with every call.
	Brand string
	App   string
	// Credential is the app's bearer credential.
	Credential string
	// Timeout per call. Zero means DefaultCheckTimeout.
	Timeout time.Duration
	// HTTPClient is optional. Redirects are never followed.
	HTTPClient *http.Client
}

// Client implements Checker against the check service. It never caches and
// never retries.
type Client struct {
	url        string
	brand, app string
	credential string
	timeout    time.Duration
	hc         *http.Client
}

// NewClient validates cfg and builds a Client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.BaseURL == "" || cfg.Credential == "" {
		return nil, errors.New("authz: BaseURL and Credential are required")
	}
	if !ValidBrand(cfg.Brand) || !ValidApp(cfg.App) {
		return nil, fmt.Errorf("%w: Brand must match ^[a-z0-9][a-z0-9-]{0,62}$ and App (the OAuth client_id) ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ without \"..\"", ErrInvalidConfig)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultCheckTimeout
	}
	base := cfg.HTTPClient
	if base == nil {
		base = &http.Client{}
	}
	hc := *base // copy so we can pin redirect behaviour without touching the caller's client
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		url:        strings.TrimRight(cfg.BaseURL, "/") + "/v1/check",
		brand:      cfg.Brand,
		app:        cfg.App,
		credential: cfg.Credential,
		timeout:    timeout,
		hc:         &hc,
	}, nil
}

type wireRequest struct {
	Brand      string  `json:"brand"`
	App        string  `json:"app"`
	Subject    string  `json:"subject"`
	Permission string  `json:"permission"`
	Object     *Object `json:"object,omitempty"`
}

// Check asks the service. It allows only on HTTP 200, a JSON object body and
// allowed === true. Anything else is an error wrapping ErrCheck or ErrTimeout.
func (c *Client) Check(ctx context.Context, req CheckRequest) (bool, error) {
	if req.Subject == "" || !ValidPermission(req.Permission) || (req.Object != nil && !ValidObject(*req.Object)) {
		return false, fmt.Errorf("%w: invalid request", ErrCheck)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	body, err := json.Marshal(wireRequest{
		Brand: c.brand, App: c.app, Subject: req.Subject, Permission: req.Permission, Object: req.Object,
	})
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrCheck, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body)) //nolint:gosec // G704: URL is operator configuration, not user input
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrCheck, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.credential)

	resp, err := c.hc.Do(httpReq) //nolint:gosec // G704: URL is operator configuration, not user input
	if err != nil {
		return false, classify(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxCheckBody))
		return false, fmt.Errorf("%w: status %d", ErrCheck, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCheckBody+1))
	if err != nil {
		return false, classify(err)
	}
	if len(raw) > maxCheckBody {
		return false, fmt.Errorf("%w: response too large", ErrCheck)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return false, fmt.Errorf("%w: malformed body", ErrCheck)
	}
	switch string(bytes.TrimSpace(out["allowed"])) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default: // missing, null, string, number...: not a decision
		return false, fmt.Errorf("%w: allowed is not a boolean", ErrCheck)
	}
}

func classify(err error) error {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return fmt.Errorf("%w: %w", ErrTimeout, err)
	}
	return fmt.Errorf("%w: %w", ErrCheck, err)
}
