package xai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultOIDCDiscoveryURL is xAI's official OpenID Connect discovery endpoint.
	DefaultOIDCDiscoveryURL = "https://auth.x.ai/.well-known/openid-configuration"
	// DefaultDeviceClientID is the public Grok CLI RFC 8628 Device Code OAuth client_id.
	DefaultDeviceClientID = "b1a00492-073a-47ea-816f-4c329264a828"
	// DefaultDeviceScopes matches official Grok CLI scopes.
	DefaultDeviceScopes = "openid profile email offline_access grok-cli:access api:access"
	// DeviceCodeGrantType is RFC 8628 grant_type.
	DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

	maxOIDCDiscoveryBody = 64 * 1024
	defaultPollInterval  = 5 * time.Second
)

var (
	ErrUntrustedXAIHost        = errors.New("xai: OIDC/OAuth URL must use https://*.x.ai")
	ErrDeviceAuthDenied        = errors.New("xai: device authorization denied")
	ErrDeviceAuthExpired       = errors.New("xai: device authorization expired")
	ErrDeviceEndpointMissing   = errors.New("xai: OIDC discovery missing device_authorization_endpoint or token_endpoint")
	ErrDeviceRedirectForbidden = errors.New("xai: redirects are forbidden on OAuth device endpoints")
)

// OIDCDiscoveryDocument captures the validated subset of xAI's OpenID Connect metadata.
type OIDCDiscoveryDocument struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// DeviceAuthorizationResponse is returned by RFC 8628 device authorization endpoint.
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval,omitempty"`
}

// DeviceOAuthClient performs OIDC discovery and RFC 8628 Device Code OAuth flows
// against validated https://*.x.ai endpoints using a neutral official CLI UA.
type DeviceOAuthClient struct {
	httpClient        *http.Client
	discoveryURL      string
	userAgent         string
	acceptLanguage    string
	allowTestHosts    bool // strictly for httptest local mock servers in unit tests
	minPollInterval   time.Duration
}

// DeviceOAuthOption configures DeviceOAuthClient.
type DeviceOAuthOption func(*DeviceOAuthClient)

// WithDeviceDiscoveryURL overrides the discovery URL (validated against https://*.x.ai unless test mode).
func WithDeviceDiscoveryURL(u string) DeviceOAuthOption {
	return func(c *DeviceOAuthClient) {
		if strings.TrimSpace(u) != "" {
			c.discoveryURL = strings.TrimSpace(u)
		}
	}
}

// WithDeviceUserAgent sets the explicit CLI User-Agent (never berth-grok-oauth).
func WithDeviceUserAgent(ua string) DeviceOAuthOption {
	return func(c *DeviceOAuthClient) {
		if strings.TrimSpace(ua) != "" {
			c.userAgent = strings.TrimSpace(ua)
		}
	}
}

// WithDeviceAcceptLanguage sets cage-aligned Accept-Language (defaults to en-US,en;q=0.9).
func WithDeviceAcceptLanguage(lang string) DeviceOAuthOption {
	return func(c *DeviceOAuthClient) {
		if strings.TrimSpace(lang) != "" {
			c.acceptLanguage = strings.TrimSpace(lang)
		}
	}
}

// NewDeviceOAuthClient constructs a DeviceOAuthClient that refuses redirects and
// validates every discovered endpoint against https://*.x.ai.
func NewDeviceOAuthClient(httpClient *http.Client, opts ...DeviceOAuthOption) *DeviceOAuthClient {
	baseClient := httpClient
	if baseClient == nil {
		baseClient = &http.Client{Timeout: 30 * time.Second}
	}
	clone := *baseClient
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return ErrDeviceRedirectForbidden
	}

	c := &DeviceOAuthClient{
		httpClient:      &clone,
		discoveryURL:    DefaultOIDCDiscoveryURL,
		userAgent:       CLIUserAgent(ResolveCLIVersion()),
		acceptLanguage:  "en-US,en;q=0.9",
		minPollInterval: defaultPollInterval,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// ValidateTrustedXAIEndpoint enforces strict https://*.x.ai (or https://x.ai) validation
// so untrusted OIDC discovery responses cannot redirect credentials to attacker hosts.
func ValidateTrustedXAIEndpoint(rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed == nil {
		return fmt.Errorf("%w: parse error", ErrUntrustedXAIHost)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("%w: scheme %q", ErrUntrustedXAIHost, parsed.Scheme)
	}
	if parsed.User != nil || parsed.Opaque != "" {
		return fmt.Errorf("%w: disallowed userinfo/opaque", ErrUntrustedXAIHost)
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parsed.Hostname()), "."))
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrUntrustedXAIHost)
	}
	if host != "x.ai" && !strings.HasSuffix(host, ".x.ai") {
		return fmt.Errorf("%w: host %q", ErrUntrustedXAIHost, host)
	}
	return nil
}

func (c *DeviceOAuthClient) validateEndpoint(rawURL string) error {
	if c.allowTestHosts {
		parsed, err := url.Parse(strings.TrimSpace(rawURL))
		if err != nil || parsed.Host == "" {
			return ErrUntrustedXAIHost
		}
		return nil
	}
	return ValidateTrustedXAIEndpoint(rawURL)
}

// Discover fetches and validates xAI's OpenID Connect discovery document.
func (c *DeviceOAuthClient) Discover(ctx context.Context) (*OIDCDiscoveryDocument, error) {
	if err := c.validateEndpoint(c.discoveryURL); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept-Language", c.acceptLanguage)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xai oidc discovery request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOIDCDiscoveryBody+1))
	if err != nil {
		return nil, fmt.Errorf("xai oidc discovery read: %w", err)
	}
	if len(body) > maxOIDCDiscoveryBody {
		return nil, errors.New("xai oidc discovery document exceeds size limit")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xai oidc discovery failed with status %d", resp.StatusCode)
	}

	var doc OIDCDiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("xai oidc discovery decode: %w", err)
	}
	if strings.TrimSpace(doc.DeviceAuthorizationEndpoint) == "" || strings.TrimSpace(doc.TokenEndpoint) == "" {
		return nil, ErrDeviceEndpointMissing
	}
	if err := c.validateEndpoint(doc.DeviceAuthorizationEndpoint); err != nil {
		return nil, fmt.Errorf("invalid device_authorization_endpoint: %w", err)
	}
	if err := c.validateEndpoint(doc.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("invalid token_endpoint: %w", err)
	}
	return &doc, nil
}

// RequestDeviceCode initiates an RFC 8628 Device Authorization Grant.
func (c *DeviceOAuthClient) RequestDeviceCode(ctx context.Context, deviceEndpoint, clientID, scope string) (*DeviceAuthorizationResponse, error) {
	if err := c.validateEndpoint(deviceEndpoint); err != nil {
		return nil, err
	}
	if strings.TrimSpace(clientID) == "" {
		clientID = DefaultDeviceClientID
	}
	if strings.TrimSpace(scope) == "" {
		scope = DefaultDeviceScopes
	}

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", scope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept-Language", c.acceptLanguage)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xai device authorization request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOIDCDiscoveryBody))
	if err != nil {
		return nil, fmt.Errorf("xai device authorization read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xai device authorization failed with status %d", resp.StatusCode)
	}

	var out DeviceAuthorizationResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("xai device authorization decode: %w", err)
	}
	if strings.TrimSpace(out.DeviceCode) == "" || strings.TrimSpace(out.UserCode) == "" {
		return nil, errors.New("xai device authorization response missing device_code or user_code")
	}
	if out.Interval <= 0 {
		out.Interval = 5
	}
	return &out, nil
}

// PollDeviceToken polls the discovered token_endpoint until authorization succeeds,
// is denied/expired, or ctx is canceled. Honors RFC 8628 authorization_pending and slow_down.
func (c *DeviceOAuthClient) PollDeviceToken(
	ctx context.Context,
	tokenEndpoint, clientID, deviceCode string,
	interval time.Duration,
	expiresIn time.Duration,
) (*TokenResponse, error) {
	if err := c.validateEndpoint(tokenEndpoint); err != nil {
		return nil, err
	}
	if strings.TrimSpace(clientID) == "" {
		clientID = DefaultDeviceClientID
	}
	if strings.TrimSpace(deviceCode) == "" {
		return nil, errors.New("xai: device_code is required")
	}
	if interval <= 0 {
		interval = c.minPollInterval
	}
	if expiresIn <= 0 {
		expiresIn = 10 * time.Minute
	}

	deadline := time.Now().Add(expiresIn)
	for {
		if time.Now().After(deadline) {
			return nil, ErrDeviceAuthExpired
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}

		form := url.Values{}
		form.Set("grant_type", DeviceCodeGrantType)
		form.Set("client_id", clientID)
		form.Set("device_code", deviceCode)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept-Language", c.acceptLanguage)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("xai device token poll request: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxOIDCDiscoveryBody))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("xai device token poll read: %w", readErr)
		}

		var payload struct {
			TokenResponse
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("xai device token poll decode: %w", err)
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && strings.TrimSpace(payload.AccessToken) != "" {
			return &payload.TokenResponse, nil
		}

		switch strings.TrimSpace(payload.Error) {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "access_denied":
			return nil, ErrDeviceAuthDenied
		case "expired_token":
			return nil, ErrDeviceAuthExpired
		default:
			return nil, fmt.Errorf("xai device token poll failed (status=%d, error=%s): %s",
				resp.StatusCode, payload.Error, payload.ErrorDescription)
		}
	}
}
