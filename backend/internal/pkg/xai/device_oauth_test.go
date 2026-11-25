package xai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateTrustedXAIEndpoint(t *testing.T) {
	require.NoError(t, ValidateTrustedXAIEndpoint("https://auth.x.ai/.well-known/openid-configuration"))
	require.NoError(t, ValidateTrustedXAIEndpoint("https://accounts.x.ai/oauth2/device/auth"))
	require.NoError(t, ValidateTrustedXAIEndpoint("https://x.ai/oauth2/token"))

	// Reject plaintext HTTP, evil suffix, and foreign hosts.
	require.ErrorIs(t, ValidateTrustedXAIEndpoint("http://auth.x.ai/oauth2/token"), ErrUntrustedXAIHost)
	require.ErrorIs(t, ValidateTrustedXAIEndpoint("https://evil-x.ai/oauth2/token"), ErrUntrustedXAIHost)
	require.ErrorIs(t, ValidateTrustedXAIEndpoint("https://auth.x.ai.attacker.com/token"), ErrUntrustedXAIHost)
	require.ErrorIs(t, ValidateTrustedXAIEndpoint("https://127.0.0.1/token"), ErrUntrustedXAIHost)
}

func TestDeviceOAuthClient_DiscoveryAndRFC8628DeviceFlow(t *testing.T) {
	var pollCount atomic.Int32
	var seenUA atomic.Value

	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUA.Store(r.Header.Get("User-Agent"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(OIDCDiscoveryDocument{
				Issuer:                      srv.URL,
				DeviceAuthorizationEndpoint: srv.URL + "/oauth2/device/auth",
				TokenEndpoint:               srv.URL + "/oauth2/token",
			})
		case "/oauth2/device/auth":
			require.NoError(t, r.ParseForm())
			require.Equal(t, DefaultDeviceClientID, r.Form.Get("client_id"))
			require.Contains(t, r.Form.Get("scope"), "grok-cli:access")
			_ = json.NewEncoder(w).Encode(DeviceAuthorizationResponse{
				DeviceCode:      "dev-code-123",
				UserCode:        "ABCD-EFGH",
				VerificationURI: "https://auth.x.ai/device",
				ExpiresIn:       600,
				Interval:        1,
			})
		case "/oauth2/token":
			require.NoError(t, r.ParseForm())
			require.Equal(t, DeviceCodeGrantType, r.Form.Get("grant_type"))
			require.Equal(t, "dev-code-123", r.Form.Get("device_code"))
			n := pollCount.Add(1)
			if n == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(TokenResponse{
				AccessToken:  "xai-access-token",
				RefreshToken: "xai-refresh-token",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewDeviceOAuthClient(srv.Client(), WithDeviceDiscoveryURL(srv.URL+"/.well-known/openid-configuration"))
	client.allowTestHosts = true
	client.minPollInterval = 5 * time.Millisecond

	ctx := context.Background()
	doc, err := client.Discover(ctx)
	require.NoError(t, err)
	require.Equal(t, srv.URL+"/oauth2/device/auth", doc.DeviceAuthorizationEndpoint)
	require.Equal(t, srv.URL+"/oauth2/token", doc.TokenEndpoint)

	devResp, err := client.RequestDeviceCode(ctx, doc.DeviceAuthorizationEndpoint, "", "")
	require.NoError(t, err)
	require.Equal(t, "dev-code-123", devResp.DeviceCode)
	require.Equal(t, "ABCD-EFGH", devResp.UserCode)

	tok, err := client.PollDeviceToken(ctx, doc.TokenEndpoint, "", devResp.DeviceCode, 5*time.Millisecond, 5*time.Second)
	require.NoError(t, err)
	require.Equal(t, "xai-access-token", tok.AccessToken)
	require.Equal(t, "xai-refresh-token", tok.RefreshToken)
	require.Equal(t, int32(2), pollCount.Load())

	ua, _ := seenUA.Load().(string)
	require.NotContains(t, strings.ToLower(ua), "berth")
	require.Contains(t, ua, "grok-pager/")
}

func TestDeviceOAuthClient_RejectsUntrustedDiscoveredEndpoints(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OIDCDiscoveryDocument{
			Issuer:                      "https://auth.x.ai",
			DeviceAuthorizationEndpoint: "https://evil.attacker.com/device",
			TokenEndpoint:               "https://auth.x.ai/oauth2/token",
		})
	}))
	defer srv.Close()

	// Production validation enabled: allowTestHosts=false rejects both non-x.ai discovery and endpoints.
	prodClient := NewDeviceOAuthClient(srv.Client(), WithDeviceDiscoveryURL(srv.URL+"/.well-known/openid-configuration"))
	_, err := prodClient.Discover(context.Background())
	require.ErrorIs(t, err, ErrUntrustedXAIHost)
}
