package service

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	infraerrors "github.com/jk-zhang-meta/berth/internal/pkg/errors"
)

var (
	ErrEdgeCredentialUnavailable = infraerrors.New(http.StatusServiceUnavailable, "EDGE_CREDENTIAL_UNAVAILABLE", "Account upstream credential lookup is unavailable")
	ErrEdgeCredentialForbidden   = infraerrors.New(http.StatusForbidden, "EDGE_CREDENTIAL_FORBIDDEN", "Landing node is not authorized for this lease or account credential")
)

// EdgeAccountLookup is a minimal seam satisfied by AdminService to load an Account
// for ephemeral upstream credential resolution on the assigned Landing node.
type EdgeAccountLookup interface {
	GetAccount(ctx context.Context, id int64) (*Account, error)
}

// EdgeUpstreamCredential is a short-lived, RAM-only upstream auth bundle returned
// strictly to the Ed25519-authenticated Landing node bound to an active SessionLease.
type EdgeUpstreamCredential struct {
	AccountID     int64             `json:"account_id"`
	Platform      string            `json:"platform"`
	AccountType   string            `json:"account_type"`
	Headers       map[string]string `json:"headers"`
	BaseURL       string            `json:"base_url,omitempty"`
	ExpiresAtUnix int64             `json:"expires_at_unix"`
}

const maxEdgeCredentialTTL = 120 * time.Second

// ResolveUpstreamCredentialForLease strictly verifies that callingNodeID is the exact
// assigned Landing node for an active, non-revoked leaseID bound to accountID, and returns
// ephemeral platform auth headers + upstream base URL.
func ResolveUpstreamCredentialForLease(
	ctx context.Context,
	leases *BerthEdgeLeaseService,
	lookup EdgeAccountLookup,
	callingNodeID int64,
	leaseID string,
	accountID int64,
	now time.Time,
) (*EdgeUpstreamCredential, error) {
	if leases == nil || lookup == nil {
		return nil, ErrEdgeCredentialUnavailable
	}
	if callingNodeID <= 0 || strings.TrimSpace(leaseID) == "" || accountID <= 0 {
		return nil, ErrEdgeLeaseInvalid
	}
	if now.IsZero() {
		now = time.Now()
	}

	lease, err := leases.GetLeaseRecord(ctx, leaseID)
	if err != nil {
		return nil, err
	}
	if lease.RevokedAt != nil {
		return nil, ErrEdgeLeaseRevoked
	}
	if !now.Before(lease.ExpiresAt) {
		return nil, ErrEdgeLeaseForbidden
	}
	if lease.LandingNodeID != callingNodeID || lease.AccountID != accountID {
		return nil, fmt.Errorf("%w: node/account mismatch for lease %s", ErrEdgeCredentialForbidden, leaseID)
	}

	acc, err := lookup.GetAccount(ctx, accountID)
	if err != nil || acc == nil {
		if err != nil {
			return nil, err
		}
		return nil, ErrEdgeCredentialForbidden
	}
	if acc.Status != StatusActive {
		return nil, fmt.Errorf("%w: account %d status=%s", ErrEdgeCredentialForbidden, acc.ID, acc.Status)
	}

	// Shadow accounts delegate credentials to their parent account.
	credAcc := acc
	if acc.ParentAccountID != nil && *acc.ParentAccountID > 0 {
		parent, pErr := lookup.GetAccount(ctx, *acc.ParentAccountID)
		if pErr != nil || parent == nil {
			return nil, fmt.Errorf("%w: parent account %d unavailable", ErrEdgeCredentialForbidden, *acc.ParentAccountID)
		}
		credAcc = parent
	}

	headers, baseURL, err := extractUpstreamAuth(credAcc)
	if err != nil {
		return nil, err
	}

	exp := now.Add(maxEdgeCredentialTTL)
	if lease.ExpiresAt.Before(exp) {
		exp = lease.ExpiresAt
	}

	return &EdgeUpstreamCredential{
		AccountID:     acc.ID,
		Platform:      acc.Platform,
		AccountType:   credAcc.Type,
		Headers:       headers,
		BaseURL:       baseURL,
		ExpiresAtUnix: exp.Unix(),
	}, nil
}

func extractUpstreamAuth(acc *Account) (map[string]string, string, error) {
	platform := strings.ToLower(strings.TrimSpace(acc.Platform))
	accType := strings.ToLower(strings.TrimSpace(acc.Type))
	headers := make(map[string]string, 3)

	firstNonEmpty := func(keys ...string) string {
		for _, k := range keys {
			if v := strings.TrimSpace(acc.GetCredential(k)); v != "" {
				return v
			}
		}
		return ""
	}

	switch platform {
	case PlatformOpenAI, "codex":
		if accType == AccountTypeOAuth {
			tok := strings.TrimSpace(acc.GetOpenAIAccessToken())
			if tok == "" {
				tok = firstNonEmpty("access_token", "oauth_token")
			}
			if tok == "" {
				return nil, "", fmt.Errorf("%w: openai oauth access_token missing", ErrEdgeCredentialUnavailable)
			}
			headers["Authorization"] = "Bearer " + tok
			if chatgptID := strings.TrimSpace(acc.GetExtraString("chatgpt_account_id")); chatgptID != "" {
				headers["Chatgpt-Account-Id"] = chatgptID
			}
			base := firstNonEmpty("base_url")
			if base == "" {
				base = "https://chatgpt.com/backend-api/codex"
			}
			return headers, strings.TrimRight(base, "/"), nil
		}
		key := firstNonEmpty("api_key", "key")
		if key == "" {
			key = strings.TrimSpace(acc.GetTypeSafeAPIKey())
		}
		if key == "" {
			return nil, "", fmt.Errorf("%w: openai api_key missing", ErrEdgeCredentialUnavailable)
		}
		headers["Authorization"] = "Bearer " + key
		base := strings.TrimRight(strings.TrimSpace(acc.GetOpenAIBaseURL()), "/")
		return headers, base, nil

	case PlatformAnthropic, "claude":
		if accType == AccountTypeOAuth || accType == AccountTypeSetupToken {
			tok := firstNonEmpty("access_token", "oauth_token", "setup_token")
			if tok == "" {
				return nil, "", fmt.Errorf("%w: anthropic oauth token missing", ErrEdgeCredentialUnavailable)
			}
			headers["Authorization"] = "Bearer " + tok
			headers["anthropic-beta"] = "oauth-2025-04-20"
			base := strings.TrimRight(strings.TrimSpace(acc.GetBaseURL()), "/")
			return headers, base, nil
		}
		key := firstNonEmpty("api_key", "key")
		if key == "" {
			return nil, "", fmt.Errorf("%w: anthropic api_key missing", ErrEdgeCredentialUnavailable)
		}
		headers["x-api-key"] = key
		base := strings.TrimRight(strings.TrimSpace(acc.GetBaseURL()), "/")
		return headers, base, nil

	case PlatformAntigravity, PlatformGemini:
		if accType == AccountTypeOAuth {
			tok := firstNonEmpty("access_token", "oauth_token")
			if tok == "" {
				return nil, "", fmt.Errorf("%w: gemini/antigravity oauth token missing", ErrEdgeCredentialUnavailable)
			}
			headers["Authorization"] = "Bearer " + tok
			base := firstNonEmpty("base_url")
			return headers, strings.TrimRight(base, "/"), nil
		}
		key := firstNonEmpty("api_key", "key")
		if key == "" {
			return nil, "", fmt.Errorf("%w: gemini/antigravity api_key missing", ErrEdgeCredentialUnavailable)
		}
		headers["x-goog-api-key"] = key
		base := strings.TrimRight(strings.TrimSpace(acc.GetGeminiBaseURL("https://generativelanguage.googleapis.com")), "/")
		return headers, base, nil

	case PlatformGrok, "xai":
		tok := firstNonEmpty("api_key", "access_token", "key")
		if tok == "" {
			return nil, "", fmt.Errorf("%w: grok api_key missing", ErrEdgeCredentialUnavailable)
		}
		headers["Authorization"] = "Bearer " + tok
		base := strings.TrimRight(strings.TrimSpace(acc.GetGrokBaseURLOr("https://api.x.ai")), "/")
		return headers, base, nil

	default:
		tok := firstNonEmpty("api_key", "access_token", "key")
		if tok == "" {
			return nil, "", fmt.Errorf("%w: unsupported platform %q credential missing", ErrEdgeCredentialUnavailable, platform)
		}
		headers["Authorization"] = "Bearer " + tok
		return headers, strings.TrimRight(strings.TrimSpace(acc.GetBaseURL()), "/"), nil
	}
}
