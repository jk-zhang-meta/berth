package service

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/antigravity"
	"github.com/jk-zhang-meta/berth/internal/pkg/claude"
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

// EdgeCageLookup is an optional seam satisfied by BerthAccountCageService to attach
// authoritative AccountCage identity fields to an ephemeral Edge credential bundle.
type EdgeCageLookup interface {
	GetActiveCageByAccountID(ctx context.Context, accountID int64) (*AccountCage, error)
}

// EdgeTokenRefresher coordinates fresh OAuth access-token resolution through the
// unified OAuthRefreshAPI + WAL lock before Landing executes upstream requests.
type EdgeTokenRefresher interface {
	EnsureFreshAccessToken(ctx context.Context, account *Account) (string, *time.Time, error)
}

// EdgeCageIdentity carries authoritative per-account virtual client & anti-ban
// convergence parameters from Berth Central to the assigned Landing Edge node.
type EdgeCageIdentity struct {
	ClientOS             string `json:"client_os,omitempty"`
	ClientOSVersion      string `json:"client_os_version,omitempty"`
	ClientArch           string `json:"client_arch,omitempty"`
	ClientRuntime        string `json:"client_runtime,omitempty"`
	ClientRuntimeVersion string `json:"client_runtime_version,omitempty"`
	ClientAppVersion     string `json:"client_app_version,omitempty"`
	UserAgentInference   string `json:"user_agent_inference,omitempty"`
	UserAgentOAuth       string `json:"user_agent_oauth,omitempty"`
	Originator           string `json:"originator,omitempty"`
	AcceptLanguage       string `json:"accept_language,omitempty"`
	OAILanguage          string `json:"oai_language,omitempty"`
	Timezone             string `json:"timezone,omitempty"`
	ClaudeDeviceID       string `json:"claude_device_id,omitempty"`
	ClaudeAccountUUID    string `json:"claude_account_uuid,omitempty"`
	CodexInstallationID  string `json:"codex_installation_id,omitempty"`
	CodexFingerprintMode string `json:"codex_fingerprint_mode,omitempty"`
	AntigravityProjectID string `json:"antigravity_project_id,omitempty"`
	AntigravityPlanType  string `json:"antigravity_plan_type,omitempty"`
	TLSProfile           string `json:"tls_profile,omitempty"`
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
	CageIdentity  *EdgeCageIdentity `json:"cage_identity,omitempty"`
}

const (
	maxEdgeCredentialTTL         = 120 * time.Second
	edgeCredentialTokenExpirySkew = 30 * time.Second
)

// MultiPlatformEdgeTokenRefresher dispatches OAuth token freshness checks to each
// platform's existing unified TokenProvider (sharing OAuthRefreshAPI + WAL + locks).
type MultiPlatformEdgeTokenRefresher struct {
	Claude      *ClaudeTokenProvider
	OpenAI      *OpenAITokenProvider
	Antigravity *AntigravityTokenProvider
	Gemini      *GeminiTokenProvider
	Grok        *GrokTokenProvider
	Accounts    EdgeAccountLookup
}

func (r *MultiPlatformEdgeTokenRefresher) EnsureFreshAccessToken(ctx context.Context, account *Account) (string, *time.Time, error) {
	if r == nil || account == nil || !account.IsOAuth() {
		return "", nil, nil
	}
	var (
		tok string
		err error
	)
	switch strings.ToLower(strings.TrimSpace(account.Platform)) {
	case PlatformAnthropic, "claude":
		if r.Claude != nil {
			tok, err = r.Claude.GetAccessToken(ctx, account)
		}
	case PlatformOpenAI, "codex":
		if r.OpenAI != nil {
			tok, err = r.OpenAI.GetAccessToken(ctx, account)
		}
	case PlatformAntigravity:
		if r.Antigravity != nil {
			tok, err = r.Antigravity.GetAccessToken(ctx, account)
		}
	case PlatformGemini:
		if r.Gemini != nil {
			tok, err = r.Gemini.GetAccessToken(ctx, account)
		}
	case PlatformGrok, "xai":
		if r.Grok != nil {
			tok, err = r.Grok.GetAccessToken(ctx, account)
		}
	default:
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	tok = strings.TrimSpace(tok)
	var exp *time.Time
	if r.Accounts != nil && account.ID > 0 {
		if latest, lErr := r.Accounts.GetAccount(ctx, account.ID); lErr == nil && latest != nil {
			exp = latest.GetCredentialAsTime("expires_at")
			if tok == "" {
				tok = strings.TrimSpace(latest.GetCredential("access_token"))
			}
		}
	}
	if exp == nil {
		exp = account.GetCredentialAsTime("expires_at")
	}
	return tok, exp, nil
}

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
	return ResolveUpstreamCredentialForLeaseWithDeps(ctx, leases, lookup, nil, nil, callingNodeID, leaseID, accountID, now)
}

// ResolveUpstreamCredentialForLeaseWithDeps extends ResolveUpstreamCredentialForLease with
// unified OAuth token refresh coordination and authoritative AccountCage identity delivery.
func ResolveUpstreamCredentialForLeaseWithDeps(
	ctx context.Context,
	leases *BerthEdgeLeaseService,
	lookup EdgeAccountLookup,
	cages EdgeCageLookup,
	refresher EdgeTokenRefresher,
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

	verifyBinding := func() error {
		if leases.store == nil {
			return nil
		}
		if authVerifier, ok := leases.store.(edgeLandingOAuthAuthVerifier); ok {
			if aErr := authVerifier.VerifyAccountEdgeLandingAuthorization(ctx, accountID, callingNodeID); aErr != nil {
				return fmt.Errorf("%w: %v", ErrEdgeCredentialForbidden, aErr)
			}
		}
		if cageResolver, ok := leases.store.(edgeLeaseAccountCageResolver); ok {
			_, dbEpoch, gateState, _, _, _, found, cErr := cageResolver.ResolveAccountCageState(ctx, accountID)
			if cErr != nil {
				return fmt.Errorf("%w: cage lookup failed: %v", ErrEdgeCredentialUnavailable, cErr)
			}
			if found {
				if gateState == CageGateStateQuarantined || gateState == CageGateStateClosed {
					return fmt.Errorf("%w: account cage is %s", ErrEdgeCredentialForbidden, gateState)
				}
				if lease.CageEpoch > 0 && dbEpoch > lease.CageEpoch {
					return fmt.Errorf("%w: lease cage epoch %d is stale (current %d)", ErrEdgeCredentialForbidden, lease.CageEpoch, dbEpoch)
				}
			}
		}
		return nil
	}

	// Re-verify live account landing pin and cage state before any refresh or lookup.
	if err := verifyBinding(); err != nil {
		return nil, err
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

	// Shadow accounts delegate credentials to their parent account (must also be active!).
	credAcc := acc
	if acc.ParentAccountID != nil && *acc.ParentAccountID > 0 {
		parent, pErr := lookup.GetAccount(ctx, *acc.ParentAccountID)
		if pErr != nil || parent == nil {
			return nil, fmt.Errorf("%w: parent account %d unavailable", ErrEdgeCredentialForbidden, *acc.ParentAccountID)
		}
		if parent.Status != StatusActive {
			return nil, fmt.Errorf("%w: parent account %d status=%s", ErrEdgeCredentialForbidden, parent.ID, parent.Status)
		}
		credAcc = parent
	}

	// Coordinate OAuth token freshness via unified TokenProvider / OAuthRefreshAPI + WAL.
	freshToken := ""
	tokenExpiresAt := credAcc.GetCredentialAsTime("expires_at")
	if refresher != nil && credAcc.IsOAuth() {
		refTok, refExp, refErr := refresher.EnsureFreshAccessToken(ctx, credAcc)
		if refErr != nil {
			return nil, fmt.Errorf("%w: oauth token refresh failed: %v", ErrEdgeCredentialUnavailable, refErr)
		}
		if refTok != "" {
			freshToken = refTok
		}
		if refExp != nil {
			tokenExpiresAt = refExp
		}
		// Re-verify landing/cage binding after refresh in case a rebind occurred during refresh.
		if err := verifyBinding(); err != nil {
			return nil, err
		}
	}

	headers, baseURL, err := extractUpstreamAuthWithToken(credAcc, freshToken)
	if err != nil {
		return nil, err
	}

	// Cap credential TTL at min(now+120s, lease.ExpiresAt, tokenExpiresAt-30s); fail closed if already expired!
	exp := now.Add(maxEdgeCredentialTTL)
	if lease.ExpiresAt.Before(exp) {
		exp = lease.ExpiresAt
	}
	if credAcc.IsOAuth() && tokenExpiresAt != nil && !tokenExpiresAt.IsZero() {
		safeTokenExp := tokenExpiresAt.Add(-edgeCredentialTokenExpirySkew)
		if !now.Before(safeTokenExp) {
			return nil, fmt.Errorf("%w: upstream oauth token expired or within skew window", ErrEdgeCredentialUnavailable)
		}
		if safeTokenExp.Before(exp) {
			exp = safeTokenExp
		}
	}
	if !now.Before(exp) {
		return nil, fmt.Errorf("%w: credential envelope already expired", ErrEdgeCredentialUnavailable)
	}

	var cageRow *AccountCage
	if cages != nil {
		if c, cErr := cages.GetActiveCageByAccountID(ctx, acc.ID); cErr == nil && c != nil {
			cageRow = c
		}
	}
	cageIdentity := buildEdgeCageIdentity(acc, credAcc, cageRow)

	return &EdgeUpstreamCredential{
		AccountID:     acc.ID,
		Platform:      acc.Platform,
		AccountType:   credAcc.Type,
		Headers:       headers,
		BaseURL:       baseURL,
		ExpiresAtUnix: exp.Unix(),
		CageIdentity:  cageIdentity,
	}, nil
}

func maxNonEmptySemver(candidates ...string) string {
	best := ""
	for _, raw := range candidates {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if best == "" || CompareVersions(v, best) > 0 {
			best = v
		}
	}
	return best
}

func buildEdgeCageIdentity(acc, credAcc *Account, cageRow *AccountCage) *EdgeCageIdentity {
	if acc == nil && credAcc == nil && cageRow == nil {
		return nil
	}
	platform := ""
	if acc != nil {
		platform = strings.ToLower(strings.TrimSpace(acc.Platform))
	} else if credAcc != nil {
		platform = strings.ToLower(strings.TrimSpace(credAcc.Platform))
	}
	id := &EdgeCageIdentity{}
	if cageRow != nil {
		id.ClientOS = strings.TrimSpace(cageRow.ClientOS)
		id.ClientOSVersion = strings.TrimSpace(cageRow.ClientOSVersion)
		id.ClientArch = strings.TrimSpace(cageRow.ClientArch)
		id.ClientRuntime = strings.TrimSpace(cageRow.ClientRuntime)
		id.ClientRuntimeVersion = strings.TrimSpace(cageRow.ClientRuntimeVersion)
		id.ClientAppVersion = strings.TrimSpace(cageRow.ClientAppVersion)
		id.UserAgentInference = strings.TrimSpace(cageRow.UserAgentInference)
		id.UserAgentOAuth = strings.TrimSpace(cageRow.UserAgentOAuth)
		id.Originator = strings.TrimSpace(cageRow.Originator)
		id.AcceptLanguage = strings.TrimSpace(cageRow.AcceptLanguage)
		id.OAILanguage = strings.TrimSpace(cageRow.OAILanguage)
		id.Timezone = strings.TrimSpace(cageRow.Timezone)
		id.ClaudeDeviceID = strings.TrimSpace(cageRow.ClaudeDeviceID)
		id.CodexInstallationID = strings.TrimSpace(cageRow.CodexInstallationID)
	}

	switch platform {
	case PlatformAnthropic, "claude":
		id.TLSProfile = "anthropic_cli"
		id.ClientAppVersion = maxNonEmptySemver(id.ClientAppVersion, claude.CLIVersion())
		if credAcc != nil {
			uuid := strings.TrimSpace(credAcc.GetExtraString("account_uuid"))
			if uuid == "" {
				uuid = strings.TrimSpace(credAcc.GetCredential("account_uuid"))
			}
			id.ClaudeAccountUUID = uuid
		}
	case PlatformOpenAI, "codex":
		id.TLSProfile = "openai_codex"
		id.ClientAppVersion = maxNonEmptySemver(id.ClientAppVersion, CodexCanonicalClientVersion(), codexUpstreamMinVersion)
		if id.Originator == "" || strings.EqualFold(id.Originator, "codex-tui") {
			id.Originator = "codex_cli_rs"
		}
		if credAcc != nil {
			id.CodexFingerprintMode = string(credAcc.GetCodexFingerprintMode())
			if devID := strings.TrimSpace(credAcc.GetOpenAIDeviceID()); devID != "" {
				id.CodexInstallationID = devID
			}
		}
		if id.CodexFingerprintMode == "" {
			id.CodexFingerprintMode = string(codexFingerprintDevice)
		}
	case PlatformAntigravity, PlatformGemini:
		id.TLSProfile = "antigravity_cli"
		id.ClientAppVersion = maxNonEmptySemver(id.ClientAppVersion, antigravity.GetDefaultUserAgentVersion())
		if credAcc != nil {
			projectID := strings.TrimSpace(credAcc.GetCredential("project_id"))
			if projectID == "" {
				projectID = strings.TrimSpace(credAcc.GetCredential(antigravityProjectIDFallbackCredentialKey))
			}
			id.AntigravityProjectID = projectID
			id.AntigravityPlanType = strings.TrimSpace(credAcc.GetCredential("plan_type"))
		}
	case PlatformGrok, "xai":
		id.TLSProfile = "grok_cli"
	default:
		id.TLSProfile = "default"
	}
	return id
}

func extractUpstreamAuth(acc *Account) (map[string]string, string, error) {
	return extractUpstreamAuthWithToken(acc, "")
}

func extractUpstreamAuthWithToken(acc *Account, freshOAuthToken string) (map[string]string, string, error) {
	platform := strings.ToLower(strings.TrimSpace(acc.Platform))
	accType := strings.ToLower(strings.TrimSpace(acc.Type))
	headers := make(map[string]string, 4)

	firstNonEmpty := func(keys ...string) string {
		for _, k := range keys {
			if v := strings.TrimSpace(acc.GetCredential(k)); v != "" {
				return v
			}
		}
		return ""
	}
	oauthTok := func(keys ...string) string {
		if strings.TrimSpace(freshOAuthToken) != "" {
			return strings.TrimSpace(freshOAuthToken)
		}
		return firstNonEmpty(keys...)
	}

	switch platform {
	case PlatformOpenAI, "codex":
		if accType == AccountTypeOAuth {
			tok := strings.TrimSpace(freshOAuthToken)
			if tok == "" {
				tok = strings.TrimSpace(acc.GetOpenAIAccessToken())
			}
			if tok == "" {
				tok = firstNonEmpty("access_token", "oauth_token")
			}
			if tok == "" {
				return nil, "", fmt.Errorf("%w: openai oauth access_token missing", ErrEdgeCredentialUnavailable)
			}
			headers["Authorization"] = "Bearer " + tok
			chatgptID := strings.TrimSpace(acc.GetChatGPTAccountID())
			if chatgptID == "" {
				chatgptID = strings.TrimSpace(acc.GetExtraString("chatgpt_account_id"))
			}
			if chatgptID != "" {
				headers["Chatgpt-Account-Id"] = chatgptID
			}
			if acc.IsChatGPTAccountFedRAMP() {
				headers["x-openai-fedramp"] = "true"
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
			tok := oauthTok("access_token", "oauth_token", "setup_token")
			if tok == "" {
				return nil, "", fmt.Errorf("%w: anthropic oauth token missing", ErrEdgeCredentialUnavailable)
			}
			headers["Authorization"] = "Bearer " + tok
			headers["anthropic-beta"] = "oauth-2025-04-20"
			base := strings.TrimRight(strings.TrimSpace(acc.GetBaseURL()), "/")
			if base == "" {
				base = "https://api.anthropic.com"
			}
			return headers, base, nil
		}
		key := firstNonEmpty("api_key", "key")
		if key == "" {
			return nil, "", fmt.Errorf("%w: anthropic api_key missing", ErrEdgeCredentialUnavailable)
		}
		headers["x-api-key"] = key
		base := strings.TrimRight(strings.TrimSpace(acc.GetBaseURL()), "/")
		if base == "" {
			base = "https://api.anthropic.com"
		}
		return headers, base, nil

	case PlatformAntigravity, PlatformGemini:
		if accType == AccountTypeOAuth {
			tok := oauthTok("access_token", "oauth_token")
			if tok == "" {
				return nil, "", fmt.Errorf("%w: gemini/antigravity oauth token missing", ErrEdgeCredentialUnavailable)
			}
			headers["Authorization"] = "Bearer " + tok
			base := strings.TrimRight(firstNonEmpty("base_url"), "/")
			if base == "" {
				if platform == PlatformGemini && strings.EqualFold(firstNonEmpty("oauth_type"), "ai_studio") {
					base = "https://generativelanguage.googleapis.com"
				} else if platform == PlatformAntigravity {
					base = strings.TrimRight(resolveAntigravityForwardBaseURL(acc), "/")
					if base == "" {
						base = "https://cloudcode-pa.googleapis.com"
					}
				} else {
					base = "https://cloudcode-pa.googleapis.com"
				}
			}
			return headers, base, nil
		}
		key := firstNonEmpty("api_key", "key")
		if key == "" {
			return nil, "", fmt.Errorf("%w: gemini/antigravity api_key missing", ErrEdgeCredentialUnavailable)
		}
		headers["x-goog-api-key"] = key
		base := strings.TrimRight(strings.TrimSpace(acc.GetGeminiBaseURL("https://generativelanguage.googleapis.com")), "/")
		return headers, base, nil

	case PlatformGrok, "xai":
		tok := oauthTok("api_key", "access_token", "key")
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
