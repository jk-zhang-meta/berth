package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	infraerrors "github.com/jk-zhang-meta/berth/internal/pkg/errors"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
)

var (
	ErrEdgeLeaseInvalid           = infraerrors.New(http.StatusBadRequest, "EDGE_LEASE_INVALID", "Invalid edge lease request")
	ErrEdgeLeaseNotFound          = infraerrors.New(http.StatusNotFound, "EDGE_LEASE_NOT_FOUND", "Edge session lease not found")
	ErrEdgeLeaseForbidden         = infraerrors.New(http.StatusForbidden, "EDGE_LEASE_FORBIDDEN", "Edge session lease forbidden")
	ErrEdgeLeaseRevoked           = infraerrors.New(http.StatusForbidden, "EDGE_LEASE_REVOKED", "Edge session lease has been revoked")
	ErrEdgeCageRebindRequired     = infraerrors.New(http.StatusConflict, "cage_rebind_required", "Current cage cohort has no healthy accounts; rebind required")
	ErrCentralDirectEgressBlocked = infraerrors.New(http.StatusForbidden, "EDGE_DATA_PLANE_STRICT", "Direct AI provider egress from Berth Central is blocked when EDGE_DATA_PLANE_STRICT=true")
)

const (
	DefaultEdgeLeaseTTL    = 15 * time.Minute
	DefaultSnapshotTTL     = 60 * time.Second
	EnvEdgeSigningKey      = "BERTH_EDGE_SIGNING_KEY"
	EnvEdgeDataPlaneStrict = "EDGE_DATA_PLANE_STRICT"
)

// LoadOrGenerateEdgeSigningKey loads an Ed25519 keypair from envVar (32B seed or 64B private key
// in base64/hex), or loads/persists a 0600 key file at keyPath, or generates an ephemeral keypair.
func LoadOrGenerateEdgeSigningKey(envVar, keyPath string) (ed25519.PublicKey, ed25519.PrivateKey, string, error) {
	parsePriv := func(raw string) (ed25519.PrivateKey, error) {
		raw = strings.TrimSpace(raw)
		for _, dec := range []func(string) ([]byte, error){
			base64.RawURLEncoding.DecodeString,
			base64.StdEncoding.DecodeString,
			hex.DecodeString,
		} {
			b, err := dec(raw)
			if err != nil {
				continue
			}
			switch len(b) {
			case ed25519.SeedSize:
				return ed25519.NewKeyFromSeed(b), nil
			case ed25519.PrivateKeySize:
				return ed25519.PrivateKey(b), nil
			}
		}
		return nil, errors.New("invalid ed25519 private key encoding")
	}

	if envVar != "" {
		if val := strings.TrimSpace(os.Getenv(envVar)); val != "" {
			priv, err := parsePriv(val)
			if err != nil {
				return nil, nil, "", err
			}
			pub := priv.Public().(ed25519.PublicKey)
			return pub, priv, edgeproto.KeyIDFromPublicKey(pub), nil
		}
	}

	if keyPath != "" {
		if b, err := os.ReadFile(keyPath); err == nil {
			priv, err := parsePriv(string(b))
			if err != nil {
				return nil, nil, "", err
			}
			pub := priv.Public().(ed25519.PublicKey)
			return pub, priv, edgeproto.KeyIDFromPublicKey(pub), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, "", err
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, "", err
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			return nil, nil, "", err
		}
		enc := base64.RawURLEncoding.EncodeToString(priv.Seed())
		if err := os.WriteFile(keyPath, []byte(enc+"\n"), 0o600); err != nil {
			return nil, nil, "", err
		}
		return pub, priv, edgeproto.KeyIDFromPublicKey(pub), nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	return pub, priv, edgeproto.KeyIDFromPublicKey(pub), nil
}

// WorkSessionLeaseRecord represents a row in berth_work_session_leases.
type WorkSessionLeaseRecord struct {
	LeaseID            string               `json:"lease_id"`
	WorkSessionID      int64                `json:"work_session_id"`
	UserID             int64                `json:"user_id"`
	APIKeyID           int64                `json:"api_key_id"`
	Platform           string               `json:"platform"`
	AccountID          int64                `json:"account_id"`
	MarketplaceOrderID int64                `json:"marketplace_order_id,omitempty"`
	CageID            int64                `json:"cage_id"`
	CageEpoch         int64                `json:"cage_epoch"`
	GrantID           int64                `json:"grant_id"`
	LandingNodeID     int64                `json:"landing_node_id"`
	IngressNodeID     int64                `json:"ingress_node_id"`
	RouteChain        []edgeproto.RouteHop `json:"route_chain"`
	CohortTimezone    string               `json:"cohort_timezone"`
	CohortCountryCode string               `json:"cohort_country_code"`
	CohortLocale      string               `json:"cohort_locale"`
	LeaseEpoch        int64                `json:"lease_epoch"`
	RevSeq            int64                `json:"rev_seq"`
	ExpiresAt         time.Time            `json:"expires_at"`
	RevokedAt         *time.Time           `json:"revoked_at,omitempty"`
	CreatedAt         time.Time            `json:"created_at"`
}

// MintLeaseInput describes the AGS v2 POST /api/v1/ags/leases request.
type MintLeaseInput struct {
	UserID             int64          `json:"-"`
	APIKeyID           int64          `json:"-"`
	WorkSessionID      int64          `json:"work_session_id"`
	Agent              string         `json:"agent,omitempty"`
	Platform           string         `json:"platform"`
	AccountID          int64          `json:"account_id"`
	AccountPreference  []string       `json:"account_preference,omitempty"`
	CageID             int64          `json:"cage_id"`
	CageEpoch          int64          `json:"cage_epoch"`
	GrantID            int64          `json:"grant_id"`
	LandingNodeID      int64          `json:"landing_node_id"`
	PreferredZoneSlug  string         `json:"preferred_zone_slug"`
	ZonePreference     string         `json:"zone_preference,omitempty"`
	EntryRTTMs         map[int64]int  `json:"entry_rtt_ms,omitempty"`
	CohortHint         string         `json:"cohort_hint,omitempty"`
	PinnedZoneSlug     string         `json:"-"`
	PeerCountryCode    string         `json:"peer_country_code"`
	DNSHintDomain      string         `json:"dns_hint_domain"`
	DefaultRouteVPN    bool           `json:"default_route_vpn"`
	LastCleanZoneSlug  string         `json:"last_clean_zone_slug"`
	CohortTimezone     string         `json:"cohort_timezone"`
	CohortCountryCode  string         `json:"cohort_country_code"`
	CohortLocale       string         `json:"cohort_locale"`
	LiveReverseTunnels map[int64]bool `json:"-"`
}

// MintedLeaseCage describes the authoritative Cage metadata returned to AGS v2.
type MintedLeaseCage struct {
	CageID         int64  `json:"cage_id"`
	CageEpoch      int64  `json:"cage_epoch"`
	GateEpoch      int64  `json:"gate_epoch"`
	Timezone       string `json:"timezone"`
	CountryCode    string `json:"country_code"`
	Locale         string `json:"locale"`
	AcceptLanguage string `json:"accept_language,omitempty"`
	StrictMode     bool   `json:"strict_mode"`
}

// MintedIngressCandidate mirrors AGS v2's IngressCandidate contract.
type MintedIngressCandidate struct {
	NodeID   string `json:"node_id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	ProbeURL string `json:"probe_url"`
	Weight   int    `json:"weight"`
}

// MintedLeaseZonePlan mirrors AGS v2's LeaseZonePlan contract.
type MintedLeaseZonePlan struct {
	ZoneSlug          string                   `json:"zone_slug"`
	ZoneSource        string                   `json:"zone_source,omitempty"`
	IngressCandidates []MintedIngressCandidate `json:"ingress_candidates"`
	LandingNodeID     int64                    `json:"landing_node_id,omitempty"`
	LandingNodeName   string                   `json:"landing_node_name,omitempty"`
}

// MintedLeaseResponse matches the AGS v2 /api/v1/ags/leases JSON contract.
type MintedLeaseResponse struct {
	LeaseID       string               `json:"lease_id"`
	Token         string               `json:"token"`
	LeaseToken    string               `json:"lease_token"`
	LeaseEpoch    int64                `json:"lease_epoch"`
	RevSeq        int64                `json:"rev_seq"`
	ExpiresAt     time.Time            `json:"expires_at"`
	WorkSessionID int64                `json:"work_session_id"`
	Platform      string               `json:"platform"`
	AccountID     int64                `json:"account_id"`
	GrantID       int64                `json:"grant_id"`
	ClientZone    string               `json:"client_zone"`
	ZoneSource    string               `json:"zone_source"`
	IngressNode   *EdgeNode            `json:"ingress_node,omitempty"`
	LandingNode   *EdgeNode            `json:"landing_node,omitempty"`
	RouteChain    []edgeproto.RouteHop `json:"route_chain"`
	Cage          MintedLeaseCage      `json:"cage"`
	Zone          *MintedLeaseZonePlan `json:"zone,omitempty"`
}

// FailoverCandidate describes an eligible fallback account/landing node for failover evaluation.
type FailoverCandidate struct {
	AccountID         int64  `json:"account_id"`
	CageID            int64  `json:"cage_id"`
	CageEpoch         int64  `json:"cage_epoch"`
	GrantID           int64  `json:"grant_id"`
	LandingNodeID     int64  `json:"landing_node_id"`
	CohortTimezone    string `json:"cohort_timezone"`
	CohortCountryCode string `json:"cohort_country_code"`
	CohortLocale      string `json:"cohort_locale"`
}

// EdgeFailoverRequest is sent by Ingress Relay on upstream 429/529.
type EdgeFailoverRequest struct {
	LeaseID         string              `json:"lease_id"`
	FailedAccountID int64               `json:"failed_account_id"`
	StatusCode      int                 `json:"status_code"`
	Candidates      []FailoverCandidate `json:"candidates"`
	CallerNodeID    int64               `json:"-"` // Populated from authenticated Ed25519 node header
}

// CageRebindOffer carries recommended cohort details for HTTP 409 cage_rebind_required.
type CageRebindOffer struct {
	AccountID         int64  `json:"account_id"`
	LandingNodeID     int64  `json:"landing_node_id"`
	CohortTimezone    string `json:"cohort_timezone"`
	CohortCountryCode string `json:"cohort_country_code"`
	CohortLocale      string `json:"cohort_locale"`
}

// EdgeFailoverResponse either returns a fresh same-cohort signed lease or requires cage rebind.
type EdgeFailoverResponse struct {
	Action            string               `json:"action"` // "switched" | "cage_rebind_required"
	Code              string               `json:"code,omitempty"`
	Message           string               `json:"message,omitempty"`
	Lease             *MintedLeaseResponse `json:"lease,omitempty"`
	RecommendedCohort *CageRebindOffer     `json:"recommended_cohort,omitempty"`
}

// EdgeOAuthTask represents a Central-dispatched OAuth/refresh/probe task executed
// strictly by the bound Landing node so Central never contacts AI provider IPs.
type EdgeOAuthTask struct {
	TaskID          string              `json:"task_id"`
	NodeID          int64               `json:"node_id"`
	AccountID       int64               `json:"account_id"`
	Kind            string              `json:"kind"` // oauth_exchange | token_refresh | health_probe
	TargetURL       string              `json:"target_url"`
	Method          string              `json:"method"`
	Headers         map[string]string   `json:"headers,omitempty"`
	BodyBase64      string              `json:"body_base64,omitempty"`
	FollowRedirects bool                `json:"follow_redirects,omitempty"`
	ClaimID         string              `json:"claim_id,omitempty"`
	Status          string              `json:"status"` // pending | claimed | completed | failed
	StatusCode      int                 `json:"status_code,omitempty"`
	RespHeaders     map[string][]string `json:"resp_headers,omitempty"`
	RespBody        string              `json:"resp_body,omitempty"`
	RespBodyBase64  string              `json:"resp_body_base64,omitempty"`
	Error           string              `json:"error,omitempty"`
	CreatedAt       time.Time           `json:"created_at"`
	ClaimedAt       time.Time           `json:"-"`
	CompletedAt     time.Time           `json:"-"`
}

// BerthEdgeLeaseStore abstracts lease & revocation-sequence persistence.
type BerthEdgeLeaseStore interface {
	CurrentRevSeq(ctx context.Context) (int64, error)
	BumpRevSeq(ctx context.Context) (int64, error)
	InsertLease(ctx context.Context, rec WorkSessionLeaseRecord) error
	GetLease(ctx context.Context, leaseID string) (*WorkSessionLeaseRecord, error)
	RenewLeaseRecord(ctx context.Context, leaseID string, newExpiresAt time.Time, revSeq int64) (*WorkSessionLeaseRecord, error)
	RevokeLeaseRecord(ctx context.Context, leaseID string, revokedAt time.Time) (int64, error)
	ListActiveRevokedLeaseIDs(ctx context.Context, now time.Time) ([]string, error)
}

// BerthEdgeLeaseService manages Ed25519 Session Leases, signed RevocationSnapshots,
// failover coordination, Edge outbox ingestion, and Landing-dispatched OAuth tasks.
type BerthEdgeLeaseService struct {
	store               BerthEdgeLeaseStore
	zones               *BerthZoneService
	grants              *BerthLandingGrantService
	pubKey              ed25519.PublicKey
	privKey             ed25519.PrivateKey
	keyID               string
	leaseTTL            time.Duration
	snapshotTTL         time.Duration
	edgeDataPlaneStrict bool

	mu                sync.RWMutex
	telemetryDB       *sql.DB
	billingSvc        *BillingService
	onUsageIngested   func()
	revokedAPIKeys    map[int64]struct{}
	cageMinEpochs     map[int64]int64
	liveRevTunnels    map[int64]bool
	oauthTasksByNode  map[int64][]*EdgeOAuthTask
	oauthTaskIndex    map[string]*EdgeOAuthTask
	oauthWaiters      map[string]chan struct{}
	oauthNotifyByNode map[int64]chan struct{}
}

// NewBerthEdgeLeaseService constructs a PostgreSQL-backed BerthEdgeLeaseService.
func NewBerthEdgeLeaseService(
	db *sql.DB,
	zones *BerthZoneService,
	grants *BerthLandingGrantService,
	pub ed25519.PublicKey,
	priv ed25519.PrivateKey,
	keyID string,
) *BerthEdgeLeaseService {
	return NewBerthEdgeLeaseServiceWithStore(&sqlEdgeLeaseStore{db: db}, zones, grants, pub, priv, keyID)
}

// NewBerthEdgeLeaseServiceWithStore constructs a BerthEdgeLeaseService backed by a custom store.
func NewBerthEdgeLeaseServiceWithStore(
	store BerthEdgeLeaseStore,
	zones *BerthZoneService,
	grants *BerthLandingGrantService,
	pub ed25519.PublicKey,
	priv ed25519.PrivateKey,
	keyID string,
) *BerthEdgeLeaseService {
	if len(pub) == 0 && len(priv) == ed25519.PrivateKeySize {
		pub = priv.Public().(ed25519.PublicKey)
	}
	if keyID == "" && len(pub) == ed25519.PublicKeySize {
		keyID = edgeproto.KeyIDFromPublicKey(pub)
	}
	strict := strings.EqualFold(strings.TrimSpace(os.Getenv(EnvEdgeDataPlaneStrict)), "true")
	return &BerthEdgeLeaseService{
		store:               store,
		zones:               zones,
		grants:              grants,
		pubKey:              pub,
		privKey:             priv,
		keyID:               keyID,
		leaseTTL:            DefaultEdgeLeaseTTL,
		snapshotTTL:         DefaultSnapshotTTL,
		edgeDataPlaneStrict: strict,
		revokedAPIKeys:      make(map[int64]struct{}),
		cageMinEpochs:       make(map[int64]int64),
		liveRevTunnels:      make(map[int64]bool),
		oauthTasksByNode:    make(map[int64][]*EdgeOAuthTask),
		oauthTaskIndex:      make(map[string]*EdgeOAuthTask),
		oauthWaiters:        make(map[string]chan struct{}),
		oauthNotifyByNode:   make(map[int64]chan struct{}),
	}
}

func (s *BerthEdgeLeaseService) PublicKey() ed25519.PublicKey { return s.pubKey }
func (s *BerthEdgeLeaseService) PublicKeyBase64() string {
	return base64.RawURLEncoding.EncodeToString(s.pubKey)
}
func (s *BerthEdgeLeaseService) KeyID() string { return s.keyID }

func (s *BerthEdgeLeaseService) SetEdgeDataPlaneStrict(strict bool) {
	s.mu.Lock()
	s.edgeDataPlaneStrict = strict
	s.mu.Unlock()
}

func (s *BerthEdgeLeaseService) SetSnapshotTTL(d time.Duration) {
	if d > 0 {
		s.snapshotTTL = d
	}
}

func (s *BerthEdgeLeaseService) SetLeaseTTL(d time.Duration) {
	if d > 0 {
		s.leaseTTL = d
	}
}

// AssertDirectProviderEgressAllowed enforces Codex Blocker #1.1 on Central.
func (s *BerthEdgeLeaseService) AssertDirectProviderEgressAllowed() error {
	s.mu.RLock()
	strict := s.edgeDataPlaneStrict
	s.mu.RUnlock()
	if strict {
		return ErrCentralDirectEgressBlocked
	}
	return nil
}

// SetReverseTunnelLive updates Central's view of a NAT/home Landing node's live reverse tunnel.
func (s *BerthEdgeLeaseService) SetReverseTunnelLive(nodeID int64, live bool) {
	s.mu.Lock()
	if live {
		s.liveRevTunnels[nodeID] = true
	} else {
		delete(s.liveRevTunnels, nodeID)
	}
	s.mu.Unlock()
}

func (s *BerthEdgeLeaseService) liveTunnelsSnapshot(override map[int64]bool) map[int64]bool {
	if override != nil {
		return override
	}
	var zoneSnap map[int64]bool
	if s.zones != nil {
		zoneSnap = s.zones.LiveReverseTunnelsSnapshot(time.Now())
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.liveRevTunnels) == 0 && zoneSnap == nil {
		return nil
	}
	cp := make(map[int64]bool, len(s.liveRevTunnels)+len(zoneSnap))
	for k, v := range zoneSnap {
		if v {
			cp[k] = true
		}
	}
	for k, v := range s.liveRevTunnels {
		if v {
			cp[k] = true
		}
	}
	return cp
}

func normalizePOSIXLocale(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "en_US.UTF-8"
	}
	if strings.Contains(trimmed, ".") || strings.Contains(trimmed, "@") || !strings.Contains(trimmed, "_") {
		return trimmed
	}
	return trimmed + ".UTF-8"
}

func mapAgentToPlatform(agent string) string {
	switch strings.ToLower(strings.TrimSpace(agent)) {
	case "codex", "openai":
		return "openai"
	case "claude", "claude-code", "anthropic":
		return "anthropic"
	case "agy", "antigravity", "gemini":
		return "antigravity"
	case "grok", "xai":
		return "grok"
	default:
		return strings.ToLower(strings.TrimSpace(agent))
	}
}

type edgeLeaseAccountResolver interface {
	ResolveAccountForLease(ctx context.Context, userID int64, platform string, preferred []string) (int64, error)
}

type edgeLeaseAuthorizedAccountResolver interface {
	ResolveAuthorizedAccountForLease(ctx context.Context, userID, apiKeyID int64, platform string, preferred []string) (int64, error)
	VerifyAccountAccessForLease(ctx context.Context, userID, apiKeyID, accountID int64) (bool, error)
	ResolveActiveGrantForProxy(ctx context.Context, proxyID int64) (int64, error)
	RevokeUserGroupLeases(ctx context.Context, userID, groupID int64, revokedAt time.Time) (int, int64, error)
}

type edgeLeaseAccountProxyResolver interface {
	ResolveAccountProxyBinding(ctx context.Context, accountID int64) (proxyID int64, pinnedEdgeNodeID int64, err error)
}

type edgeLeaseAccountCageResolver interface {
	ResolveAccountCageState(ctx context.Context, accountID int64) (cageID, gateEpoch int64, gateState, tz, cc, locale string, found bool, err error)
}

type edgeLeaseDurableRevocationStore interface {
	PersistCageMinEpoch(ctx context.Context, cageID, minEpoch int64) (int64, error)
	PersistRevokedAPIKey(ctx context.Context, apiKeyID int64, reason string) (int64, error)
	ListPersistedCageMinEpochs(ctx context.Context) (map[int64]int64, error)
	ListPersistedRevokedAPIKeys(ctx context.Context) ([]int64, error)
}

type edgeLeaseFailoverCandidateResolver interface {
	ListAuthorizedFailoverCandidates(ctx context.Context, userID, apiKeyID int64, platform string, excludeAccountID int64) ([]FailoverCandidate, error)
}

type edgeLeaseMarketplaceOrderResolver interface {
	ResolveActiveMarketplaceOrderForLease(ctx context.Context, userID, apiKeyID, accountID int64) (orderID int64, orderExpiresAt *time.Time, accountExpiresAt *time.Time, err error)
}

// MintLease resolves client zone, validates grant & landing node, solves shortest route,
// persists berth_work_session_leases, and signs a compact Ed25519 SessionLease JWS.
func (s *BerthEdgeLeaseService) MintLease(ctx context.Context, in MintLeaseInput) (*MintedLeaseResponse, error) {
	if in.Platform == "" && in.Agent != "" {
		in.Platform = mapAgentToPlatform(in.Agent)
	}
	if in.PreferredZoneSlug == "" && in.ZonePreference != "" && !strings.EqualFold(strings.TrimSpace(in.ZonePreference), "auto") {
		in.PreferredZoneSlug = strings.TrimSpace(in.ZonePreference)
	}
	now := time.Now()

	// 1. Resolve and strictly authorize the active schedulable account FIRST (honoring API key group,
	//    steward ownership, and active marketplace rental orders) so we can pin its landing node.
	if in.UserID > 0 {
		if authResolver, ok := s.store.(edgeLeaseAuthorizedAccountResolver); ok {
			if in.AccountID <= 0 {
				// If a CohortHint was supplied (e.g. during 409 cage_rebind_required) and no explicit
				// account preference was pinned, prefer an authorized account matching that cohort first.
				if hint := strings.TrimSpace(in.CohortHint); hint != "" && len(in.AccountPreference) == 0 {
					if foResolver, ok := s.store.(edgeLeaseFailoverCandidateResolver); ok {
						if cands, cErr := foResolver.ListAuthorizedFailoverCandidates(ctx, in.UserID, in.APIKeyID, in.Platform, 0); cErr == nil {
							for _, cand := range cands {
								if strings.EqualFold(strings.TrimSpace(cand.CohortTimezone), hint) ||
									strings.EqualFold(strings.TrimSpace(cand.CohortCountryCode), hint) {
									in.AccountID = cand.AccountID
									break
								}
							}
						}
					}
				}
			}
			if in.AccountID <= 0 {
				resolvedID, rErr := authResolver.ResolveAuthorizedAccountForLease(ctx, in.UserID, in.APIKeyID, in.Platform, in.AccountPreference)
				if rErr != nil && !errors.Is(rErr, sql.ErrNoRows) {
					return nil, fmt.Errorf("resolve authorized account for lease: %w", rErr)
				}
				if resolvedID <= 0 {
					return nil, fmt.Errorf("%w: no authorized active account available for platform %q", ErrEdgeLeaseForbidden, in.Platform)
				}
				in.AccountID = resolvedID
			} else {
				allowed, vErr := authResolver.VerifyAccountAccessForLease(ctx, in.UserID, in.APIKeyID, in.AccountID)
				if vErr != nil {
					return nil, fmt.Errorf("verify account %d lease access: %w", in.AccountID, vErr)
				}
				if !allowed {
					return nil, fmt.Errorf("%w: caller is not authorized to use account %d", ErrEdgeLeaseForbidden, in.AccountID)
				}
			}
		} else if in.AccountID <= 0 {
			if resolver, ok := s.store.(edgeLeaseAccountResolver); ok {
				if resolvedID, rErr := resolver.ResolveAccountForLease(ctx, in.UserID, in.Platform, in.AccountPreference); rErr == nil && resolvedID > 0 {
					in.AccountID = resolvedID
				}
			}
		}
	}

	var pinnedProxyID int64
	var pinnedEdgeNodeID int64
	if in.AccountID > 0 {
		if pr, ok := s.store.(edgeLeaseAccountProxyResolver); ok {
			pid, eid, pErr := pr.ResolveAccountProxyBinding(ctx, in.AccountID)
			if pErr != nil && !errors.Is(pErr, sql.ErrNoRows) {
				return nil, fmt.Errorf("resolve account %d proxy binding: %w", in.AccountID, pErr)
			}
			pinnedProxyID = pid
			pinnedEdgeNodeID = eid
		}
	}

	// Enforce authoritative edge landing pin before any auto-resolution or explicit override.
	if pinnedEdgeNodeID > 0 && in.LandingNodeID > 0 && in.LandingNodeID != pinnedEdgeNodeID {
		return nil, fmt.Errorf("%w: account %d is pinned to landing node %d (cannot route via %d)",
			ErrLandingGrantForbidden, in.AccountID, pinnedEdgeNodeID, in.LandingNodeID)
	}

	// 2. Auto-resolve an eligible active Admin Landing Grant & active Landing node when
	//    AGS v2 omits explicit landing_node_id/grant_id. For marketplace renters using an
	//    authorized rented account pinned to a seller's landing proxy, resolve the active
	//    grant backing that pinned proxy so traffic exits strictly from the account's IP.
	grantBackedByAuthorizedAccount := false
	if in.UserID > 0 && s.grants != nil {
		if in.LandingNodeID <= 0 && in.GrantID > 0 {
			if g, gErr := s.grants.GetGrant(ctx, in.GrantID); gErr == nil && g != nil {
				in.LandingNodeID = g.NodeID
			}
		}
		if pinnedEdgeNodeID > 0 && in.LandingNodeID > 0 && in.LandingNodeID != pinnedEdgeNodeID {
			return nil, fmt.Errorf("%w: grant %d does not match account %d pinned landing node %d",
				ErrLandingGrantForbidden, in.GrantID, in.AccountID, pinnedEdgeNodeID)
		}
		if in.LandingNodeID <= 0 {
			userGrants, gErr := s.grants.ListUserGrants(ctx, in.UserID)
			if gErr != nil {
				return nil, fmt.Errorf("list user grants: %w", gErr)
			}
			hint := strings.ToLower(strings.TrimSpace(in.CohortHint))
			var pinnedGrant *LandingNodeGrant
			var hintGrant *LandingNodeGrant
			var fallbackGrant *LandingNodeGrant
			for i := range userGrants {
				g := &userGrants[i]
				if g.Status != GrantStatusActive {
					continue
				}
				if g.ExpiresAt != nil && !now.Before(*g.ExpiresAt) {
					continue
				}
				if g.MaxBytes > 0 && g.RemainingBytes <= 0 {
					continue
				}
				node, nErr := s.zones.GetNode(ctx, g.NodeID)
				if nErr != nil || node == nil || node.Status != EdgeNodeStatusActive {
					continue
				}
				if pinnedProxyID > 0 && g.ProxyID != nil && *g.ProxyID == pinnedProxyID {
					pinnedGrant = g
					break
				}
				if pinnedEdgeNodeID > 0 && g.NodeID == pinnedEdgeNodeID && pinnedGrant == nil {
					pinnedGrant = g
					continue
				}
				if pinnedEdgeNodeID > 0 {
					// Account has an authoritative edge landing pin; never select a different landing node.
					continue
				}
				if fallbackGrant == nil {
					fallbackGrant = g
				}
				if hintGrant == nil && hint != "" && (strings.Contains(strings.ToLower(node.Name), hint) ||
					strings.Contains(strings.ToLower(node.ExitTimezone), hint) ||
					strings.EqualFold(node.ExitCountryCode, hint)) {
					hintGrant = g
				}
			}
			chosen := pinnedGrant
			if chosen == nil && pinnedEdgeNodeID > 0 && pinnedProxyID > 0 {
				// Authorized renter/caller on an account pinned to a seller's edge landing proxy:
				// bind the active grant backing that proxy so the rented account exits from its pinned IP.
				if authResolver, ok := s.store.(edgeLeaseAuthorizedAccountResolver); ok {
					if backingGrantID, bErr := authResolver.ResolveActiveGrantForProxy(ctx, pinnedProxyID); bErr == nil && backingGrantID > 0 {
						if bg, bgErr := s.grants.GetGrant(ctx, backingGrantID); bgErr == nil && bg != nil && bg.Status == GrantStatusActive && bg.NodeID == pinnedEdgeNodeID {
							chosen = bg
							grantBackedByAuthorizedAccount = true
						}
					}
				}
			}
			if chosen == nil && pinnedEdgeNodeID > 0 {
				return nil, fmt.Errorf("%w: no active landing grant matches account %d pinned landing node %d",
					ErrNoRouteAvailable, in.AccountID, pinnedEdgeNodeID)
			}
			if chosen == nil {
				chosen = hintGrant
			}
			if chosen == nil {
				chosen = fallbackGrant
			}
			if chosen != nil {
				in.GrantID = chosen.ID
				in.LandingNodeID = chosen.NodeID
			}
		}
	}

	if in.UserID <= 0 || in.AccountID <= 0 || in.LandingNodeID <= 0 {
		return nil, fmt.Errorf("%w: user_id, account_id, and landing_node_id are required", ErrEdgeLeaseInvalid)
	}
	if pinnedEdgeNodeID > 0 && in.LandingNodeID != pinnedEdgeNodeID {
		return nil, fmt.Errorf("%w: account %d must exit via pinned landing node %d",
			ErrLandingGrantForbidden, in.AccountID, pinnedEdgeNodeID)
	}

	// Validate landing node.
	landingNode, err := s.zones.GetNode(ctx, in.LandingNodeID)
	if err != nil {
		return nil, err
	}
	if landingNode.Status != EdgeNodeStatusActive {
		return nil, fmt.Errorf("%w: landing node %s is not active", ErrNoRouteAvailable, landingNode.Name)
	}

	// Validate landing grant. When an account is pinned to a Berth Edge Landing proxy,
	// enforce a positive active grant even if the caller supplied landing_node_id directly.
	if in.GrantID <= 0 && pinnedEdgeNodeID > 0 && pinnedProxyID > 0 && s.grants != nil {
		if authResolver, ok := s.store.(edgeLeaseAuthorizedAccountResolver); ok {
			if backingGrantID, bErr := authResolver.ResolveActiveGrantForProxy(ctx, pinnedProxyID); bErr == nil && backingGrantID > 0 {
				in.GrantID = backingGrantID
				grantBackedByAuthorizedAccount = true
			}
		}
		if in.GrantID <= 0 {
			return nil, fmt.Errorf("%w: active landing grant required for account %d pinned to landing node %d",
				ErrLandingGrantForbidden, in.AccountID, pinnedEdgeNodeID)
		}
	}
	var grantExpiry *time.Time
	if in.GrantID > 0 && s.grants != nil {
		grant, err := s.grants.GetGrant(ctx, in.GrantID)
		if err != nil {
			return nil, err
		}
		if grant.GranteeUserID != in.UserID {
			if !(grantBackedByAuthorizedAccount && pinnedProxyID > 0 && grant.ProxyID != nil && *grant.ProxyID == pinnedProxyID) {
				return nil, ErrLandingGrantForbidden
			}
		}
		if grant.NodeID != in.LandingNodeID {
			return nil, ErrLandingGrantForbidden
		}
		if pinnedEdgeNodeID > 0 && grant.NodeID != pinnedEdgeNodeID {
			return nil, ErrLandingGrantForbidden
		}
		if pinnedEdgeNodeID > 0 && pinnedProxyID > 0 && grant.ProxyID != nil && *grant.ProxyID != pinnedProxyID {
			return nil, ErrLandingGrantForbidden
		}
		if grant.Status != GrantStatusActive {
			return nil, ErrLandingGrantInactive
		}
		if grant.ExpiresAt != nil {
			if !now.Before(*grant.ExpiresAt) {
				return nil, ErrLandingGrantExpired
			}
			t := *grant.ExpiresAt
			grantExpiry = &t
		}
		if grant.MaxBytes > 0 && grant.RemainingBytes <= 0 {
			return nil, ErrLandingGrantQuotaExhausted
		}
	}

	// Resolve client zone via FR-138.
	zoneRes, err := s.zones.ResolveClientZone(ctx, ZoneResolutionInput{
		PinnedZoneSlug:    in.PinnedZoneSlug,
		PreferredZoneSlug: in.PreferredZoneSlug,
		PeerCountryCode:   in.PeerCountryCode,
		DNSHintDomain:     in.DNSHintDomain,
		DefaultRouteVPN:   in.DefaultRouteVPN,
		LastCleanZoneSlug: in.LastCleanZoneSlug,
		Now:               now,
	})
	if err != nil {
		return nil, err
	}

	var clientZoneID int64
	clientZoneSlug := ""
	if zoneRes.Zone != nil {
		clientZoneID = zoneRes.Zone.ID
		clientZoneSlug = zoneRes.Zone.Slug
	}

	// Select best zone entry node and compute end-to-end Dijkstra route_chain.
	liveTunnels := s.liveTunnelsSnapshot(in.LiveReverseTunnels)
	ingressNode, routeChain, _, err := s.zones.SelectBestIngressAndRouteWithRTT(ctx, clientZoneID, landingNode.ID, liveTunnels, in.EntryRTTMs)
	if err != nil && clientZoneID > 0 {
		// Fall back to any non-centre entry if resolved zone has no reachable entry node.
		ingressNode, routeChain, _, err = s.zones.SelectBestIngressAndRouteWithRTT(ctx, 0, landingNode.ID, liveTunnels, in.EntryRTTMs)
	}
	if err != nil {
		return nil, err
	}

	cohortTZ := strings.TrimSpace(in.CohortTimezone)
	cohortCC := strings.TrimSpace(in.CohortCountryCode)
	cohortLocale := strings.TrimSpace(in.CohortLocale)
	cageID := in.CageID
	cageEpoch := in.CageEpoch

	// Derive authoritative cage_id, cage_epoch, gate_state, and cohort from DB
	// account_cages whenever backed by SQL (never trust caller-supplied cage claims).
	if cageResolver, ok := s.store.(edgeLeaseAccountCageResolver); ok && in.AccountID > 0 {
		dbCageID, dbEpoch, gateState, dbTZ, dbCC, dbLocale, found, cErr := cageResolver.ResolveAccountCageState(ctx, in.AccountID)
		if cErr != nil {
			return nil, fmt.Errorf("resolve account %d cage state: %w", in.AccountID, cErr)
		}
		if found {
			if gateState == CageGateStateQuarantined || gateState == CageGateStateClosed {
				return nil, fmt.Errorf("%w: account %d cage %d is %s", ErrEdgeLeaseForbidden, in.AccountID, dbCageID, gateState)
			}
			cageID = dbCageID
			cageEpoch = dbEpoch
			if strings.TrimSpace(dbTZ) != "" {
				cohortTZ = strings.TrimSpace(dbTZ)
			}
			if strings.TrimSpace(dbCC) != "" {
				cohortCC = strings.TrimSpace(dbCC)
			}
			if strings.TrimSpace(dbLocale) != "" {
				cohortLocale = strings.TrimSpace(dbLocale)
			}
		}
	}
	if cohortTZ == "" {
		cohortTZ = landingNode.ExitTimezone
	}
	if cohortCC == "" {
		cohortCC = landingNode.ExitCountryCode
	}
	if cohortLocale == "" {
		cohortLocale = landingNode.ExitLocale
	}
	cohortLocale = normalizePOSIXLocale(cohortLocale)
	if cageEpoch <= 0 {
		cageEpoch = 1
	}
	in.CageID = cageID

	revSeq, err := s.store.CurrentRevSeq(ctx)
	if err != nil {
		return nil, err
	}

	leaseID := uuid.NewString()
	exp := now.Add(s.leaseTTL)
	if grantExpiry != nil && grantExpiry.Before(exp) {
		exp = *grantExpiry
	}
	var marketplaceOrderID int64
	if ordResolver, ok := s.store.(edgeLeaseMarketplaceOrderResolver); ok && in.UserID > 0 && in.AccountID > 0 {
		oid, orderExp, acctExp, oErr := ordResolver.ResolveActiveMarketplaceOrderForLease(ctx, in.UserID, in.APIKeyID, in.AccountID)
		if oErr != nil {
			return nil, fmt.Errorf("resolve marketplace rental order for lease: %w", oErr)
		}
		marketplaceOrderID = oid
		if orderExp != nil {
			if !now.Before(*orderExp) {
				return nil, ErrEdgeLeaseForbidden
			}
			if orderExp.Before(exp) {
				exp = *orderExp
			}
		}
		if acctExp != nil {
			if !now.Before(*acctExp) {
				return nil, ErrEdgeLeaseForbidden
			}
			if acctExp.Before(exp) {
				exp = *acctExp
			}
		}
	}
	rec := WorkSessionLeaseRecord{
		LeaseID:            leaseID,
		WorkSessionID:      in.WorkSessionID,
		UserID:             in.UserID,
		APIKeyID:           in.APIKeyID,
		Platform:           in.Platform,
		AccountID:          in.AccountID,
		MarketplaceOrderID: marketplaceOrderID,
		CageID:             in.CageID,
		CageEpoch:          cageEpoch,
		GrantID:            in.GrantID,
		LandingNodeID:      landingNode.ID,
		IngressNodeID:      ingressNode.ID,
		RouteChain:         routeChain,
		CohortTimezone:     cohortTZ,
		CohortCountryCode:  cohortCC,
		CohortLocale:       cohortLocale,
		LeaseEpoch:         1,
		RevSeq:             revSeq,
		ExpiresAt:          exp,
		CreatedAt:          now,
	}
	if err := s.store.InsertLease(ctx, rec); err != nil {
		return nil, err
	}

	tok, err := s.signRecord(rec, now)
	if err != nil {
		return nil, err
	}

	return buildMintedLeaseResponse(rec, tok, clientZoneSlug, zoneRes.Source, ingressNode, landingNode), nil
}

func redactEdgeNodeForTenant(n *EdgeNode, isIngress bool) *EdgeNode {
	if n == nil {
		return nil
	}
	out := &EdgeNode{
		ID:              n.ID,
		Name:            n.Name,
		ZoneID:          n.ZoneID,
		Roles:           append([]string(nil), n.Roles...),
		ConnectMode:     n.ConnectMode,
		ExitCountryCode: n.ExitCountryCode,
		ExitTimezone:    n.ExitTimezone,
		ExitLocale:      n.ExitLocale,
		Status:          n.Status,
	}
	if isIngress {
		out.PublicAddr = n.PublicAddr
	}
	return out
}

func buildMintedLeaseResponse(
	rec WorkSessionLeaseRecord,
	tok string,
	clientZoneSlug string,
	zoneSource string,
	ingressNode *EdgeNode,
	landingNode *EdgeNode,
) *MintedLeaseResponse {
	zonePlan := &MintedLeaseZonePlan{
		ZoneSlug:   clientZoneSlug,
		ZoneSource: zoneSource,
	}
	if ingressNode != nil && strings.TrimSpace(ingressNode.PublicAddr) != "" {
		rawURL := strings.TrimSpace(ingressNode.PublicAddr)
		if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
			rawURL = "https://" + rawURL
		}
		rawURL = strings.TrimRight(rawURL, "/")
		zonePlan.IngressCandidates = []MintedIngressCandidate{
			{
				NodeID:   fmt.Sprintf("%d", ingressNode.ID),
				Name:     ingressNode.Name,
				URL:      rawURL,
				ProbeURL: rawURL + "/healthz",
				Weight:   100,
			},
		}
	}
	if landingNode != nil {
		zonePlan.LandingNodeID = landingNode.ID
		zonePlan.LandingNodeName = landingNode.Name
	}
	acceptLang := DeriveGeoIdentity(rec.CohortCountryCode, rec.CohortTimezone).AcceptLanguage
	return &MintedLeaseResponse{
		LeaseID:       rec.LeaseID,
		Token:         tok,
		LeaseToken:    tok,
		LeaseEpoch:    rec.LeaseEpoch,
		RevSeq:        rec.RevSeq,
		ExpiresAt:     rec.ExpiresAt,
		WorkSessionID: rec.WorkSessionID,
		Platform:      rec.Platform,
		AccountID:     rec.AccountID,
		GrantID:       rec.GrantID,
		ClientZone:    clientZoneSlug,
		ZoneSource:    zoneSource,
		IngressNode:   redactEdgeNodeForTenant(ingressNode, true),
		LandingNode:   redactEdgeNodeForTenant(landingNode, false),
		RouteChain:    rec.RouteChain,
		Cage: MintedLeaseCage{
			CageID:         rec.CageID,
			CageEpoch:      rec.CageEpoch,
			GateEpoch:      rec.CageEpoch,
			Timezone:       rec.CohortTimezone,
			CountryCode:    rec.CohortCountryCode,
			Locale:         rec.CohortLocale,
			AcceptLanguage: acceptLang,
			StrictMode:     true,
		},
		Zone: zonePlan,
	}
}

func (s *BerthEdgeLeaseService) signRecord(rec WorkSessionLeaseRecord, now time.Time) (string, error) {
	claims := edgeproto.SessionLeaseClaims{
		LeaseID:           rec.LeaseID,
		JTI:               uuid.NewString(),
		UserID:            rec.UserID,
		APIKeyID:          rec.APIKeyID,
		WorkSessionID:     rec.WorkSessionID,
		Platform:          rec.Platform,
		AccountID:         rec.AccountID,
		CageID:            rec.CageID,
		CageEpoch:         rec.CageEpoch,
		GrantID:           rec.GrantID,
		IngressNodeID:     rec.IngressNodeID,
		LandingNodeID:     rec.LandingNodeID,
		RouteChain:        rec.RouteChain,
		CohortTimezone:    rec.CohortTimezone,
		CohortCountryCode: rec.CohortCountryCode,
		CohortLocale:      rec.CohortLocale,
		RevSeq:            rec.RevSeq,
		LeaseEpoch:        rec.LeaseEpoch,
		IssuedAt:          now.Unix(),
		ExpiresAt:         rec.ExpiresAt.Unix(),
	}
	return edgeproto.SignLease(s.privKey, s.keyID, claims)
}

// RenewLease extends an existing non-revoked lease belonging to userID and mints a fresh signed token.
func (s *BerthEdgeLeaseService) RenewLease(ctx context.Context, userID int64, leaseID string) (*MintedLeaseResponse, error) {
	return s.RenewLeaseWithKey(ctx, userID, 0, leaseID)
}

// RenewLeaseWithKey extends an existing non-revoked, non-expired lease belonging to
// (userID, apiKeyID) after re-verifying account access, current landing pin, and grant validity.
func (s *BerthEdgeLeaseService) RenewLeaseWithKey(ctx context.Context, userID, callerAPIKeyID int64, leaseID string) (*MintedLeaseResponse, error) {
	rec, err := s.store.GetLease(ctx, leaseID)
	if err != nil {
		return nil, err
	}
	if userID > 0 && rec.UserID != userID {
		return nil, ErrEdgeLeaseForbidden
	}
	if callerAPIKeyID > 0 && rec.APIKeyID > 0 && callerAPIKeyID != rec.APIKeyID {
		return nil, ErrEdgeLeaseForbidden
	}
	if rec.RevokedAt != nil || (!rec.ExpiresAt.IsZero() && !time.Now().Before(rec.ExpiresAt)) {
		return nil, ErrEdgeLeaseRevoked
	}
	now := time.Now()
	if !rec.ExpiresAt.IsZero() && !now.Before(rec.ExpiresAt) {
		return nil, ErrEdgeLeaseRevoked
	}
	if authResolver, ok := s.store.(edgeLeaseAuthorizedAccountResolver); ok && rec.UserID > 0 && rec.AccountID > 0 {
		allowed, vErr := authResolver.VerifyAccountAccessForLease(ctx, rec.UserID, rec.APIKeyID, rec.AccountID)
		if vErr != nil {
			return nil, fmt.Errorf("re-verify lease account access: %w", vErr)
		}
		if !allowed {
			return nil, ErrEdgeLeaseForbidden
		}
	}
	if bindingResolver, ok := s.store.(edgeLeaseAccountProxyResolver); ok && rec.AccountID > 0 && rec.LandingNodeID > 0 {
		_, currentEdgeNodeID, bErr := bindingResolver.ResolveAccountProxyBinding(ctx, rec.AccountID)
		if bErr != nil {
			return nil, fmt.Errorf("re-verify account landing binding: %w", bErr)
		}
		if currentEdgeNodeID > 0 && currentEdgeNodeID != rec.LandingNodeID {
			return nil, ErrEdgeLeaseForbidden
		}
	}
	if cageResolver, ok := s.store.(edgeLeaseAccountCageResolver); ok && rec.AccountID > 0 {
		_, dbEpoch, gateState, _, _, _, found, cErr := cageResolver.ResolveAccountCageState(ctx, rec.AccountID)
		if cErr != nil {
			return nil, fmt.Errorf("re-verify account cage state: %w", cErr)
		}
		if found {
			if gateState == CageGateStateQuarantined || gateState == CageGateStateClosed {
				return nil, ErrEdgeLeaseRevoked
			}
			if rec.CageEpoch > 0 && dbEpoch > rec.CageEpoch {
				return nil, ErrEdgeLeaseRevoked
			}
		}
	}

	nextExpiry := now.Add(s.leaseTTL)
	if rec.GrantID > 0 && s.grants != nil {
		grant, err := s.grants.GetGrant(ctx, rec.GrantID)
		if err != nil {
			return nil, err
		}
		if grant.Status != GrantStatusActive {
			return nil, ErrLandingGrantInactive
		}
		if grant.ExpiresAt != nil {
			if !now.Before(*grant.ExpiresAt) {
				return nil, ErrLandingGrantExpired
			}
			if grant.ExpiresAt.Before(nextExpiry) {
				nextExpiry = *grant.ExpiresAt
			}
		}
	}
	if ordResolver, ok := s.store.(edgeLeaseMarketplaceOrderResolver); ok && rec.UserID > 0 && rec.AccountID > 0 {
		_, orderExp, acctExp, oErr := ordResolver.ResolveActiveMarketplaceOrderForLease(ctx, rec.UserID, rec.APIKeyID, rec.AccountID)
		if oErr != nil {
			return nil, fmt.Errorf("re-verify marketplace order expiry: %w", oErr)
		}
		if orderExp != nil {
			if !now.Before(*orderExp) {
				return nil, ErrEdgeLeaseRevoked
			}
			if orderExp.Before(nextExpiry) {
				nextExpiry = *orderExp
			}
		}
		if acctExp != nil {
			if !now.Before(*acctExp) {
				return nil, ErrEdgeLeaseRevoked
			}
			if acctExp.Before(nextExpiry) {
				nextExpiry = *acctExp
			}
		}
	}

	revSeq, err := s.store.CurrentRevSeq(ctx)
	if err != nil {
		return nil, err
	}
	updated, err := s.store.RenewLeaseRecord(ctx, leaseID, nextExpiry, revSeq)
	if err != nil {
		return nil, err
	}
	tok, err := s.signRecord(*updated, now)
	if err != nil {
		return nil, err
	}
	landingNode, _ := s.zones.GetNode(ctx, updated.LandingNodeID)
	ingressNode, _ := s.zones.GetNode(ctx, updated.IngressNodeID)
	zoneSlug := ""
	if ingressNode != nil && ingressNode.ZoneID > 0 {
		if zones, zErr := s.zones.ListZones(ctx); zErr == nil {
			for _, z := range zones {
				if z.ID == ingressNode.ZoneID {
					zoneSlug = z.Slug
					break
				}
			}
		}
	}
	return buildMintedLeaseResponse(*updated, tok, zoneSlug, "renew", ingressNode, landingNode), nil
}

// GetLeaseRecord returns the persisted lease record by leaseID.
func (s *BerthEdgeLeaseService) GetLeaseRecord(ctx context.Context, leaseID string) (*WorkSessionLeaseRecord, error) {
	if s == nil || s.store == nil || strings.TrimSpace(leaseID) == "" {
		return nil, ErrEdgeLeaseNotFound
	}
	return s.store.GetLease(ctx, leaseID)
}

// RevokeLease revokes leaseID and immediately bumps monotonic rev_seq.
func (s *BerthEdgeLeaseService) RevokeLease(ctx context.Context, userID int64, isAdmin bool, leaseID string) (int64, error) {
	return s.RevokeLeaseWithKey(ctx, userID, 0, isAdmin, leaseID)
}

// RevokeLeaseWithKey revokes leaseID while preventing sibling API keys from
// revoking another API key's lease.
func (s *BerthEdgeLeaseService) RevokeLeaseWithKey(ctx context.Context, userID, callerAPIKeyID int64, isAdmin bool, leaseID string) (int64, error) {
	rec, err := s.store.GetLease(ctx, leaseID)
	if err != nil {
		return 0, err
	}
	if !isAdmin && rec.UserID != userID {
		return 0, ErrEdgeLeaseForbidden
	}
	if !isAdmin && callerAPIKeyID > 0 && rec.APIKeyID > 0 && callerAPIKeyID != rec.APIKeyID {
		return 0, ErrEdgeLeaseForbidden
	}
	return s.store.RevokeLeaseRecord(ctx, leaseID, time.Now())
}

func (s *BerthEdgeLeaseService) recordLocalCageMinEpoch(cageID, minEpoch int64) {
	if s == nil || cageID <= 0 || minEpoch <= 0 {
		return
	}
	s.mu.Lock()
	if cur := s.cageMinEpochs[cageID]; minEpoch > cur {
		s.cageMinEpochs[cageID] = minEpoch
	}
	s.mu.Unlock()
}

// BumpCageMinEpoch raises the minimum authorized cage epoch for cageID and bumps rev_seq.
func (s *BerthEdgeLeaseService) BumpCageMinEpoch(ctx context.Context, cageID, minEpoch int64) (int64, error) {
	if cageID <= 0 || minEpoch <= 0 {
		return 0, ErrEdgeLeaseInvalid
	}
	s.recordLocalCageMinEpoch(cageID, minEpoch)
	if durable, ok := s.store.(edgeLeaseDurableRevocationStore); ok {
		return durable.PersistCageMinEpoch(ctx, cageID, minEpoch)
	}
	return s.store.BumpRevSeq(ctx)
}

// RevokeAPIKey marks an API key revoked in Edge revocation snapshots and bumps rev_seq.
func (s *BerthEdgeLeaseService) RevokeAPIKey(ctx context.Context, apiKeyID int64) (int64, error) {
	if apiKeyID <= 0 {
		return 0, ErrEdgeLeaseInvalid
	}
	s.mu.Lock()
	s.revokedAPIKeys[apiKeyID] = struct{}{}
	s.mu.Unlock()
	if durable, ok := s.store.(edgeLeaseDurableRevocationStore); ok {
		return durable.PersistRevokedAPIKey(ctx, apiKeyID, "revoked")
	}
	return s.store.BumpRevSeq(ctx)
}

// BuildRevocationSnapshot constructs and Ed25519-signs a fresh monotonic RevocationSnapshot.
func (s *BerthEdgeLeaseService) BuildRevocationSnapshot(ctx context.Context, now time.Time) (*edgeproto.RevocationSnapshot, error) {
	if now.IsZero() {
		now = time.Now()
	}
	revSeq, err := s.store.CurrentRevSeq(ctx)
	if err != nil {
		return nil, err
	}
	revokedLeases, err := s.store.ListActiveRevokedLeaseIDs(ctx, now)
	if err != nil {
		return nil, err
	}
	var revokedGrants []int64
	if s.grants != nil {
		revokedGrants, err = s.grants.ListRevokedGrantIDs(ctx)
		if err != nil {
			return nil, err
		}
	}

	revokedKeySet := make(map[int64]struct{})
	cageEpochs := make(map[int64]int64)
	if durable, ok := s.store.(edgeLeaseDurableRevocationStore); ok {
		if dbEpochs, eErr := durable.ListPersistedCageMinEpochs(ctx); eErr == nil {
			for cid, ep := range dbEpochs {
				cageEpochs[cid] = ep
			}
		} else {
			return nil, eErr
		}
		if dbKeys, kErr := durable.ListPersistedRevokedAPIKeys(ctx); kErr == nil {
			for _, kid := range dbKeys {
				revokedKeySet[kid] = struct{}{}
			}
		} else {
			return nil, kErr
		}
	}

	s.mu.RLock()
	for k := range s.revokedAPIKeys {
		revokedKeySet[k] = struct{}{}
	}
	for cid, ep := range s.cageMinEpochs {
		if ep > cageEpochs[cid] {
			cageEpochs[cid] = ep
		}
	}
	s.mu.RUnlock()

	revokedKeys := make([]int64, 0, len(revokedKeySet))
	for k := range revokedKeySet {
		revokedKeys = append(revokedKeys, k)
	}
	sort.Slice(revokedKeys, func(i, j int) bool { return revokedKeys[i] < revokedKeys[j] })

	snap := &edgeproto.RevocationSnapshot{
		Seq:              revSeq,
		IssuedAt:         now.Unix(),
		ValidUntil:       now.Add(s.snapshotTTL).Unix(),
		RevokedLeaseIDs:  revokedLeases,
		RevokedGrantIDs:  revokedGrants,
		RevokedAPIKeyIDs: revokedKeys,
		CageMinEpochs:    cageEpochs,
	}
	if err := edgeproto.SignRevocationSnapshot(s.privKey, s.keyID, snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// CoordinateFailover evaluates failover candidates after an upstream 429/529.
// Strictly matches exact (cohort_timezone, cohort_country_code) per Codex Blocker #7:
//   - If a healthy same-cohort candidate exists -> mints a new same-cohort signed lease.
//   - Otherwise -> NEVER switches across cohorts; returns Action="cage_rebind_required"
//     with recommended target cohort offer (HTTP 409).
func (s *BerthEdgeLeaseService) CoordinateFailover(ctx context.Context, req EdgeFailoverRequest) (*EdgeFailoverResponse, error) {
	cur, err := s.store.GetLease(ctx, req.LeaseID)
	if err != nil {
		return nil, err
	}
	if cur.RevokedAt != nil {
		return nil, ErrEdgeLeaseRevoked
	}
	if !cur.ExpiresAt.IsZero() && !time.Now().Before(cur.ExpiresAt) {
		return nil, ErrEdgeLeaseRevoked
	}
	if req.CallerNodeID > 0 {
		callerAuthorized := cur.IngressNodeID == req.CallerNodeID || cur.LandingNodeID == req.CallerNodeID
		if !callerAuthorized {
			for _, hop := range cur.RouteChain {
				if hop.NodeID == req.CallerNodeID {
					callerAuthorized = true
					break
				}
			}
		}
		if !callerAuthorized {
			return nil, ErrEdgeLeaseForbidden
		}
	}
	failedAccountID := req.FailedAccountID
	if failedAccountID <= 0 {
		failedAccountID = cur.AccountID
	} else if cur.AccountID > 0 && failedAccountID != cur.AccountID {
		return nil, ErrEdgeLeaseForbidden
	}

	platform := strings.TrimSpace(cur.Platform)
	if platform == "" && cur.AccountID > 0 {
		if platResolver, ok := s.store.(edgeLeaseAccountPlatformResolver); ok {
			if p, pErr := platResolver.ResolveAccountPlatform(ctx, cur.AccountID); pErr == nil {
				platform = strings.TrimSpace(p)
			}
		}
	}

	var candidates []FailoverCandidate
	if foResolver, ok := s.store.(edgeLeaseFailoverCandidateResolver); ok {
		if platform == "" {
			return nil, ErrEdgeLeaseInvalid
		}
		resolved, rErr := foResolver.ListAuthorizedFailoverCandidates(
			ctx, cur.UserID, cur.APIKeyID, platform, failedAccountID,
		)
		if rErr != nil {
			return nil, rErr
		}
		candidates = resolved
	} else {
		// In-memory unit tests without SQL candidate store supply candidates explicitly.
		candidates = req.Candidates
	}

	var crossCohortOffer *CageRebindOffer
	for _, cand := range candidates {
		if cand.AccountID <= 0 || cand.AccountID == failedAccountID || cand.LandingNodeID <= 0 {
			continue
		}
		sameCohort := strings.EqualFold(strings.TrimSpace(cand.CohortTimezone), strings.TrimSpace(cur.CohortTimezone)) &&
			strings.EqualFold(strings.TrimSpace(cand.CohortCountryCode), strings.TrimSpace(cur.CohortCountryCode))
		if sameCohort {
			minted, mintErr := s.MintLease(ctx, MintLeaseInput{
				UserID:            cur.UserID,
				APIKeyID:          cur.APIKeyID,
				WorkSessionID:     cur.WorkSessionID,
				Platform:          platform,
				AccountID:         cand.AccountID,
				CageID:            cand.CageID,
				CageEpoch:         cand.CageEpoch,
				GrantID:           cand.GrantID,
				LandingNodeID:     cand.LandingNodeID,
				CohortTimezone:    cand.CohortTimezone,
				CohortCountryCode: cand.CohortCountryCode,
				CohortLocale:      cand.CohortLocale,
			})
			if mintErr == nil {
				return &EdgeFailoverResponse{
					Action: "switched",
					Lease:  minted,
				}, nil
			}
			continue
		}
		if crossCohortOffer == nil {
			crossCohortOffer = &CageRebindOffer{
				AccountID:         cand.AccountID,
				LandingNodeID:     cand.LandingNodeID,
				CohortTimezone:    cand.CohortTimezone,
				CohortCountryCode: cand.CohortCountryCode,
				CohortLocale:      cand.CohortLocale,
			}
		}
	}

	return &EdgeFailoverResponse{
		Action:            "cage_rebind_required",
		Code:              "cage_rebind_required",
		Message:           fmt.Sprintf("No healthy accounts remain in cohort %s/%s; cage rebind required", cur.CohortCountryCode, cur.CohortTimezone),
		RecommendedCohort: crossCohortOffer,
	}, nil
}

type edgeLeaseAccountPlatformResolver interface {
	ResolveAccountPlatform(ctx context.Context, accountID int64) (string, error)
}

// IngestUsageOutbox idempotently commits a batch of Landing usage receipts and returns ACKed receipt IDs.
func (s *BerthEdgeLeaseService) IngestUsageOutbox(ctx context.Context, nodeID int64, receipts []edgeproto.UsageReceipt) ([]string, error) {
	acked := make([]string, 0, len(receipts))
	anyCommitted := false
	for _, r := range receipts {
		if r.ReceiptID == "" {
			continue
		}
		if r.NodeID == 0 {
			r.NodeID = nodeID
		}
		if r.NodeID != nodeID {
			continue
		}
		s.prepareEdgeReceiptTelemetry(ctx, &r)
		if r.GrantID > 0 && s.grants != nil {
			res, err := s.grants.CommitGrantUsageReceipt(ctx, r)
			if err != nil {
				if errors.Is(err, ErrLandingGrantNotFound) {
					// Deleted/orphaned grant is a permanent failure: ACK so the Edge OutboxWAL
					// never head-of-line blocks subsequent valid receipts forever.
					acked = append(acked, r.ReceiptID)
					continue
				}
				return acked, err
			}
			if res != nil && !res.Duplicate {
				anyCommitted = true
			}
		} else {
			anyCommitted = true
		}
		acked = append(acked, r.ReceiptID)
	}
	if anyCommitted || len(acked) > 0 {
		s.notifyUsageIngested()
	}
	return acked, nil
}

const (
	maxPendingOAuthTasksPerNode = 128
	maxClaimOAuthTaskBatch      = 8
	oauthTaskRetentionTTL       = 2 * time.Minute
)

func (s *BerthEdgeLeaseService) reapExpiredOAuthTasksLocked(now time.Time) {
	for id, t := range s.oauthTaskIndex {
		if t == nil {
			delete(s.oauthTaskIndex, id)
			continue
		}
		expired := false
		switch t.Status {
		case "completed", "failed":
			ref := t.CompletedAt
			if ref.IsZero() {
				ref = t.CreatedAt
			}
			expired = now.Sub(ref) > oauthTaskRetentionTTL
		case "claimed":
			ref := t.ClaimedAt
			if ref.IsZero() {
				ref = t.CreatedAt
			}
			expired = now.Sub(ref) > oauthTaskRetentionTTL
		default:
			expired = now.Sub(t.CreatedAt) > oauthTaskRetentionTTL
		}
		if expired {
			t.Headers = nil
			t.BodyBase64 = ""
			t.RespHeaders = nil
			t.RespBody = ""
			t.RespBodyBase64 = ""
			if ch, ok := s.oauthWaiters[id]; ok {
				close(ch)
				delete(s.oauthWaiters, id)
			}
			delete(s.oauthTaskIndex, id)
		}
	}
	for nid, list := range s.oauthTasksByNode {
		kept := list[:0]
		for _, t := range list {
			if t != nil && t.Status == "pending" && s.oauthTaskIndex[t.TaskID] == t {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(s.oauthTasksByNode, nid)
		} else {
			s.oauthTasksByNode[nid] = kept
		}
	}
}

// EnqueueOAuthTask queues an upstream OAuth/refresh/probe task for execution strictly by nodeID.
func (s *BerthEdgeLeaseService) EnqueueOAuthTask(task EdgeOAuthTask) EdgeOAuthTask {
	if task.TaskID == "" {
		task.TaskID = uuid.NewString()
	}
	if task.Status == "" {
		task.Status = "pending"
	}
	now := time.Now()
	if task.CreatedAt.IsZero() {
		task.CreatedAt = now
	}
	cp := task
	s.mu.Lock()
	s.reapExpiredOAuthTasksLocked(now)
	if len(s.oauthTasksByNode[task.NodeID]) >= maxPendingOAuthTasksPerNode {
		cp.Status = "failed"
		cp.Error = "edge landing OAuth task queue full"
		cp.CompletedAt = now
		s.mu.Unlock()
		return cp
	}
	s.oauthTasksByNode[task.NodeID] = append(s.oauthTasksByNode[task.NodeID], &cp)
	s.oauthTaskIndex[task.TaskID] = &cp
	if s.oauthWaiters == nil {
		s.oauthWaiters = make(map[string]chan struct{})
	}
	if _, exists := s.oauthWaiters[task.TaskID]; !exists {
		s.oauthWaiters[task.TaskID] = make(chan struct{})
	}
	ret := cp // Copy before releasing lock so concurrent completion cannot race.
	s.notifyNodeOAuthLocked(task.NodeID)
	s.mu.Unlock()
	return ret
}

// ListPendingOAuthTasks atomically claims up to a bounded batch of pending OAuth/refresh/probe
// tasks assigned to nodeID, removing them from the pending queue so a poller can NEVER execute
// the same single-use OAuth POST twice.
func (s *BerthEdgeLeaseService) ListPendingOAuthTasks(nodeID int64) []EdgeOAuthTask {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.reapExpiredOAuthTasksLocked(now)
	list := s.oauthTasksByNode[nodeID]
	if len(list) == 0 {
		return []EdgeOAuthTask{}
	}
	out := make([]EdgeOAuthTask, 0, min(len(list), maxClaimOAuthTaskBatch))
	remaining := make([]*EdgeOAuthTask, 0, len(list))
	for _, t := range list {
		if t == nil || t.Status != "pending" {
			continue
		}
		if len(out) < maxClaimOAuthTaskBatch {
			t.Status = "claimed"
			t.ClaimID = uuid.NewString()
			t.ClaimedAt = now
			out = append(out, *t)
		} else {
			remaining = append(remaining, t)
		}
	}
	if len(remaining) == 0 {
		delete(s.oauthTasksByNode, nodeID)
	} else {
		s.oauthTasksByNode[nodeID] = remaining
	}
	return out
}

// CompleteOAuthTask records the Landing node's execution result for taskID (backward-compatible wrapper).
func (s *BerthEdgeLeaseService) CompleteOAuthTask(nodeID int64, taskID string, statusCode int, respBody, errMsg string) (*EdgeOAuthTask, error) {
	return s.CompleteOAuthTaskFull(nodeID, taskID, "", statusCode, respBody, "", nil, errMsg)
}

// CompleteOAuthTaskFull records the Landing node's execution result idempotently, binds completion
// to the claim token when present, and purges request secrets immediately.
func (s *BerthEdgeLeaseService) CompleteOAuthTaskFull(
	nodeID int64,
	taskID, claimID string,
	statusCode int,
	respBody, respBodyBase64 string,
	respHeaders map[string][]string,
	errMsg string,
) (*EdgeOAuthTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.oauthTaskIndex[taskID]
	if !ok || t == nil || t.NodeID != nodeID {
		return nil, ErrEdgeLeaseNotFound
	}
	if t.ClaimID != "" && claimID != "" && t.ClaimID != claimID {
		return nil, ErrEdgeLeaseForbidden
	}
	// Terminal completion is strictly idempotent: never overwrite the first terminal result.
	if t.Status == "completed" || t.Status == "failed" {
		cp := *t
		return &cp, nil
	}
	if errMsg != "" {
		t.Status = "failed"
		t.Error = errMsg
	} else {
		t.Status = "completed"
	}
	t.StatusCode = statusCode
	t.RespBody = respBody
	t.RespBodyBase64 = respBodyBase64
	if len(respHeaders) > 0 {
		hdrCopy := make(map[string][]string, len(respHeaders))
		for k, vals := range respHeaders {
			cpVals := make([]string, len(vals))
			copy(cpVals, vals)
			hdrCopy[k] = cpVals
		}
		t.RespHeaders = hdrCopy
	}
	t.CompletedAt = time.Now()
	// Purge request secrets immediately once upstream execution completes.
	t.Headers = nil
	t.BodyBase64 = ""
	if ch, ok := s.oauthWaiters[taskID]; ok {
		close(ch)
		delete(s.oauthWaiters, taskID)
	}
	cp := *t
	return &cp, nil
}

// ConsumeOAuthTask returns the completed task snapshot and immediately purges its payload
// and secrets from Central memory.
func (s *BerthEdgeLeaseService) ConsumeOAuthTask(taskID string) (EdgeOAuthTask, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.oauthTaskIndex[taskID]
	if !ok || t == nil {
		return EdgeOAuthTask{}, false
	}
	snap := *t
	t.Headers = nil
	t.BodyBase64 = ""
	t.RespHeaders = nil
	t.RespBody = ""
	t.RespBodyBase64 = ""
	delete(s.oauthTaskIndex, taskID)
	delete(s.oauthWaiters, taskID)
	return snap, true
}

// CancelOAuthTask marks an expired/cancelled task as failed and purges its secrets from memory.
func (s *BerthEdgeLeaseService) CancelOAuthTask(nodeID int64, taskID, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.oauthTaskIndex[taskID]; ok && t != nil {
		if t.Status == "pending" || t.Status == "claimed" {
			t.Status = "failed"
			t.Error = reason
			t.CompletedAt = time.Now()
		}
		t.Headers = nil
		t.BodyBase64 = ""
		t.RespHeaders = nil
		t.RespBody = ""
		t.RespBodyBase64 = ""
	}
	if ch, ok := s.oauthWaiters[taskID]; ok {
		close(ch)
		delete(s.oauthWaiters, taskID)
	}
	if list := s.oauthTasksByNode[nodeID]; len(list) > 0 {
		kept := list[:0]
		for _, t := range list {
			if t != nil && t.TaskID != taskID && t.Status == "pending" {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(s.oauthTasksByNode, nodeID)
		} else {
			s.oauthTasksByNode[nodeID] = kept
		}
	}
}

// ---------- PostgreSQL BerthEdgeLeaseStore ----------

type sqlEdgeLeaseStore struct {
	db *sql.DB
}

func (s *sqlEdgeLeaseStore) CurrentRevSeq(ctx context.Context) (int64, error) {
	var seq int64
	err := s.db.QueryRowContext(ctx, `SELECT rev_seq FROM berth_edge_revocation_state WHERE id = 1`).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 1, nil
	}
	return seq, err
}

func (s *BerthEdgeLeaseService) RevokeLeasesForUserGroup(ctx context.Context, userID, groupID int64) (int, error) {
	if s == nil || userID <= 0 || groupID <= 0 {
		return 0, nil
	}
	authResolver, ok := s.store.(edgeLeaseAuthorizedAccountResolver)
	if !ok {
		return 0, nil
	}
	count, _, err := authResolver.RevokeUserGroupLeases(ctx, userID, groupID, time.Now())
	return count, err
}

// RevokeActiveEdgeLeasesForUserGroup revokes active Berth Edge leases belonging to
// userID on groupID via the globally registered BerthEdgeLeaseService (e.g. upon
// marketplace rental termination).
func RevokeActiveEdgeLeasesForUserGroup(ctx context.Context, userID, groupID int64) (int, error) {
	svc := getDefaultEdgeLeaseService()
	if svc == nil {
		return 0, nil
	}
	return svc.RevokeLeasesForUserGroup(ctx, userID, groupID)
}

func (s *sqlEdgeLeaseStore) ResolveAuthorizedAccountForLease(ctx context.Context, userID, apiKeyID int64, platform string, preferred []string) (int64, error) {
	var keyGroupID int64
	if apiKeyID > 0 {
		var gid sql.NullInt64
		var keyStatus string
		if err := s.db.QueryRowContext(ctx, `
			SELECT group_id, status FROM api_keys
			WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`, apiKeyID, userID).Scan(&gid, &keyStatus); err != nil {
			return 0, err
		}
		if keyStatus != "active" {
			return 0, sql.ErrNoRows
		}
		if gid.Valid && gid.Int64 > 0 {
			keyGroupID = gid.Int64
		}
	}

	queryBase := `
		SELECT a.id
		FROM accounts a
		JOIN users u ON u.id = $1 AND u.deleted_at IS NULL AND u.status = 'active'
		WHERE a.deleted_at IS NULL AND a.status = 'active' AND a.schedulable = TRUE
		  AND (a.expires_at IS NULL OR a.expires_at > clock_timestamp())
		  AND (
		    $2 = ''
		    OR LOWER(a.platform) = LOWER($2)
		    OR (LOWER($2) IN ('antigravity','gemini') AND LOWER(a.platform) IN ('antigravity','gemini'))
		    OR (LOWER($2) IN ('grok','xai') AND LOWER(a.platform) IN ('grok','xai'))
		  )
		  AND (
		    ($3 > 0 AND EXISTS(
		      SELECT 1 FROM account_groups ag
		      JOIN groups g ON g.id = ag.group_id AND g.deleted_at IS NULL AND g.status = 'active'
		      WHERE ag.account_id = a.id AND ag.group_id = $3
		        AND (
		          u.role = 'admin'
		          OR NOT EXISTS(SELECT 1 FROM berth_account_groups bg WHERE bg.group_id = g.id)
		          OR EXISTS(
		            SELECT 1 FROM berth_account_groups bg
		            JOIN account_stewards st ON st.account_id = bg.account_id AND st.user_id = u.id
		            WHERE bg.group_id = g.id AND bg.owner_user_id = u.id
		          )
		          OR EXISTS(
		            SELECT 1 FROM berth_marketplace_orders o
		            WHERE o.group_id = g.id AND o.resource_type = 'account' AND o.resource_id = a.id
		              AND o.buyer_id = u.id AND o.status = 'active' AND o.terminating_at IS NULL
		              AND o.starts_at <= clock_timestamp()
		              AND (o.expires_at IS NULL OR o.expires_at > clock_timestamp())
		              AND (o.quota_limit_usd IS NULL OR o.quota_used_usd < o.quota_limit_usd)
		          )
		        )
		    ))
		    OR ($3 = 0 AND (
		      u.role = 'admin'
		      OR EXISTS(SELECT 1 FROM account_stewards st WHERE st.account_id = a.id AND st.user_id = u.id)
		      OR EXISTS(
		        SELECT 1 FROM berth_account_groups bg
		        JOIN berth_marketplace_orders o ON o.group_id = bg.group_id
		        WHERE bg.account_id = a.id AND o.resource_type = 'account' AND o.resource_id = a.id
		          AND o.buyer_id = u.id AND o.status = 'active' AND o.terminating_at IS NULL
		          AND o.starts_at <= clock_timestamp()
		          AND (o.expires_at IS NULL OR o.expires_at > clock_timestamp())
		          AND (o.quota_limit_usd IS NULL OR o.quota_used_usd < o.quota_limit_usd)
		      )
		    ))
		  )`

	for _, pref := range preferred {
		pref = strings.TrimSpace(pref)
		if pref == "" {
			continue
		}
		var id int64
		if err := s.db.QueryRowContext(ctx, queryBase+`
			AND (a.id::text = $4 OR LOWER(a.name) = LOWER($4))
			ORDER BY EXISTS(SELECT 1 FROM account_groups ag2 WHERE ag2.account_id = a.id) DESC, a.priority ASC, a.id DESC
			LIMIT 1`, userID, platform, keyGroupID, pref).Scan(&id); err == nil && id > 0 {
			return id, nil
		}
	}

	var id int64
	err := s.db.QueryRowContext(ctx, queryBase+`
		ORDER BY EXISTS(SELECT 1 FROM account_groups ag2 WHERE ag2.account_id = a.id) DESC, a.priority ASC, a.id DESC
		LIMIT 1`, userID, platform, keyGroupID).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *sqlEdgeLeaseStore) VerifyAccountAccessForLease(ctx context.Context, userID, apiKeyID, accountID int64) (bool, error) {
	if userID <= 0 || accountID <= 0 {
		return false, nil
	}
	var keyGroupID int64
	if apiKeyID > 0 {
		var gid sql.NullInt64
		var keyStatus string
		if err := s.db.QueryRowContext(ctx, `
			SELECT group_id, status FROM api_keys
			WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`, apiKeyID, userID).Scan(&gid, &keyStatus); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return false, err
		}
		if keyStatus != "active" {
			return false, nil
		}
		if gid.Valid && gid.Int64 > 0 {
			keyGroupID = gid.Int64
		}
	}
	var allowed bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1
			FROM accounts a
			JOIN users u ON u.id = $1 AND u.deleted_at IS NULL AND u.status = 'active'
			WHERE a.id = $2 AND a.deleted_at IS NULL AND a.status = 'active'
			  AND (a.expires_at IS NULL OR a.expires_at > clock_timestamp())
			  AND (
			    ($3 > 0 AND EXISTS(
			      SELECT 1 FROM account_groups ag
			      JOIN groups g ON g.id = ag.group_id AND g.deleted_at IS NULL AND g.status = 'active'
			      WHERE ag.account_id = a.id AND ag.group_id = $3
			        AND (
			          u.role = 'admin'
			          OR NOT EXISTS(SELECT 1 FROM berth_account_groups bg WHERE bg.group_id = g.id)
			          OR EXISTS(
			            SELECT 1 FROM berth_account_groups bg
			            JOIN account_stewards st ON st.account_id = bg.account_id AND st.user_id = u.id
			            WHERE bg.group_id = g.id AND bg.owner_user_id = u.id
			          )
			          OR EXISTS(
			            SELECT 1 FROM berth_marketplace_orders o
			            WHERE o.group_id = g.id AND o.resource_type = 'account' AND o.resource_id = a.id
			              AND o.buyer_id = u.id AND o.status = 'active' AND o.terminating_at IS NULL
			              AND o.starts_at <= clock_timestamp()
			              AND (o.expires_at IS NULL OR o.expires_at > clock_timestamp())
			              AND (o.quota_limit_usd IS NULL OR o.quota_used_usd < o.quota_limit_usd)
			          )
			        )
			    ))
			    OR ($3 = 0 AND (
			      u.role = 'admin'
			      OR EXISTS(SELECT 1 FROM account_stewards st WHERE st.account_id = a.id AND st.user_id = u.id)
			      OR EXISTS(
			        SELECT 1 FROM berth_account_groups bg
			        JOIN berth_marketplace_orders o ON o.group_id = bg.group_id
			        WHERE bg.account_id = a.id AND o.resource_type = 'account' AND o.resource_id = a.id
			          AND o.buyer_id = u.id AND o.status = 'active' AND o.terminating_at IS NULL
			          AND o.starts_at <= clock_timestamp()
			          AND (o.expires_at IS NULL OR o.expires_at > clock_timestamp())
			          AND (o.quota_limit_usd IS NULL OR o.quota_used_usd < o.quota_limit_usd)
			      )
			    ))
			  )
		)`, userID, accountID, keyGroupID).Scan(&allowed)
	return allowed, err
}

func (s *sqlEdgeLeaseStore) ResolveActiveGrantForProxy(ctx context.Context, proxyID int64) (int64, error) {
	if proxyID <= 0 {
		return 0, sql.ErrNoRows
	}
	var grantID int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id FROM berth_landing_node_grants
		WHERE proxy_id = $1 AND status = 'active'
		  AND (expires_at IS NULL OR expires_at > clock_timestamp())
		  AND (max_bytes <= 0 OR (max_bytes - used_bytes - reserved_bytes) > 0)
		ORDER BY id DESC
		LIMIT 1`, proxyID).Scan(&grantID)
	return grantID, err
}

func (s *sqlEdgeLeaseStore) RevokeUserGroupLeases(ctx context.Context, userID, groupID int64, revokedAt time.Time) (int, int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
		UPDATE berth_work_session_leases
		SET revoked_at = COALESCE(revoked_at, $3)
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $3
		  AND (
		    account_id IN (SELECT account_id FROM account_groups WHERE group_id = $2)
		    OR api_key_id IN (SELECT id FROM api_keys WHERE user_id = $1 AND group_id = $2)
		  )`, userID, groupID, revokedAt)
	if err != nil {
		return 0, 0, err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return 0, 0, nil
	}
	var seq int64
	if err := tx.QueryRowContext(ctx, `
		UPDATE berth_edge_revocation_state
		SET rev_seq = rev_seq + 1, updated_at = NOW()
		WHERE id = 1
		RETURNING rev_seq`).Scan(&seq); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return int(affected), seq, nil
}

func (s *sqlEdgeLeaseStore) ResolveAccountForLease(ctx context.Context, _ int64, platform string, preferred []string) (int64, error) {
	for _, pref := range preferred {
		pref = strings.TrimSpace(pref)
		if pref == "" {
			continue
		}
		var id int64
		if err := s.db.QueryRowContext(ctx, `
			SELECT id FROM accounts
			WHERE deleted_at IS NULL AND status = 'active' AND schedulable = TRUE
			  AND (
			    $1 = ''
			    OR LOWER(platform) = LOWER($1)
			    OR (LOWER($1) IN ('antigravity','gemini') AND LOWER(platform) IN ('antigravity','gemini'))
			    OR (LOWER($1) IN ('grok','xai') AND LOWER(platform) IN ('grok','xai'))
			  )
			  AND (id::text = $2 OR LOWER(name) = LOWER($2))
			ORDER BY priority ASC, id ASC
			LIMIT 1`, platform, pref).Scan(&id); err == nil && id > 0 {
			return id, nil
		}
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id FROM accounts
		WHERE deleted_at IS NULL AND status = 'active' AND schedulable = TRUE
		  AND (
		    $1 = ''
		    OR LOWER(platform) = LOWER($1)
		    OR (LOWER($1) IN ('antigravity','gemini') AND LOWER(platform) IN ('antigravity','gemini'))
		    OR (LOWER($1) IN ('grok','xai') AND LOWER(platform) IN ('grok','xai'))
		  )
		ORDER BY priority ASC, id ASC
		LIMIT 1`, platform).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *sqlEdgeLeaseStore) ResolveAccountProxyBinding(ctx context.Context, accountID int64) (int64, int64, error) {
	var proxyID sql.NullInt64
	var edgeNodeID sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT a.proxy_id, p.edge_node_id
		FROM accounts a
		LEFT JOIN proxies p ON p.id = a.proxy_id AND p.deleted_at IS NULL
		WHERE a.id = $1 AND a.deleted_at IS NULL`, accountID).Scan(&proxyID, &edgeNodeID)
	if err != nil {
		return 0, 0, err
	}
	var pid, eid int64
	if proxyID.Valid {
		pid = proxyID.Int64
	}
	if edgeNodeID.Valid {
		eid = edgeNodeID.Int64
	}
	return pid, eid, nil
}

func (s *sqlEdgeLeaseStore) ListAuthorizedFailoverCandidates(ctx context.Context, userID, apiKeyID int64, platform string, excludeAccountID int64) ([]FailoverCandidate, error) {
	if userID <= 0 {
		return nil, nil
	}
	var keyGroupID int64
	if apiKeyID > 0 {
		var gid sql.NullInt64
		var keyStatus string
		if err := s.db.QueryRowContext(ctx, `
			SELECT group_id, status FROM api_keys
			WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`, apiKeyID, userID).Scan(&gid, &keyStatus); err != nil {
			return nil, err
		}
		if keyStatus != "active" {
			return nil, nil
		}
		if gid.Valid && gid.Int64 > 0 {
			keyGroupID = gid.Int64
		}
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id,
		       COALESCE(c.id, a.id),
		       COALESCE(c.gate_epoch, 1),
		       COALESCE((
		         SELECT g2.id FROM berth_landing_node_grants g2
		         WHERE g2.status = 'active'
		           AND (g2.expires_at IS NULL OR g2.expires_at > clock_timestamp())
		           AND (g2.max_bytes <= 0 OR (g2.max_bytes - g2.used_bytes - g2.reserved_bytes) > 0)
		           AND (g2.proxy_id = p.id OR (g2.node_id = n.id AND g2.grantee_user_id = $1))
		         ORDER BY (g2.proxy_id = p.id) DESC, g2.id DESC
		         LIMIT 1
		       ), 0),
		       n.id,
		       COALESCE(NULLIF(n.exit_timezone, ''), NULLIF(p.exit_timezone, ''), NULLIF(c.timezone, ''), 'UTC'),
		       COALESCE(NULLIF(n.exit_country_code, ''), NULLIF(p.exit_country_code, ''), 'US'),
		       COALESCE(NULLIF(n.exit_locale, ''), NULLIF(c.locale, ''), '')
		FROM accounts a
		JOIN users u ON u.id = $1 AND u.deleted_at IS NULL AND u.status = 'active'
		JOIN proxies p ON p.id = a.proxy_id AND p.deleted_at IS NULL AND p.status = 'active'
		JOIN berth_edge_nodes n ON n.id = p.edge_node_id AND n.status = 'active'
		LEFT JOIN account_cages c ON c.account_id = a.id AND c.deleted_at IS NULL
		WHERE a.deleted_at IS NULL AND a.status = 'active' AND a.schedulable = TRUE
		  AND (c.id IS NULL OR c.gate_state = 'open')
		  AND (
		    COALESCE(p.source_type, '') <> 'edge_landing_grant'
		    OR EXISTS(
		      SELECT 1 FROM berth_landing_node_grants g3
		      WHERE g3.status = 'active'
		        AND (g3.expires_at IS NULL OR g3.expires_at > clock_timestamp())
		        AND (g3.max_bytes <= 0 OR (g3.max_bytes - g3.used_bytes - g3.reserved_bytes) > 0)
		        AND (g3.proxy_id = p.id OR (g3.node_id = n.id AND g3.grantee_user_id = $1))
		    )
		  )
		  AND a.id <> $4
		  AND (a.expires_at IS NULL OR a.expires_at > clock_timestamp())
		  AND (
		    $2 = ''
		    OR LOWER(a.platform) = LOWER($2)
		    OR (LOWER($2) IN ('antigravity','gemini') AND LOWER(a.platform) IN ('antigravity','gemini'))
		    OR (LOWER($2) IN ('grok','xai') AND LOWER(a.platform) IN ('grok','xai'))
		  )
		  AND (
		    ($3 > 0 AND EXISTS(
		      SELECT 1 FROM account_groups ag
		      JOIN groups g ON g.id = ag.group_id AND g.deleted_at IS NULL AND g.status = 'active'
		      WHERE ag.account_id = a.id AND ag.group_id = $3
		        AND (
		          u.role = 'admin'
		          OR NOT EXISTS(SELECT 1 FROM berth_account_groups bg WHERE bg.group_id = g.id)
		          OR EXISTS(
		            SELECT 1 FROM berth_account_groups bg
		            JOIN account_stewards st ON st.account_id = bg.account_id AND st.user_id = u.id
		            WHERE bg.group_id = g.id AND bg.owner_user_id = u.id
		          )
		          OR EXISTS(
		            SELECT 1 FROM berth_marketplace_orders o
		            WHERE o.group_id = g.id AND o.resource_type = 'account' AND o.resource_id = a.id
		              AND o.buyer_id = u.id AND o.status = 'active' AND o.terminating_at IS NULL
		              AND o.starts_at <= clock_timestamp()
		              AND (o.expires_at IS NULL OR o.expires_at > clock_timestamp())
		              AND (o.quota_limit_usd IS NULL OR o.quota_used_usd < o.quota_limit_usd)
		          )
		        )
		    ))
		    OR ($3 = 0 AND (
		      u.role = 'admin'
		      OR EXISTS(SELECT 1 FROM account_stewards st WHERE st.account_id = a.id AND st.user_id = u.id)
		      OR EXISTS(
		        SELECT 1 FROM berth_account_groups bg
		        JOIN berth_marketplace_orders o ON o.group_id = bg.group_id
		        WHERE bg.account_id = a.id AND o.resource_type = 'account' AND o.resource_id = a.id
		          AND o.buyer_id = u.id AND o.status = 'active' AND o.terminating_at IS NULL
		          AND o.starts_at <= clock_timestamp()
		          AND (o.expires_at IS NULL OR o.expires_at > clock_timestamp())
		          AND (o.quota_limit_usd IS NULL OR o.quota_used_usd < o.quota_limit_usd)
		      )
		    ))
		  )
		ORDER BY a.priority ASC, a.id ASC`, userID, platform, keyGroupID, excludeAccountID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []FailoverCandidate
	for rows.Next() {
		var c FailoverCandidate
		if err := rows.Scan(
			&c.AccountID, &c.CageID, &c.CageEpoch, &c.GrantID,
			&c.LandingNodeID, &c.CohortTimezone, &c.CohortCountryCode, &c.CohortLocale,
		); err != nil {
			return nil, err
		}
		if strings.TrimSpace(c.CohortLocale) == "" {
			c.CohortLocale = DeriveGeoIdentity(c.CohortCountryCode, c.CohortTimezone).Locale
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *sqlEdgeLeaseStore) BumpRevSeq(ctx context.Context) (int64, error) {
	var seq int64
	err := s.db.QueryRowContext(ctx, `
		UPDATE berth_edge_revocation_state
		SET rev_seq = rev_seq + 1, updated_at = NOW()
		WHERE id = 1
		RETURNING rev_seq`).Scan(&seq)
	return seq, err
}

func (s *sqlEdgeLeaseStore) ResolveAccountCageState(ctx context.Context, accountID int64) (int64, int64, string, string, string, string, bool, error) {
	var cageID, gateEpoch int64
	var gateState, tz, cc, locale string
	err := s.db.QueryRowContext(ctx, `
		SELECT c.id,
		       c.gate_epoch,
		       COALESCE(c.gate_state, 'closed'),
		       COALESCE(NULLIF(c.timezone, ''), NULLIF(p.exit_timezone, ''), ''),
		       COALESCE(NULLIF(p.exit_country_code, ''), ''),
		       COALESCE(NULLIF(c.locale, ''), '')
		FROM account_cages c
		LEFT JOIN proxies p ON p.id = c.proxy_id AND p.deleted_at IS NULL
		WHERE c.account_id = $1 AND c.deleted_at IS NULL`, accountID).Scan(
		&cageID, &gateEpoch, &gateState, &tz, &cc, &locale,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, "", "", "", "", false, nil
	}
	if err != nil {
		return 0, 0, "", "", "", "", false, err
	}
	return cageID, gateEpoch, gateState, tz, cc, locale, true, nil
}

func (s *sqlEdgeLeaseStore) PersistCageMinEpoch(ctx context.Context, cageID, minEpoch int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO berth_edge_cage_min_epochs (cage_id, min_epoch, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (cage_id) DO UPDATE
		SET min_epoch = GREATEST(berth_edge_cage_min_epochs.min_epoch, EXCLUDED.min_epoch),
		    updated_at = NOW()`, cageID, minEpoch); err != nil {
		return 0, err
	}
	var seq int64
	if err := tx.QueryRowContext(ctx, `
		UPDATE berth_edge_revocation_state
		SET rev_seq = rev_seq + 1, updated_at = NOW()
		WHERE id = 1
		RETURNING rev_seq`).Scan(&seq); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return seq, nil
}

func (s *sqlEdgeLeaseStore) PersistRevokedAPIKey(ctx context.Context, apiKeyID int64, reason string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO berth_edge_revoked_api_keys (api_key_id, reason, revoked_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (api_key_id) DO NOTHING`, apiKeyID, reason); err != nil {
		return 0, err
	}
	var seq int64
	if err := tx.QueryRowContext(ctx, `
		UPDATE berth_edge_revocation_state
		SET rev_seq = rev_seq + 1, updated_at = NOW()
		WHERE id = 1
		RETURNING rev_seq`).Scan(&seq); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return seq, nil
}

func (s *sqlEdgeLeaseStore) ListPersistedCageMinEpochs(ctx context.Context) (map[int64]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cage_id, min_epoch FROM berth_edge_cage_min_epochs`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make(map[int64]int64)
	for rows.Next() {
		var cid, ep int64
		if err := rows.Scan(&cid, &ep); err != nil {
			return nil, err
		}
		out[cid] = ep
	}
	return out, rows.Err()
}

func (s *sqlEdgeLeaseStore) ListPersistedRevokedAPIKeys(ctx context.Context) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT api_key_id FROM berth_edge_revoked_api_keys ORDER BY api_key_id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]int64, 0, 16)
	for rows.Next() {
		var kid int64
		if err := rows.Scan(&kid); err != nil {
			return nil, err
		}
		out = append(out, kid)
	}
	return out, rows.Err()
}

func (s *sqlEdgeLeaseStore) ResolveAccountPlatform(ctx context.Context, accountID int64) (string, error) {
	var platform string
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(platform, '')
		FROM accounts
		WHERE id = $1 AND deleted_at IS NULL`, accountID).Scan(&platform)
	return platform, err
}

func (s *sqlEdgeLeaseStore) ResolveActiveMarketplaceOrderForLease(
	ctx context.Context,
	userID, apiKeyID, accountID int64,
) (int64, *time.Time, *time.Time, error) {
	var acctExp sql.NullTime
	if err := s.db.QueryRowContext(ctx, `
		SELECT expires_at FROM accounts WHERE id = $1 AND deleted_at IS NULL`, accountID).Scan(&acctExp); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, nil, nil, err
		}
	}
	var accountExpiresAt *time.Time
	if acctExp.Valid {
		t := acctExp.Time
		accountExpiresAt = &t
	}

	// Owner self-use is never attributed to a buyer rental order.
	var isOwner bool
	_ = s.db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM account_stewards WHERE account_id = $1 AND user_id = $2)`,
		accountID, userID).Scan(&isOwner)
	if isOwner {
		return 0, nil, accountExpiresAt, nil
	}

	var keyGroupID int64
	if apiKeyID > 0 {
		var gid sql.NullInt64
		if err := s.db.QueryRowContext(ctx, `SELECT group_id FROM api_keys WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`, apiKeyID, userID).Scan(&gid); err == nil && gid.Valid {
			keyGroupID = gid.Int64
		}
	}

	var orderID int64
	var orderExp sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT o.id, o.expires_at
		FROM berth_marketplace_orders o
		WHERE o.resource_type = 'account'
		  AND o.resource_id = $1
		  AND o.buyer_id = $2
		  AND o.seller_id <> $2
		  AND ($3 = 0 OR o.group_id = $3)
		  AND o.status = 'active'
		  AND o.terminating_at IS NULL
		  AND o.starts_at <= clock_timestamp()
		  AND (o.expires_at IS NULL OR o.expires_at > clock_timestamp())
		  AND (o.quota_limit_usd IS NULL OR o.quota_used_usd < o.quota_limit_usd)
		ORDER BY CASE WHEN o.rental_mode IN ('quota','hybrid') THEN 0 ELSE 1 END,
		         o.expires_at ASC NULLS LAST,
		         o.id ASC
		LIMIT 1`, accountID, userID, keyGroupID).Scan(&orderID, &orderExp)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, accountExpiresAt, nil
	}
	if err != nil {
		return 0, nil, accountExpiresAt, err
	}
	var orderExpiresAt *time.Time
	if orderExp.Valid {
		t := orderExp.Time
		orderExpiresAt = &t
	}
	return orderID, orderExpiresAt, accountExpiresAt, nil
}

func (s *sqlEdgeLeaseStore) VerifyAccountEdgeLandingAuthorization(ctx context.Context, accountID, targetNodeID int64) error {
	if accountID <= 0 || targetNodeID <= 0 {
		return ErrLandingGrantForbidden
	}
	var edgeNodeID sql.NullInt64
	var proxyID sql.NullInt64
	var proxyStatus sql.NullString
	var sourceType sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT p.id, p.edge_node_id, p.status, COALESCE(p.source_type, '')
		FROM accounts a
		LEFT JOIN proxies p ON p.id = a.proxy_id AND p.deleted_at IS NULL
		WHERE a.id = $1 AND a.deleted_at IS NULL`, accountID).Scan(&proxyID, &edgeNodeID, &proxyStatus, &sourceType)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEdgeLeaseNotFound
		}
		return err
	}
	if !proxyID.Valid || proxyID.Int64 <= 0 || !edgeNodeID.Valid || edgeNodeID.Int64 != targetNodeID {
		return ErrLandingGrantForbidden
	}
	if !proxyStatus.Valid || proxyStatus.String != StatusActive {
		return ErrLandingGrantInactive
	}
	if sourceType.String == ProxySourceTypeEdgeLandingGrant {
		var grantID int64
		err = s.db.QueryRowContext(ctx, `
			SELECT id FROM berth_landing_node_grants
			WHERE proxy_id = $1 AND node_id = $2 AND status = 'active'
			  AND (expires_at IS NULL OR expires_at > clock_timestamp())
			  AND (max_bytes <= 0 OR (max_bytes - used_bytes - reserved_bytes) > 0)
			LIMIT 1`, proxyID.Int64, targetNodeID).Scan(&grantID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrLandingGrantInactive
			}
			return err
		}
	}
	return nil
}

func (s *sqlEdgeLeaseStore) InsertLease(ctx context.Context, rec WorkSessionLeaseRecord) error {
	routeJSON, err := json.Marshal(rec.RouteChain)
	if err != nil {
		return err
	}
	nullID := func(v int64) sql.NullInt64 {
		if v <= 0 {
			return sql.NullInt64{}
		}
		return sql.NullInt64{Int64: v, Valid: true}
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO berth_work_session_leases (
			lease_id, work_session_id, user_id, api_key_id, platform, account_id,
			marketplace_order_id, cage_id, cage_epoch, grant_id, landing_node_id, ingress_node_id,
			route_chain, cohort_timezone, cohort_country_code, cohort_locale,
			lease_epoch, rev_seq, expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		rec.LeaseID, nullID(rec.WorkSessionID), rec.UserID, nullID(rec.APIKeyID), strings.TrimSpace(rec.Platform), nullID(rec.AccountID),
		nullID(rec.MarketplaceOrderID), rec.CageID, rec.CageEpoch, nullID(rec.GrantID), nullID(rec.LandingNodeID), nullID(rec.IngressNodeID),
		string(routeJSON), rec.CohortTimezone, rec.CohortCountryCode, rec.CohortLocale,
		rec.LeaseEpoch, rec.RevSeq, rec.ExpiresAt,
	)
	return err
}

func scanLeaseRecord(sc interface{ Scan(...any) error }) (*WorkSessionLeaseRecord, error) {
	var rec WorkSessionLeaseRecord
	var wsID, keyID, acctID, orderID, grantID, landID, ingID sql.NullInt64
	var routeJSON []byte
	var revAt sql.NullTime
	err := sc.Scan(
		&rec.LeaseID, &wsID, &rec.UserID, &keyID, &rec.Platform, &acctID, &orderID,
		&rec.CageID, &rec.CageEpoch, &grantID, &landID, &ingID,
		&routeJSON, &rec.CohortTimezone, &rec.CohortCountryCode, &rec.CohortLocale,
		&rec.LeaseEpoch, &rec.RevSeq, &rec.ExpiresAt, &revAt, &rec.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEdgeLeaseNotFound
		}
		return nil, err
	}
	if wsID.Valid {
		rec.WorkSessionID = wsID.Int64
	}
	if keyID.Valid {
		rec.APIKeyID = keyID.Int64
	}
	if acctID.Valid {
		rec.AccountID = acctID.Int64
	}
	if orderID.Valid {
		rec.MarketplaceOrderID = orderID.Int64
	}
	if grantID.Valid {
		rec.GrantID = grantID.Int64
	}
	if landID.Valid {
		rec.LandingNodeID = landID.Int64
	}
	if ingID.Valid {
		rec.IngressNodeID = ingID.Int64
	}
	if revAt.Valid {
		t := revAt.Time
		rec.RevokedAt = &t
	}
	if len(routeJSON) > 0 {
		_ = json.Unmarshal(routeJSON, &rec.RouteChain)
	}
	return &rec, nil
}

const leaseSelectCols = `
	lease_id::text, work_session_id, user_id, api_key_id, COALESCE(platform, ''), account_id,
	marketplace_order_id, cage_id, cage_epoch, grant_id, landing_node_id, ingress_node_id,
	route_chain, cohort_timezone, cohort_country_code, cohort_locale,
	lease_epoch, rev_seq, expires_at, revoked_at, created_at`

func (s *sqlEdgeLeaseStore) GetLease(ctx context.Context, leaseID string) (*WorkSessionLeaseRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+leaseSelectCols+` FROM berth_work_session_leases WHERE lease_id = $1`, leaseID)
	return scanLeaseRecord(row)
}

func (s *sqlEdgeLeaseStore) RenewLeaseRecord(ctx context.Context, leaseID string, newExpiresAt time.Time, revSeq int64) (*WorkSessionLeaseRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		UPDATE berth_work_session_leases
		SET lease_epoch = lease_epoch + 1,
		    rev_seq = $2,
		    expires_at = $3
		WHERE lease_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		RETURNING `+leaseSelectCols, leaseID, revSeq, newExpiresAt)
	return scanLeaseRecord(row)
}

func (s *sqlEdgeLeaseStore) RevokeLeaseRecord(ctx context.Context, leaseID string, revokedAt time.Time) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
		UPDATE berth_work_session_leases
		SET revoked_at = COALESCE(revoked_at, $2)
		WHERE lease_id = $1`, leaseID, revokedAt)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrEdgeLeaseNotFound
	}
	var seq int64
	if err := tx.QueryRowContext(ctx, `
		UPDATE berth_edge_revocation_state
		SET rev_seq = rev_seq + 1, updated_at = NOW()
		WHERE id = 1
		RETURNING rev_seq`).Scan(&seq); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return seq, nil
}

func (s *sqlEdgeLeaseStore) ListActiveRevokedLeaseIDs(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT lease_id::text
		FROM berth_work_session_leases
		WHERE revoked_at IS NOT NULL AND expires_at > $1
		ORDER BY lease_id ASC`, now)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]string, 0, 16)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ---------- In-Memory BerthEdgeLeaseStore (for unit/E2E tests) ----------

type MemoryEdgeLeaseStore struct {
	mu        sync.Mutex
	revSeqPtr *int64
	leases    map[string]*WorkSessionLeaseRecord
}

func NewMemoryEdgeLeaseStore(revSeqPtr *int64) *MemoryEdgeLeaseStore {
	if revSeqPtr == nil {
		v := int64(1)
		revSeqPtr = &v
	}
	return &MemoryEdgeLeaseStore{
		revSeqPtr: revSeqPtr,
		leases:    make(map[string]*WorkSessionLeaseRecord),
	}
}

func (m *MemoryEdgeLeaseStore) CurrentRevSeq(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return *m.revSeqPtr, nil
}

func (m *MemoryEdgeLeaseStore) BumpRevSeq(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	*m.revSeqPtr++
	return *m.revSeqPtr, nil
}

func (m *MemoryEdgeLeaseStore) InsertLease(_ context.Context, rec WorkSessionLeaseRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := rec
	m.leases[rec.LeaseID] = &cp
	return nil
}

func (m *MemoryEdgeLeaseStore) GetLease(_ context.Context, leaseID string) (*WorkSessionLeaseRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.leases[leaseID]
	if !ok {
		return nil, ErrEdgeLeaseNotFound
	}
	cp := *rec
	return &cp, nil
}

func (m *MemoryEdgeLeaseStore) RenewLeaseRecord(_ context.Context, leaseID string, newExpiresAt time.Time, revSeq int64) (*WorkSessionLeaseRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.leases[leaseID]
	if !ok {
		return nil, ErrEdgeLeaseNotFound
	}
	if rec.RevokedAt != nil || (!rec.ExpiresAt.IsZero() && !time.Now().Before(rec.ExpiresAt)) {
		return nil, ErrEdgeLeaseRevoked
	}
	rec.LeaseEpoch++
	rec.RevSeq = revSeq
	rec.ExpiresAt = newExpiresAt
	cp := *rec
	return &cp, nil
}

func (m *MemoryEdgeLeaseStore) RevokeLeaseRecord(_ context.Context, leaseID string, revokedAt time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.leases[leaseID]
	if !ok {
		return 0, ErrEdgeLeaseNotFound
	}
	if rec.RevokedAt == nil {
		t := revokedAt
		rec.RevokedAt = &t
	}
	*m.revSeqPtr++
	return *m.revSeqPtr, nil
}

func (m *MemoryEdgeLeaseStore) ListActiveRevokedLeaseIDs(_ context.Context, now time.Time) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0)
	for _, rec := range m.leases {
		if rec.RevokedAt != nil && rec.ExpiresAt.After(now) {
			out = append(out, rec.LeaseID)
		}
	}
	sort.Strings(out)
	return out, nil
}
