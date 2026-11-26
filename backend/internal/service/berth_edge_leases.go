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
	LeaseID           string               `json:"lease_id"`
	WorkSessionID     int64                `json:"work_session_id"`
	UserID            int64                `json:"user_id"`
	APIKeyID          int64                `json:"api_key_id"`
	Platform          string               `json:"platform"`
	AccountID         int64                `json:"account_id"`
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
	TaskID     string            `json:"task_id"`
	NodeID     int64             `json:"node_id"`
	AccountID  int64             `json:"account_id"`
	Kind       string            `json:"kind"` // oauth_exchange | token_refresh | health_probe
	TargetURL  string            `json:"target_url"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers,omitempty"`
	BodyBase64 string            `json:"body_base64,omitempty"`
	Status     string            `json:"status"` // pending | completed | failed
	StatusCode int               `json:"status_code,omitempty"`
	RespBody   string            `json:"resp_body,omitempty"`
	Error      string            `json:"error,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
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

	mu               sync.RWMutex
	revokedAPIKeys   map[int64]struct{}
	cageMinEpochs    map[int64]int64
	liveRevTunnels   map[int64]bool
	oauthTasksByNode map[int64][]*EdgeOAuthTask
	oauthTaskIndex   map[string]*EdgeOAuthTask
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.liveRevTunnels) == 0 {
		return nil
	}
	cp := make(map[int64]bool, len(s.liveRevTunnels))
	for k, v := range s.liveRevTunnels {
		cp[k] = v
	}
	return cp
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
		return "xai"
	default:
		return strings.ToLower(strings.TrimSpace(agent))
	}
}

type edgeLeaseAccountResolver interface {
	ResolveAccountForLease(ctx context.Context, userID int64, platform string, preferred []string) (int64, error)
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

	// Auto-resolve an eligible active Admin Landing Grant & active Landing node when
	// AGS v2 omits explicit landing_node_id/grant_id.
	if in.UserID > 0 && s.grants != nil {
		if in.LandingNodeID <= 0 && in.GrantID > 0 {
			if g, gErr := s.grants.GetGrant(ctx, in.GrantID); gErr == nil && g != nil {
				in.LandingNodeID = g.NodeID
			}
		}
		if in.LandingNodeID <= 0 {
			userGrants, gErr := s.grants.ListUserGrants(ctx, in.UserID)
			if gErr == nil {
				hint := strings.ToLower(strings.TrimSpace(in.CohortHint))
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
					if fallbackGrant == nil {
						fallbackGrant = g
					}
					if hint != "" && (strings.Contains(strings.ToLower(node.Name), hint) ||
						strings.Contains(strings.ToLower(node.ExitTimezone), hint) ||
						strings.EqualFold(node.ExitCountryCode, hint)) {
						fallbackGrant = g
						break
					}
				}
				if fallbackGrant != nil {
					in.GrantID = fallbackGrant.ID
					in.LandingNodeID = fallbackGrant.NodeID
				}
			}
		}
	}

	// Auto-resolve an active schedulable account for the requested platform when AGS v2 omits account_id.
	if in.UserID > 0 && in.AccountID <= 0 {
		if resolver, ok := s.store.(edgeLeaseAccountResolver); ok {
			if resolvedID, rErr := resolver.ResolveAccountForLease(ctx, in.UserID, in.Platform, in.AccountPreference); rErr == nil && resolvedID > 0 {
				in.AccountID = resolvedID
			}
		}
	}

	if in.UserID <= 0 || in.AccountID <= 0 || in.LandingNodeID <= 0 {
		return nil, fmt.Errorf("%w: user_id, account_id, and landing_node_id are required", ErrEdgeLeaseInvalid)
	}

	// Validate landing node.
	landingNode, err := s.zones.GetNode(ctx, in.LandingNodeID)
	if err != nil {
		return nil, err
	}
	if landingNode.Status != EdgeNodeStatusActive {
		return nil, fmt.Errorf("%w: landing node %s is not active", ErrNoRouteAvailable, landingNode.Name)
	}

	// Validate landing grant if specified.
	if in.GrantID > 0 && s.grants != nil {
		grant, err := s.grants.GetGrant(ctx, in.GrantID)
		if err != nil {
			return nil, err
		}
		if grant.GranteeUserID != in.UserID {
			return nil, ErrLandingGrantForbidden
		}
		if grant.NodeID != in.LandingNodeID {
			return nil, ErrLandingGrantForbidden
		}
		if grant.Status != GrantStatusActive {
			return nil, ErrLandingGrantInactive
		}
		if grant.ExpiresAt != nil && !now.Before(*grant.ExpiresAt) {
			return nil, ErrLandingGrantExpired
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

	// Select best ingress relay in resolved zone and compute Dijkstra route_chain.
	liveTunnels := s.liveTunnelsSnapshot(in.LiveReverseTunnels)
	ingressNode, routeChain, _, err := s.zones.SelectBestIngressAndRoute(ctx, clientZoneID, landingNode.ID, liveTunnels)
	if err != nil && clientZoneID > 0 {
		// Fall back to any non-centre ingress if resolved zone has no dedicated relay configured.
		ingressNode, routeChain, _, err = s.zones.SelectBestIngressAndRoute(ctx, 0, landingNode.ID, liveTunnels)
	}
	if err != nil {
		return nil, err
	}

	cohortTZ := strings.TrimSpace(in.CohortTimezone)
	if cohortTZ == "" {
		cohortTZ = landingNode.ExitTimezone
	}
	cohortCC := strings.TrimSpace(in.CohortCountryCode)
	if cohortCC == "" {
		cohortCC = landingNode.ExitCountryCode
	}
	cohortLocale := strings.TrimSpace(in.CohortLocale)
	if cohortLocale == "" {
		cohortLocale = landingNode.ExitLocale
	}
	cageEpoch := in.CageEpoch
	if cageEpoch <= 0 {
		cageEpoch = 1
	}

	revSeq, err := s.store.CurrentRevSeq(ctx)
	if err != nil {
		return nil, err
	}

	leaseID := uuid.NewString()
	exp := now.Add(s.leaseTTL)
	rec := WorkSessionLeaseRecord{
		LeaseID:           leaseID,
		WorkSessionID:     in.WorkSessionID,
		UserID:            in.UserID,
		APIKeyID:          in.APIKeyID,
		Platform:          in.Platform,
		AccountID:         in.AccountID,
		CageID:            in.CageID,
		CageEpoch:         cageEpoch,
		GrantID:           in.GrantID,
		LandingNodeID:     landingNode.ID,
		IngressNodeID:     ingressNode.ID,
		RouteChain:        routeChain,
		CohortTimezone:    cohortTZ,
		CohortCountryCode: cohortCC,
		CohortLocale:      cohortLocale,
		LeaseEpoch:        1,
		RevSeq:            revSeq,
		ExpiresAt:         exp,
		CreatedAt:         now,
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
	acceptLang := "en-US,en;q=0.9"
	if strings.HasPrefix(strings.ToLower(rec.CohortLocale), "ja") {
		acceptLang = "ja-JP,ja;q=0.9,en;q=0.8"
	} else if strings.HasPrefix(strings.ToLower(rec.CohortLocale), "de") {
		acceptLang = "de-DE,de;q=0.9,en;q=0.8"
	} else if strings.HasPrefix(strings.ToLower(rec.CohortLocale), "en_gb") {
		acceptLang = "en-GB,en;q=0.9"
	}
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
		IngressNode:   ingressNode,
		LandingNode:   landingNode,
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
	rec, err := s.store.GetLease(ctx, leaseID)
	if err != nil {
		return nil, err
	}
	if userID > 0 && rec.UserID != userID {
		return nil, ErrEdgeLeaseForbidden
	}
	if rec.RevokedAt != nil {
		return nil, ErrEdgeLeaseRevoked
	}

	now := time.Now()
	if rec.GrantID > 0 && s.grants != nil {
		grant, err := s.grants.GetGrant(ctx, rec.GrantID)
		if err != nil {
			return nil, err
		}
		if grant.Status != GrantStatusActive {
			return nil, ErrLandingGrantInactive
		}
		if grant.ExpiresAt != nil && !now.Before(*grant.ExpiresAt) {
			return nil, ErrLandingGrantExpired
		}
	}

	revSeq, err := s.store.CurrentRevSeq(ctx)
	if err != nil {
		return nil, err
	}
	updated, err := s.store.RenewLeaseRecord(ctx, leaseID, now.Add(s.leaseTTL), revSeq)
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

// RevokeLease revokes leaseID and immediately bumps monotonic rev_seq.
func (s *BerthEdgeLeaseService) RevokeLease(ctx context.Context, userID int64, isAdmin bool, leaseID string) (int64, error) {
	rec, err := s.store.GetLease(ctx, leaseID)
	if err != nil {
		return 0, err
	}
	if !isAdmin && rec.UserID != userID {
		return 0, ErrEdgeLeaseForbidden
	}
	return s.store.RevokeLeaseRecord(ctx, leaseID, time.Now())
}

// BumpCageMinEpoch raises the minimum authorized cage epoch for cageID and bumps rev_seq.
func (s *BerthEdgeLeaseService) BumpCageMinEpoch(ctx context.Context, cageID, minEpoch int64) (int64, error) {
	if cageID <= 0 || minEpoch <= 0 {
		return 0, ErrEdgeLeaseInvalid
	}
	s.mu.Lock()
	if cur := s.cageMinEpochs[cageID]; minEpoch > cur {
		s.cageMinEpochs[cageID] = minEpoch
	}
	s.mu.Unlock()
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

	s.mu.RLock()
	revokedKeys := make([]int64, 0, len(s.revokedAPIKeys))
	for k := range s.revokedAPIKeys {
		revokedKeys = append(revokedKeys, k)
	}
	sort.Slice(revokedKeys, func(i, j int) bool { return revokedKeys[i] < revokedKeys[j] })

	cageEpochs := make(map[int64]int64, len(s.cageMinEpochs))
	for cid, ep := range s.cageMinEpochs {
		cageEpochs[cid] = ep
	}
	s.mu.RUnlock()

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

	var crossCohortOffer *CageRebindOffer
	for _, cand := range req.Candidates {
		if cand.AccountID <= 0 || cand.AccountID == req.FailedAccountID || cand.LandingNodeID <= 0 {
			continue
		}
		sameCohort := strings.EqualFold(strings.TrimSpace(cand.CohortTimezone), strings.TrimSpace(cur.CohortTimezone)) &&
			strings.EqualFold(strings.TrimSpace(cand.CohortCountryCode), strings.TrimSpace(cur.CohortCountryCode))
		if sameCohort {
			minted, mintErr := s.MintLease(ctx, MintLeaseInput{
				UserID:            cur.UserID,
				APIKeyID:          cur.APIKeyID,
				WorkSessionID:     cur.WorkSessionID,
				Platform:          cur.Platform,
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

// IngestUsageOutbox idempotently commits a batch of Landing usage receipts and returns ACKed receipt IDs.
func (s *BerthEdgeLeaseService) IngestUsageOutbox(ctx context.Context, nodeID int64, receipts []edgeproto.UsageReceipt) ([]string, error) {
	acked := make([]string, 0, len(receipts))
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
		if r.GrantID > 0 && s.grants != nil {
			if _, err := s.grants.CommitGrantUsageReceipt(ctx, r); err != nil {
				return acked, err
			}
		}
		acked = append(acked, r.ReceiptID)
	}
	return acked, nil
}

// EnqueueOAuthTask queues an upstream OAuth/refresh/probe task for execution strictly by nodeID.
func (s *BerthEdgeLeaseService) EnqueueOAuthTask(task EdgeOAuthTask) EdgeOAuthTask {
	if task.TaskID == "" {
		task.TaskID = uuid.NewString()
	}
	if task.Status == "" {
		task.Status = "pending"
	}
	if task.CreatedAt.IsZero() {
		task.CreatedAt = time.Now()
	}
	cp := task
	s.mu.Lock()
	s.oauthTasksByNode[task.NodeID] = append(s.oauthTasksByNode[task.NodeID], &cp)
	s.oauthTaskIndex[task.TaskID] = &cp
	s.mu.Unlock()
	return cp
}

// ListPendingOAuthTasks returns pending OAuth/refresh/probe tasks assigned to nodeID.
func (s *BerthEdgeLeaseService) ListPendingOAuthTasks(nodeID int64) []EdgeOAuthTask {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := s.oauthTasksByNode[nodeID]
	out := make([]EdgeOAuthTask, 0, len(list))
	for _, t := range list {
		if t.Status == "pending" {
			out = append(out, *t)
		}
	}
	return out
}

// CompleteOAuthTask records the Landing node's execution result for taskID.
func (s *BerthEdgeLeaseService) CompleteOAuthTask(nodeID int64, taskID string, statusCode int, respBody, errMsg string) (*EdgeOAuthTask, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.oauthTaskIndex[taskID]
	if !ok || t.NodeID != nodeID {
		return nil, ErrEdgeLeaseNotFound
	}
	if errMsg != "" {
		t.Status = "failed"
		t.Error = errMsg
	} else {
		t.Status = "completed"
	}
	t.StatusCode = statusCode
	t.RespBody = respBody
	cp := *t
	return &cp, nil
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
			  AND ($1 = '' OR LOWER(platform) = LOWER($1))
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
		  AND ($1 = '' OR LOWER(platform) = LOWER($1))
		ORDER BY priority ASC, id ASC
		LIMIT 1`, platform).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
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
			lease_id, work_session_id, user_id, api_key_id, account_id,
			cage_id, cage_epoch, grant_id, landing_node_id, ingress_node_id,
			route_chain, cohort_timezone, cohort_country_code, cohort_locale,
			lease_epoch, rev_seq, expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		rec.LeaseID, nullID(rec.WorkSessionID), rec.UserID, nullID(rec.APIKeyID), nullID(rec.AccountID),
		rec.CageID, rec.CageEpoch, nullID(rec.GrantID), nullID(rec.LandingNodeID), nullID(rec.IngressNodeID),
		string(routeJSON), rec.CohortTimezone, rec.CohortCountryCode, rec.CohortLocale,
		rec.LeaseEpoch, rec.RevSeq, rec.ExpiresAt,
	)
	return err
}

func scanLeaseRecord(sc interface{ Scan(...any) error }) (*WorkSessionLeaseRecord, error) {
	var rec WorkSessionLeaseRecord
	var wsID, keyID, acctID, grantID, landID, ingID sql.NullInt64
	var routeJSON []byte
	var revAt sql.NullTime
	err := sc.Scan(
		&rec.LeaseID, &wsID, &rec.UserID, &keyID, &acctID,
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
	lease_id::text, work_session_id, user_id, api_key_id, account_id,
	cage_id, cage_epoch, grant_id, landing_node_id, ingress_node_id,
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
		WHERE lease_id = $1 AND revoked_at IS NULL
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
	if rec.RevokedAt != nil {
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
