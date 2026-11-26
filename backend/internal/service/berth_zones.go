package service

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	infraerrors "github.com/jk-zhang-meta/berth/internal/pkg/errors"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/lib/pq"
)

var (
	ErrEdgeZoneInvalid      = infraerrors.New(http.StatusBadRequest, "EDGE_ZONE_INVALID", "Invalid network zone or topology request")
	ErrEdgeZoneNotFound     = infraerrors.New(http.StatusNotFound, "EDGE_ZONE_NOT_FOUND", "Network zone, node, or link not found")
	ErrEdgeZoneConflict     = infraerrors.New(http.StatusConflict, "EDGE_ZONE_CONFLICT", "Network zone or link conflicts with existing state")
	ErrEdgeZoneUnresolved   = infraerrors.New(http.StatusForbidden, "EDGE_ZONE_UNRESOLVED", "Client network zone could not be resolved under strict policy")
	ErrNoRouteAvailable     = infraerrors.New(http.StatusServiceUnavailable, "EDGE_NO_ROUTE", "No healthy route available to target landing node")
	ErrEdgeNodeUnauthorized = infraerrors.New(http.StatusUnauthorized, "EDGE_NODE_UNAUTHORIZED", "Edge node authentication failed")
)

const (
	ZoneResolutionUnconfigured     = "unconfigured"
	ZoneResolutionResolved         = "resolved"
	ZoneResolutionUnresolvedStrict = "unresolved_strict"

	EdgeRoleIngressRelay = "ingress_relay"
	EdgeRoleTransit      = "transit"
	EdgeRoleLanding      = "landing"
	EdgeRoleCompat       = "compat"
	EdgeRoleMgmtEntry    = "mgmt_entry"

	ConnectModeDirect        = "direct"
	ConnectModeReverseTunnel = "reverse_tunnel"

	LinkDirectionBidirectional = "bidirectional"
	LinkDirectionOneWay        = "one_way"

	LinkClassDirect        = "direct"
	LinkClassIPLC          = "iplc"
	LinkClassReverseTunnel = "reverse_tunnel"

	EdgeNodeStatusActive    = "active"
	EdgeNodeStatusDraining  = "draining"
	EdgeNodeStatusOffline   = "offline"
	EdgeNodeStatusSuspended = "suspended"
)

// NetworkZone maps to berth_network_zones.
type NetworkZone struct {
	ID                int64     `json:"id"`
	Slug              string    `json:"slug"`
	DisplayName       string    `json:"display_name"`
	IsCentre          bool      `json:"is_centre"`
	DefaultMgmtPolicy string    `json:"default_mgmt_policy"`
	DNSHintDomains    []string  `json:"dns_hint_domains"`
	GeoCountryCodes   []string  `json:"geo_country_codes"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// EdgeNode maps to berth_edge_nodes.
type EdgeNode struct {
	ID                   int64           `json:"id"`
	Name                 string          `json:"name"`
	ZoneID               int64           `json:"zone_id"`
	Roles                []string        `json:"roles"`
	PublicAddr           string          `json:"public_addr"`
	TunnelAddr           string          `json:"tunnel_addr"`
	MgmtEntryAddr        string          `json:"mgmt_entry_addr"`
	ConnectMode          string          `json:"connect_mode"`
	ProviderRegion       string          `json:"provider_region"`
	ExitIP               string          `json:"exit_ip"`
	ExitCountryCode      string          `json:"exit_country_code"`
	ExitTimezone         string          `json:"exit_timezone"`
	ExitLocale           string          `json:"exit_locale"`
	ExitASNClass         string          `json:"exit_asn_class"`
	PubkeyEd25519        string          `json:"pubkey_ed25519"`
	AgentCertFingerprint string          `json:"agent_cert_fingerprint"`
	Status               string          `json:"status"`
	MaxBytesMonth        int64           `json:"max_bytes_month"`
	UsedBytesMonth       int64           `json:"used_bytes_month"`
	ReservedBytesMonth   int64           `json:"reserved_bytes_month"`
	LastHeartbeatAt      *time.Time      `json:"last_heartbeat_at,omitempty"`
	Meta                 json.RawMessage `json:"meta,omitempty"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

// HasRole reports whether the edge node advertises the given role.
func (n *EdgeNode) HasRole(role string) bool {
	if n == nil {
		return false
	}
	return slices.Contains(n.Roles, role)
}

// ServerLink maps to berth_server_links.
type ServerLink struct {
	ID        int64     `json:"id"`
	SrcNodeID int64     `json:"src_node_id"`
	DstNodeID int64     `json:"dst_node_id"`
	Direction string    `json:"direction"`  // bidirectional | one_way
	LinkClass string    `json:"link_class"` // direct | iplc | reverse_tunnel
	Weight    int       `json:"weight"`
	RTTMs     int       `json:"rtt_ms"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ZoneResolutionInput provides FR-138 client zone resolution inputs.
type ZoneResolutionInput struct {
	PinnedZoneSlug      string
	PreferredZoneSlug   string
	PhysicalCountryCode string
	PhysicalObservedAt  *time.Time
	PeerCountryCode     string
	DNSHintDomain       string
	DefaultRouteVPN     bool
	LastCleanZoneSlug   string
	Now                 time.Time
}

// ZoneResolutionResult describes the 3-state MeshHarbor zone resolution outcome.
type ZoneResolutionResult struct {
	Status string       `json:"status"` // resolved | unresolved_strict | unconfigured
	Zone   *NetworkZone `json:"zone,omitempty"`
	Source string       `json:"source"`
}

// EdgeHeartbeatUpdate captures node telemetry reported on heartbeat.
// EdgeProbeTarget describes an active peer node advertised to berth-edge for FR-125 auto-probing.
type EdgeProbeTarget struct {
	NodeID   int64  `json:"node_id"`
	NodeName string `json:"node_name"`
	Addr     string `json:"addr"`
}

// MeasuredPeerLink mirrors berth-edge's directional peer probe report.
type MeasuredPeerLink struct {
	TargetNodeID   int64  `json:"target_node_id"`
	TargetName     string `json:"target_name,omitempty"`
	Reachable      bool   `json:"reachable"`
	RTTMs          int    `json:"rtt_ms"`
	LinkClass      string `json:"link_class"`
	MeasuredAtUnix int64  `json:"measured_at_unix"`
}

// LiveTopologyEdge is a directional auto-discovered edge in Central's live FR-125 mesh graph.
type LiveTopologyEdge struct {
	SrcNodeID      int64  `json:"src_node_id"`
	SrcNodeName    string `json:"src_node_name"`
	DstNodeID      int64  `json:"dst_node_id"`
	DstNodeName    string `json:"dst_node_name"`
	LinkClass      string `json:"link_class"`
	RTTMs          int    `json:"rtt_ms"`
	WeightBias     int    `json:"weight_bias"`
	EffectiveCost  int    `json:"effective_cost"`
	MeasuredAtUnix int64  `json:"measured_at_unix"`
	Source         string `json:"source"` // measured | reverse_tunnel
}

const measuredTopologyFreshTTL = 90 * time.Second

type EdgeHeartbeatUpdate struct {
	Status             string             `json:"status"`
	ExitIP             string             `json:"exit_ip,omitempty"`
	ExitCountryCode    string             `json:"exit_country_code,omitempty"`
	ExitTimezone       string             `json:"exit_timezone,omitempty"`
	ExitLocale         string             `json:"exit_locale,omitempty"`
	ExitASNClass       string             `json:"exit_asn_class,omitempty"`
	AgentVersion       string             `json:"agent_version,omitempty"`
	AgentArch          string             `json:"agent_arch,omitempty"`
	AgentSHA256        string             `json:"agent_sha256,omitempty"`
	MeasuredLinks      []MeasuredPeerLink `json:"measured_links,omitempty"`
	LiveReverseTunnels []int64            `json:"live_reverse_tunnels,omitempty"`
	Meta               json.RawMessage    `json:"meta,omitempty"`
}

// BerthZoneStore abstracts persistence for zones, edge nodes, and server links.
type BerthZoneStore interface {
	ListZones(ctx context.Context) ([]NetworkZone, error)
	CreateZone(ctx context.Context, z NetworkZone) (*NetworkZone, error)
	ListNodes(ctx context.Context) ([]EdgeNode, error)
	GetNode(ctx context.Context, id int64) (*EdgeNode, error)
	CreateNode(ctx context.Context, n EdgeNode) (*EdgeNode, error)
	UpdateNode(ctx context.Context, n EdgeNode) (*EdgeNode, error)
	RecordHeartbeat(ctx context.Context, nodeID int64, upd EdgeHeartbeatUpdate, at time.Time) (*EdgeNode, error)
	ListLinks(ctx context.Context) ([]ServerLink, error)
	CreateLink(ctx context.Context, l ServerLink) (*ServerLink, error)
	DeleteLink(ctx context.Context, id int64) error
}

type nodeMeasuredReport struct {
	reportedAt         time.Time
	links              []MeasuredPeerLink
	liveReverseTunnels []int64
}

// BerthZoneService manages logical zones, edge nodes, FR-125 auto-probed mesh topology,
// FR-138 zone resolution, and Dijkstra shortest-path routing across direct, IPLC, and reverse tunnels.
type BerthZoneService struct {
	store BerthZoneStore

	measuredMu     sync.RWMutex
	measuredByNode map[int64]nodeMeasuredReport
}

// NewBerthZoneService creates a PostgreSQL-backed BerthZoneService.
func NewBerthZoneService(db *sql.DB) *BerthZoneService {
	return &BerthZoneService{
		store:          &sqlZoneStore{db: db},
		measuredByNode: make(map[int64]nodeMeasuredReport),
	}
}

// NewBerthZoneServiceWithStore creates a BerthZoneService backed by a custom store.
func NewBerthZoneServiceWithStore(store BerthZoneStore) *BerthZoneService {
	return &BerthZoneService{
		store:          store,
		measuredByNode: make(map[int64]nodeMeasuredReport),
	}
}

func normalizeCountryCode(cc string) string {
	return strings.ToUpper(strings.TrimSpace(cc))
}

func validateZone(z *NetworkZone) error {
	z.Slug = strings.ToLower(strings.TrimSpace(z.Slug))
	z.DisplayName = strings.TrimSpace(z.DisplayName)
	if z.Slug == "" || z.DisplayName == "" {
		return fmt.Errorf("%w: slug and display_name are required", ErrEdgeZoneInvalid)
	}
	if z.DefaultMgmtPolicy == "" {
		z.DefaultMgmtPolicy = "entry_required"
	}
	switch z.DefaultMgmtPolicy {
	case "direct_allowed", "entry_required", "direct_preferred":
	default:
		return fmt.Errorf("%w: invalid default_mgmt_policy %q", ErrEdgeZoneInvalid, z.DefaultMgmtPolicy)
	}
	if z.IsCentre && len(z.GeoCountryCodes) > 0 {
		return fmt.Errorf("%w: centre zone cannot claim geo_country_codes", ErrEdgeZoneInvalid)
	}
	for i, cc := range z.GeoCountryCodes {
		c := normalizeCountryCode(cc)
		if len(c) != 2 || c == "XX" || c == "ZZ" {
			return fmt.Errorf("%w: invalid country code %q", ErrEdgeZoneInvalid, cc)
		}
		z.GeoCountryCodes[i] = c
	}
	for i, dom := range z.DNSHintDomains {
		z.DNSHintDomains[i] = strings.ToLower(strings.TrimSpace(dom))
	}
	if z.DNSHintDomains == nil {
		z.DNSHintDomains = []string{}
	}
	if z.GeoCountryCodes == nil {
		z.GeoCountryCodes = []string{}
	}
	return nil
}

func validateEdgeNode(n *EdgeNode) error {
	n.Name = strings.TrimSpace(n.Name)
	if n.Name == "" || n.ZoneID <= 0 {
		return fmt.Errorf("%w: name and zone_id are required", ErrEdgeZoneInvalid)
	}
	if n.ConnectMode == "" {
		n.ConnectMode = ConnectModeDirect
	}
	if n.ConnectMode != ConnectModeDirect && n.ConnectMode != ConnectModeReverseTunnel {
		return fmt.Errorf("%w: invalid connect_mode %q", ErrEdgeZoneInvalid, n.ConnectMode)
	}
	if n.Status == "" {
		n.Status = EdgeNodeStatusOffline
	}
	switch n.Status {
	case EdgeNodeStatusActive, EdgeNodeStatusDraining, EdgeNodeStatusOffline, EdgeNodeStatusSuspended:
	default:
		return fmt.Errorf("%w: invalid status %q", ErrEdgeZoneInvalid, n.Status)
	}
	if n.MaxBytesMonth < 0 {
		return fmt.Errorf("%w: max_bytes_month must be >= 0", ErrEdgeZoneInvalid)
	}
	for _, r := range n.Roles {
		switch r {
		case EdgeRoleIngressRelay, EdgeRoleTransit, EdgeRoleLanding, EdgeRoleCompat, EdgeRoleMgmtEntry:
		default:
			return fmt.Errorf("%w: invalid role %q", ErrEdgeZoneInvalid, r)
		}
	}
	if n.Roles == nil {
		n.Roles = []string{}
	}
	if len(n.Meta) == 0 {
		n.Meta = json.RawMessage(`{}`)
	}
	return nil
}

func validateServerLink(l *ServerLink) error {
	if l.SrcNodeID <= 0 || l.DstNodeID <= 0 || l.SrcNodeID == l.DstNodeID {
		return fmt.Errorf("%w: src_node_id and dst_node_id must be distinct positive IDs", ErrEdgeZoneInvalid)
	}
	if l.Direction == "" {
		l.Direction = LinkDirectionOneWay
	}
	if l.Direction != LinkDirectionBidirectional && l.Direction != LinkDirectionOneWay {
		return fmt.Errorf("%w: invalid direction %q", ErrEdgeZoneInvalid, l.Direction)
	}
	if l.LinkClass == "" {
		l.LinkClass = LinkClassDirect
	}
	switch l.LinkClass {
	case LinkClassDirect, LinkClassIPLC, LinkClassReverseTunnel:
	default:
		return fmt.Errorf("%w: invalid link_class %q", ErrEdgeZoneInvalid, l.LinkClass)
	}
	if l.Weight < 0 || l.RTTMs < 0 {
		return fmt.Errorf("%w: weight and rtt_ms must be >= 0", ErrEdgeZoneInvalid)
	}
	return nil
}

func (s *BerthZoneService) ListZones(ctx context.Context) ([]NetworkZone, error) {
	return s.store.ListZones(ctx)
}

func (s *BerthZoneService) CreateZone(ctx context.Context, z NetworkZone) (*NetworkZone, error) {
	if err := validateZone(&z); err != nil {
		return nil, err
	}
	return s.store.CreateZone(ctx, z)
}

func (s *BerthZoneService) ListNodes(ctx context.Context) ([]EdgeNode, error) {
	return s.store.ListNodes(ctx)
}

func (s *BerthZoneService) GetNode(ctx context.Context, id int64) (*EdgeNode, error) {
	if id <= 0 {
		return nil, ErrEdgeZoneInvalid
	}
	return s.store.GetNode(ctx, id)
}

func (s *BerthZoneService) CreateNode(ctx context.Context, n EdgeNode) (*EdgeNode, error) {
	if err := validateEdgeNode(&n); err != nil {
		return nil, err
	}
	return s.store.CreateNode(ctx, n)
}

func (s *BerthZoneService) UpdateNode(ctx context.Context, n EdgeNode) (*EdgeNode, error) {
	if n.ID <= 0 {
		return nil, ErrEdgeZoneInvalid
	}
	if err := validateEdgeNode(&n); err != nil {
		return nil, err
	}
	return s.store.UpdateNode(ctx, n)
}

func (s *BerthZoneService) RecordHeartbeat(ctx context.Context, nodeID int64, upd EdgeHeartbeatUpdate, at time.Time) (*EdgeNode, error) {
	if nodeID <= 0 {
		return nil, ErrEdgeZoneInvalid
	}
	if upd.Status == "" {
		upd.Status = EdgeNodeStatusActive
	}
	switch upd.Status {
	case EdgeNodeStatusActive, EdgeNodeStatusDraining, EdgeNodeStatusOffline, EdgeNodeStatusSuspended:
	default:
		return nil, fmt.Errorf("%w: invalid heartbeat status %q", ErrEdgeZoneInvalid, upd.Status)
	}
	if at.IsZero() {
		at = time.Now()
	}
	if upd.Status == EdgeNodeStatusOffline || upd.Status == EdgeNodeStatusSuspended {
		s.measuredMu.Lock()
		delete(s.measuredByNode, nodeID)
		s.measuredMu.Unlock()
	} else if upd.MeasuredLinks != nil || upd.LiveReverseTunnels != nil {
		s.measuredMu.Lock()
		if s.measuredByNode == nil {
			s.measuredByNode = make(map[int64]nodeMeasuredReport)
		}
		s.measuredByNode[nodeID] = nodeMeasuredReport{
			reportedAt:         at,
			links:              append([]MeasuredPeerLink(nil), upd.MeasuredLinks...),
			liveReverseTunnels: append([]int64(nil), upd.LiveReverseTunnels...),
		}
		s.measuredMu.Unlock()
	}
	if upd.AgentVersion != "" || upd.AgentArch != "" || upd.AgentSHA256 != "" {
		metaMap := map[string]any{}
		if trimmed := strings.TrimSpace(string(upd.Meta)); trimmed != "" {
			_ = json.Unmarshal([]byte(trimmed), &metaMap)
		}
		if upd.AgentVersion != "" {
			metaMap["agent_version"] = strings.TrimSpace(upd.AgentVersion)
		}
		if upd.AgentArch != "" {
			metaMap["agent_arch"] = strings.TrimSpace(upd.AgentArch)
		}
		if upd.AgentSHA256 != "" {
			metaMap["agent_sha256"] = strings.ToLower(strings.TrimSpace(upd.AgentSHA256))
		}
		if b, mErr := json.Marshal(metaMap); mErr == nil {
			upd.Meta = b
		}
	}
	return s.store.RecordHeartbeat(ctx, nodeID, upd, at)
}

// ProbeTargetsForNode returns all active direct peer nodes that nodeID should probe under FR-125.
func (s *BerthZoneService) ProbeTargetsForNode(ctx context.Context, nodeID int64) ([]EdgeProbeTarget, error) {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]EdgeProbeTarget, 0, len(nodes))
	for _, n := range nodes {
		if n.ID == nodeID || n.Status != EdgeNodeStatusActive || n.ConnectMode == ConnectModeReverseTunnel {
			continue
		}
		addr := cleanDialAddr(nodeDialAddr(&n))
		if addr == "" {
			continue
		}
		out = append(out, EdgeProbeTarget{
			NodeID:   n.ID,
			NodeName: n.Name,
			Addr:     addr,
		})
	}
	return out, nil
}

// LiveReverseTunnelsSnapshot returns the set of landing node IDs currently connected
// to any active reverse-tunnel hub (based on fresh heartbeats within measuredTopologyFreshTTL).
func (s *BerthZoneService) LiveReverseTunnelsSnapshot(now time.Time) map[int64]bool {
	if s == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.measuredMu.RLock()
	defer s.measuredMu.RUnlock()
	if len(s.measuredByNode) == 0 {
		return nil
	}
	out := make(map[int64]bool)
	for _, rep := range s.measuredByNode {
		if now.Sub(rep.reportedAt) > measuredTopologyFreshTTL {
			continue
		}
		for _, id := range rep.liveReverseTunnels {
			if id > 0 {
				out[id] = true
			}
		}
		for _, m := range rep.links {
			if m.Reachable && m.LinkClass == LinkClassReverseTunnel && m.TargetNodeID > 0 {
				out[m.TargetNodeID] = true
			}
		}
	}
	return out
}

func (s *BerthZoneService) snapshotFreshMeasured(now time.Time) map[int64]nodeMeasuredReport {
	if s == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.measuredMu.RLock()
	defer s.measuredMu.RUnlock()
	if len(s.measuredByNode) == 0 {
		return nil
	}
	cp := make(map[int64]nodeMeasuredReport, len(s.measuredByNode))
	for nodeID, rep := range s.measuredByNode {
		if now.Sub(rep.reportedAt) <= measuredTopologyFreshTTL {
			cp[nodeID] = nodeMeasuredReport{
				reportedAt:         rep.reportedAt,
				links:              append([]MeasuredPeerLink(nil), rep.links...),
				liveReverseTunnels: append([]int64(nil), rep.liveReverseTunnels...),
			}
		}
	}
	return cp
}

// ListMeasuredTopology returns all fresh auto-discovered reachable directional edges for UI inspection.
func (s *BerthZoneService) ListMeasuredTopology(ctx context.Context) ([]LiveTopologyEdge, error) {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	staticLinks, err := s.store.ListLinks(ctx)
	if err != nil {
		return nil, err
	}
	nodeMap := make(map[int64]*EdgeNode, len(nodes))
	for i := range nodes {
		nodeMap[nodes[i].ID] = &nodes[i]
	}
	disabledPairs, weightBias := indexStaticOverrides(staticLinks)
	fresh := s.snapshotFreshMeasured(time.Now())

	out := make([]LiveTopologyEdge, 0, 32)
	seen := make(map[[2]int64]struct{})
	for srcID, rep := range fresh {
		srcNode := nodeMap[srcID]
		if srcNode == nil || srcNode.Status != EdgeNodeStatusActive {
			continue
		}
		for _, m := range rep.links {
			if !m.Reachable || m.TargetNodeID <= 0 {
				continue
			}
			dstNode := nodeMap[m.TargetNodeID]
			if dstNode == nil || dstNode.Status != EdgeNodeStatusActive {
				continue
			}
			pair := [2]int64{srcID, m.TargetNodeID}
			if disabledPairs[pair] {
				continue
			}
			rtt := m.RTTMs
			if rtt < 1 {
				rtt = 1
			}
			bias := weightBias[pair]
			lc := m.LinkClass
			if lc == "" {
				lc = LinkClassDirect
			}
			srcTag := "measured"
			if lc == LinkClassReverseTunnel {
				srcTag = "reverse_tunnel"
			}
			seen[pair] = struct{}{}
			out = append(out, LiveTopologyEdge{
				SrcNodeID:      srcID,
				SrcNodeName:    srcNode.Name,
				DstNodeID:      dstNode.ID,
				DstNodeName:    dstNode.Name,
				LinkClass:      lc,
				RTTMs:          rtt,
				WeightBias:     bias,
				EffectiveCost:  rtt + bias,
				MeasuredAtUnix: m.MeasuredAtUnix,
				Source:         srcTag,
			})
		}
		for _, dstID := range rep.liveReverseTunnels {
			pair := [2]int64{srcID, dstID}
			if _, ok := seen[pair]; ok || disabledPairs[pair] {
				continue
			}
			dstNode := nodeMap[dstID]
			if dstNode == nil || dstNode.Status != EdgeNodeStatusActive {
				continue
			}
			bias := weightBias[pair]
			out = append(out, LiveTopologyEdge{
				SrcNodeID:      srcID,
				SrcNodeName:    srcNode.Name,
				DstNodeID:      dstNode.ID,
				DstNodeName:    dstNode.Name,
				LinkClass:      LinkClassReverseTunnel,
				RTTMs:          25,
				WeightBias:     bias,
				EffectiveCost:  25 + bias,
				MeasuredAtUnix: rep.reportedAt.Unix(),
				Source:         "reverse_tunnel",
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SrcNodeID != out[j].SrcNodeID {
			return out[i].SrcNodeID < out[j].SrcNodeID
		}
		return out[i].EffectiveCost < out[j].EffectiveCost
	})
	return out, nil
}

func (s *BerthZoneService) ListLinks(ctx context.Context) ([]ServerLink, error) {
	return s.store.ListLinks(ctx)
}

func (s *BerthZoneService) CreateLink(ctx context.Context, l ServerLink) (*ServerLink, error) {
	if err := validateServerLink(&l); err != nil {
		return nil, err
	}
	return s.store.CreateLink(ctx, l)
}

func (s *BerthZoneService) DeleteLink(ctx context.Context, id int64) error {
	if id <= 0 {
		return ErrEdgeZoneInvalid
	}
	return s.store.DeleteLink(ctx, id)
}

// ParseEd25519PublicKey parses base64url, standard base64, or hex encoded 32-byte Ed25519 keys.
func ParseEd25519PublicKey(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrEdgeNodeUnauthorized
	}
	for _, dec := range []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(raw); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, ErrEdgeNodeUnauthorized
}

// LookupNodePubKey resolves and parses the registered Ed25519 public key for an active/non-suspended node.
func (s *BerthZoneService) LookupNodePubKey(ctx context.Context, nodeID int64) (ed25519.PublicKey, error) {
	node, err := s.store.GetNode(ctx, nodeID)
	if err != nil {
		return nil, ErrEdgeNodeUnauthorized
	}
	if node.Status == EdgeNodeStatusSuspended {
		return nil, ErrEdgeNodeUnauthorized
	}
	return ParseEd25519PublicKey(node.PubkeyEd25519)
}

// ResolveClientZone implements FR-138 client zone resolution:
//  1. Admin pin (cannot be escaped)
//  2. Explicit client preference (non-centre only)
//  3. Fresh physical probe country (<= 24h)
//  4. BHE1 / peer GeoIP country hint or DNS hint domain (when not behind VPN default route)
//  5. Held last_clean_zone_slug when default route is VPN
//  6. Fallback non-centre zone ('overseas', or first non-centre without country restrictions)
//
// Fails closed with ZoneResolutionUnresolvedStrict on read error or stale pin.
func (s *BerthZoneService) ResolveClientZone(ctx context.Context, in ZoneResolutionInput) (*ZoneResolutionResult, error) {
	zones, err := s.store.ListZones(ctx)
	if err != nil {
		return &ZoneResolutionResult{Status: ZoneResolutionUnresolvedStrict, Source: "store_error"}, ErrEdgeZoneUnresolved
	}
	if len(zones) == 0 {
		return &ZoneResolutionResult{Status: ZoneResolutionUnconfigured, Source: "unconfigured"}, nil
	}

	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	bySlug := make(map[string]*NetworkZone, len(zones))
	byCountry := make(map[string]*NetworkZone)
	var fallback *NetworkZone
	for i := range zones {
		z := &zones[i]
		bySlug[z.Slug] = z
		for _, cc := range z.GeoCountryCodes {
			byCountry[normalizeCountryCode(cc)] = z
		}
		if !z.IsCentre && z.Slug == "overseas" {
			fallback = z
		}
	}
	if fallback == nil {
		for i := range zones {
			z := &zones[i]
			if !z.IsCentre && len(z.GeoCountryCodes) == 0 {
				fallback = z
				break
			}
		}
	}

	// 1. Admin pinned zone takes strict precedence; stale pin fails closed!
	if slug := strings.ToLower(strings.TrimSpace(in.PinnedZoneSlug)); slug != "" {
		z, ok := bySlug[slug]
		if !ok {
			return &ZoneResolutionResult{Status: ZoneResolutionUnresolvedStrict, Source: "stale_pin"}, ErrEdgeZoneUnresolved
		}
		return &ZoneResolutionResult{Status: ZoneResolutionResolved, Zone: z, Source: "pinned"}, nil
	}

	// 2. Explicit client preference (never allowed to target centre zone).
	if slug := strings.ToLower(strings.TrimSpace(in.PreferredZoneSlug)); slug != "" {
		if z, ok := bySlug[slug]; ok && !z.IsCentre {
			return &ZoneResolutionResult{Status: ZoneResolutionResolved, Zone: z, Source: "explicit_preference"}, nil
		}
	}

	// 3. Fresh physical-interface GeoIP probe (<= 24h) beats VPN-masked egress IP.
	if cc := normalizeCountryCode(in.PhysicalCountryCode); cc != "" {
		fresh := in.PhysicalObservedAt == nil || now.Sub(*in.PhysicalObservedAt) <= 24*time.Hour
		if fresh {
			if z, ok := byCountry[cc]; ok {
				return &ZoneResolutionResult{Status: ZoneResolutionResolved, Zone: z, Source: "auto_physical"}, nil
			}
		}
	}

	// 4a. BHE1 / socket peer GeoIP country hint (unless default route is a VPN).
	if !in.DefaultRouteVPN {
		if cc := normalizeCountryCode(in.PeerCountryCode); cc != "" {
			if z, ok := byCountry[cc]; ok {
				return &ZoneResolutionResult{Status: ZoneResolutionResolved, Zone: z, Source: "bhe1_geoip"}, nil
			}
		}
		if dom := strings.ToLower(strings.TrimSpace(in.DNSHintDomain)); dom != "" {
			for i := range zones {
				z := &zones[i]
				if z.IsCentre {
					continue
				}
				for _, hint := range z.DNSHintDomains {
					if hint != "" && (dom == hint || strings.HasSuffix(dom, "."+hint)) {
						return &ZoneResolutionResult{Status: ZoneResolutionResolved, Zone: z, Source: "dns_hint"}, nil
					}
				}
			}
		}
	}

	// 5. Hold last clean zone while VPN is active (FR-138 anti-flapping).
	if in.DefaultRouteVPN {
		if slug := strings.ToLower(strings.TrimSpace(in.LastCleanZoneSlug)); slug != "" {
			if z, ok := bySlug[slug]; ok && !z.IsCentre {
				return &ZoneResolutionResult{Status: ZoneResolutionResolved, Zone: z, Source: "auto_vpn_held"}, nil
			}
		}
	}

	// 6. Fallback non-centre zone (e.g. overseas), else fail closed.
	if fallback != nil {
		return &ZoneResolutionResult{Status: ZoneResolutionResolved, Zone: fallback, Source: "fallback"}, nil
	}
	return &ZoneResolutionResult{Status: ZoneResolutionUnresolvedStrict, Source: "no_fallback"}, ErrEdgeZoneUnresolved
}

// FindShortestPath computes the minimum-cost healthy directed path from srcNodeID
// to dstNodeID via Dijkstra over berth_server_links:
//   - Respects one_way vs bidirectional links (e.g. asymmetric 1-way IPLC).
//   - Requires all nodes along the path to have status == 'active'.
//   - When liveReverseTunnels != nil, excludes reverse_tunnel links/nodes whose
//     live reverse tunnel is currently absent (Codex Blocker #1.4).
func (s *BerthZoneService) FindShortestPath(
	ctx context.Context,
	srcNodeID, dstNodeID int64,
	liveReverseTunnels map[int64]bool,
) ([]edgeproto.RouteHop, int, error) {
	if srcNodeID <= 0 || dstNodeID <= 0 {
		return nil, 0, ErrEdgeZoneInvalid
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, 0, err
	}
	links, err := s.store.ListLinks(ctx)
	if err != nil {
		return nil, 0, err
	}
	return solveDijkstraPathWithMeasured(nodes, links, s.snapshotFreshMeasured(time.Now()), srcNodeID, dstNodeID, liveReverseTunnels)
}

type graphEdge struct {
	to        int64
	cost      int
	linkClass string
}

func nodePrimaryRole(n *EdgeNode) string {
	for _, preferred := range []string{EdgeRoleLanding, EdgeRoleCompat, EdgeRoleTransit, EdgeRoleIngressRelay, EdgeRoleMgmtEntry} {
		if n.HasRole(preferred) {
			return preferred
		}
	}
	if len(n.Roles) > 0 {
		return n.Roles[0]
	}
	return ""
}

func cleanDialAddr(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	return strings.TrimRight(s, "/")
}

func nodeDialAddr(n *EdgeNode) string {
	if n.TunnelAddr != "" {
		return cleanDialAddr(n.TunnelAddr)
	}
	return cleanDialAddr(n.PublicAddr)
}

func indexStaticOverrides(links []ServerLink) (disabled map[[2]int64]bool, weightBias map[[2]int64]int) {
	disabled = make(map[[2]int64]bool)
	weightBias = make(map[[2]int64]int)
	for _, l := range links {
		p := [2]int64{l.SrcNodeID, l.DstNodeID}
		if !l.Enabled {
			disabled[p] = true
			if l.Direction == LinkDirectionBidirectional {
				disabled[[2]int64{l.DstNodeID, l.SrcNodeID}] = true
			}
			continue
		}
		if l.Weight > 0 {
			weightBias[p] = l.Weight
			if l.Direction == LinkDirectionBidirectional {
				weightBias[[2]int64{l.DstNodeID, l.SrcNodeID}] = l.Weight
			}
		}
	}
	return disabled, weightBias
}

func solveDijkstraPath(
	nodes []EdgeNode,
	links []ServerLink,
	srcNodeID, dstNodeID int64,
	liveReverseTunnels map[int64]bool,
) ([]edgeproto.RouteHop, int, error) {
	return solveDijkstraPathWithMeasured(nodes, links, nil, srcNodeID, dstNodeID, liveReverseTunnels)
}

func solveDijkstraPathWithMeasured(
	nodes []EdgeNode,
	links []ServerLink,
	measured map[int64]nodeMeasuredReport,
	srcNodeID, dstNodeID int64,
	liveReverseTunnels map[int64]bool,
) ([]edgeproto.RouteHop, int, error) {
	nodeMap := make(map[int64]*EdgeNode, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		nodeMap[n.ID] = n
	}

	srcNode, ok := nodeMap[srcNodeID]
	if !ok || srcNode.Status != EdgeNodeStatusActive {
		return nil, 0, ErrNoRouteAvailable
	}
	dstNode, ok := nodeMap[dstNodeID]
	if !ok || dstNode.Status != EdgeNodeStatusActive {
		return nil, 0, ErrNoRouteAvailable
	}

	// Direct same-node path (zone entry IS also the landing node).
	if srcNodeID == dstNodeID {
		return []edgeproto.RouteHop{{
			NodeID:    srcNode.ID,
			NodeName:  srcNode.Name,
			Role:      nodePrimaryRole(srcNode),
			Addr:      nodeDialAddr(srcNode),
			LinkClass: LinkClassDirect,
		}}, 0, nil
	}

	disabledPairs, weightBias := indexStaticOverrides(links)

	adj := make(map[int64][]graphEdge, len(nodes))
	measuredDirectSeen := make(map[[2]int64]bool)
	hasMeasuredFrom := make(map[int64]bool)

	addEdge := func(from, to int64, cost int, linkClass string) {
		toNode, ok := nodeMap[to]
		if !ok || toNode.Status != EdgeNodeStatusActive {
			return
		}
		if disabledPairs[[2]int64{from, to}] {
			return
		}
		if (linkClass == LinkClassReverseTunnel || toNode.ConnectMode == ConnectModeReverseTunnel) &&
			liveReverseTunnels != nil && !liveReverseTunnels[to] {
			return
		}
		if cost < 1 {
			cost = 1
		}
		adj[from] = append(adj[from], graphEdge{to: to, cost: cost, linkClass: linkClass})
	}

	// 1. Primary FR-125 auto-measured edges (real live reachability + real RTT!).
	for fromID, rep := range measured {
		fromNode, ok := nodeMap[fromID]
		if !ok || fromNode.Status != EdgeNodeStatusActive {
			continue
		}
		hasMeasuredFrom[fromID] = true
		for _, m := range rep.links {
			if !m.Reachable || m.TargetNodeID <= 0 {
				continue
			}
			pair := [2]int64{fromID, m.TargetNodeID}
			measuredDirectSeen[pair] = true
			lc := m.LinkClass
			if lc == "" {
				lc = LinkClassDirect
			}
			rtt := m.RTTMs
			if rtt < 1 {
				rtt = 1
			}
			addEdge(fromID, m.TargetNodeID, rtt+weightBias[pair], lc)
		}
		for _, revDst := range rep.liveReverseTunnels {
			pair := [2]int64{fromID, revDst}
			if measuredDirectSeen[pair] {
				continue
			}
			measuredDirectSeen[pair] = true
			addEdge(fromID, revDst, 25+weightBias[pair], LinkClassReverseTunnel)
		}
	}

	// 2. Static links serve as cold-start fallback for nodes that haven't reported FR-125 probes yet.
	for _, l := range links {
		if !l.Enabled {
			continue
		}
		fromNode, okFrom := nodeMap[l.SrcNodeID]
		toNode, okTo := nodeMap[l.DstNodeID]
		if !okFrom || !okTo || fromNode.Status != EdgeNodeStatusActive || toNode.Status != EdgeNodeStatusActive {
			continue
		}
		cost := l.Weight + l.RTTMs
		if !hasMeasuredFrom[l.SrcNodeID] && !measuredDirectSeen[[2]int64{l.SrcNodeID, l.DstNodeID}] {
			addEdge(l.SrcNodeID, l.DstNodeID, cost, l.LinkClass)
		}
		if l.Direction == LinkDirectionBidirectional && !hasMeasuredFrom[l.DstNodeID] && !measuredDirectSeen[[2]int64{l.DstNodeID, l.SrcNodeID}] {
			addEdge(l.DstNodeID, l.SrcNodeID, cost, l.LinkClass)
		}
	}

	// Deterministic Dijkstra (small graph: dozens to hundreds of edge nodes).
	dist := make(map[int64]int, len(nodes))
	prev := make(map[int64]int64, len(nodes))
	prevClass := make(map[int64]string, len(nodes))
	visited := make(map[int64]bool, len(nodes))
	for id := range nodeMap {
		dist[id] = math.MaxInt
	}
	dist[srcNodeID] = 0

	for {
		u := int64(0)
		best := math.MaxInt
		for id, d := range dist {
			if visited[id] || d == math.MaxInt {
				continue
			}
			if d < best || (d == best && (u == 0 || id < u)) {
				best = d
				u = id
			}
		}
		if u == 0 || u == dstNodeID {
			break
		}
		visited[u] = true
		for _, e := range adj[u] {
			if visited[e.to] {
				continue
			}
			nd := dist[u] + e.cost
			if nd < dist[e.to] || (nd == dist[e.to] && u < prev[e.to]) {
				dist[e.to] = nd
				prev[e.to] = u
				prevClass[e.to] = e.linkClass
			}
		}
	}

	if dist[dstNodeID] == math.MaxInt {
		return nil, 0, ErrNoRouteAvailable
	}

	// Reconstruct path from srcNodeID -> ... -> dstNodeID.
	revIDs := make([]int64, 0, 8)
	for cur := dstNodeID; ; {
		revIDs = append(revIDs, cur)
		if cur == srcNodeID {
			break
		}
		p, ok := prev[cur]
		if !ok {
			return nil, 0, ErrNoRouteAvailable
		}
		cur = p
	}
	slices.Reverse(revIDs)

	hops := make([]edgeproto.RouteHop, 0, len(revIDs))
	for idx, id := range revIDs {
		n := nodeMap[id]
		lc := LinkClassDirect
		if idx > 0 {
			lc = prevClass[id]
		}
		role := EdgeRoleTransit
		if idx == 0 {
			role = EdgeRoleIngressRelay
		} else if idx == len(revIDs)-1 {
			if n.HasRole(EdgeRoleCompat) && !n.HasRole(EdgeRoleLanding) {
				role = EdgeRoleCompat
			} else {
				role = EdgeRoleLanding
			}
		}
		hops = append(hops, edgeproto.RouteHop{
			NodeID:    n.ID,
			NodeName:  n.Name,
			Role:      role,
			Addr:      nodeDialAddr(n),
			LinkClass: lc,
		})
	}
	return hops, dist[dstNodeID], nil
}

// isZoneClientEntry reports whether an active node in a logical zone can directly
// accept client connections: any direct-mode node with a configured public_addr
// (or legacy ingress_relay role) serves as a zone entry without needing a separate role flag.
func isZoneClientEntry(n EdgeNode) bool {
	if n.Status != EdgeNodeStatusActive || n.ConnectMode == ConnectModeReverseTunnel {
		return false
	}
	if strings.TrimSpace(n.PublicAddr) != "" {
		return true
	}
	return n.HasRole(EdgeRoleIngressRelay)
}

// SelectBestIngressAndRoute picks the lowest-cost active zone entry node in clientZoneID
// that has a healthy Dijkstra path to landingNodeID.
func (s *BerthZoneService) SelectBestIngressAndRoute(
	ctx context.Context,
	clientZoneID, landingNodeID int64,
	liveReverseTunnels map[int64]bool,
) (*EdgeNode, []edgeproto.RouteHop, int, error) {
	return s.SelectBestIngressAndRouteWithRTT(ctx, clientZoneID, landingNodeID, liveReverseTunnels, nil)
}

// SelectBestIngressAndRouteWithRTT picks the zone entry node E in clientZoneID minimizing
// total end-to-end cost: clientEntryRTTMs[E.ID] + dijkstra_cost(E -> landingNodeID).
func (s *BerthZoneService) SelectBestIngressAndRouteWithRTT(
	ctx context.Context,
	clientZoneID, landingNodeID int64,
	liveReverseTunnels map[int64]bool,
	clientEntryRTTMs map[int64]int,
) (*EdgeNode, []edgeproto.RouteHop, int, error) {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	links, err := s.store.ListLinks(ctx)
	if err != nil {
		return nil, nil, 0, err
	}

	candidates := make([]EdgeNode, 0, 8)
	for _, n := range nodes {
		if !isZoneClientEntry(n) {
			continue
		}
		if clientZoneID > 0 && n.ZoneID != clientZoneID {
			continue
		}
		candidates = append(candidates, n)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })

	freshMeasured := s.snapshotFreshMeasured(time.Now())

	var bestIngress *EdgeNode
	var bestHops []edgeproto.RouteHop
	bestCost := math.MaxInt

	for i := range candidates {
		c := &candidates[i]
		hops, pathCost, err := solveDijkstraPathWithMeasured(nodes, links, freshMeasured, c.ID, landingNodeID, liveReverseTunnels)
		if err != nil {
			continue
		}
		totalCost := pathCost
		if rtt, ok := clientEntryRTTMs[c.ID]; ok && rtt > 0 {
			totalCost += rtt
		}
		if totalCost < bestCost {
			bestCost = totalCost
			bestIngress = c
			bestHops = hops
		}
	}
	if bestIngress == nil {
		return nil, nil, 0, ErrNoRouteAvailable
	}
	return bestIngress, bestHops, bestCost, nil
}

// ---------- PostgreSQL BerthZoneStore ----------

type sqlZoneStore struct {
	db *sql.DB
}

func (s *sqlZoneStore) ListZones(ctx context.Context) ([]NetworkZone, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, slug, display_name, is_centre, default_mgmt_policy,
		       dns_hint_domains, geo_country_codes, created_at, updated_at
		FROM berth_network_zones
		ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]NetworkZone, 0, 8)
	for rows.Next() {
		var z NetworkZone
		if err := rows.Scan(
			&z.ID, &z.Slug, &z.DisplayName, &z.IsCentre, &z.DefaultMgmtPolicy,
			pq.Array(&z.DNSHintDomains), pq.Array(&z.GeoCountryCodes),
			&z.CreatedAt, &z.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if z.DNSHintDomains == nil {
			z.DNSHintDomains = []string{}
		}
		if z.GeoCountryCodes == nil {
			z.GeoCountryCodes = []string{}
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

func (s *sqlZoneStore) CreateZone(ctx context.Context, z NetworkZone) (*NetworkZone, error) {
	var created NetworkZone
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO berth_network_zones
			(slug, display_name, is_centre, default_mgmt_policy, dns_hint_domains, geo_country_codes)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, slug, display_name, is_centre, default_mgmt_policy,
		          dns_hint_domains, geo_country_codes, created_at, updated_at`,
		z.Slug, z.DisplayName, z.IsCentre, z.DefaultMgmtPolicy,
		pq.Array(z.DNSHintDomains), pq.Array(z.GeoCountryCodes),
	).Scan(
		&created.ID, &created.Slug, &created.DisplayName, &created.IsCentre, &created.DefaultMgmtPolicy,
		pq.Array(&created.DNSHintDomains), pq.Array(&created.GeoCountryCodes),
		&created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		return nil, mapZoneSQLError(err)
	}
	return &created, nil
}

const edgeNodeSelectCols = `
	id, name, zone_id, roles, public_addr, tunnel_addr, mgmt_entry_addr, connect_mode,
	provider_region, exit_ip, exit_country_code, exit_timezone, exit_locale, exit_asn_class,
	pubkey_ed25519, agent_cert_fingerprint, status, max_bytes_month, used_bytes_month,
	reserved_bytes_month, last_heartbeat_at, meta, created_at, updated_at`

func scanEdgeNode(sc interface{ Scan(...any) error }) (*EdgeNode, error) {
	var n EdgeNode
	var hb sql.NullTime
	var metaBytes []byte
	err := sc.Scan(
		&n.ID, &n.Name, &n.ZoneID, pq.Array(&n.Roles), &n.PublicAddr, &n.TunnelAddr, &n.MgmtEntryAddr, &n.ConnectMode,
		&n.ProviderRegion, &n.ExitIP, &n.ExitCountryCode, &n.ExitTimezone, &n.ExitLocale, &n.ExitASNClass,
		&n.PubkeyEd25519, &n.AgentCertFingerprint, &n.Status, &n.MaxBytesMonth, &n.UsedBytesMonth,
		&n.ReservedBytesMonth, &hb, &metaBytes, &n.CreatedAt, &n.UpdatedAt,
	)
	if err != nil {
		return nil, mapZoneSQLError(err)
	}
	if hb.Valid {
		t := hb.Time
		n.LastHeartbeatAt = &t
	}
	if len(metaBytes) > 0 {
		n.Meta = json.RawMessage(metaBytes)
	} else {
		n.Meta = json.RawMessage(`{}`)
	}
	if n.Roles == nil {
		n.Roles = []string{}
	}
	return &n, nil
}

func (s *sqlZoneStore) ListNodes(ctx context.Context) ([]EdgeNode, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+edgeNodeSelectCols+` FROM berth_edge_nodes ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]EdgeNode, 0, 16)
	for rows.Next() {
		n, err := scanEdgeNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

func (s *sqlZoneStore) GetNode(ctx context.Context, id int64) (*EdgeNode, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+edgeNodeSelectCols+` FROM berth_edge_nodes WHERE id = $1`, id)
	return scanEdgeNode(row)
}

func (s *sqlZoneStore) CreateNode(ctx context.Context, n EdgeNode) (*EdgeNode, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO berth_edge_nodes (
			name, zone_id, roles, public_addr, tunnel_addr, mgmt_entry_addr, connect_mode,
			provider_region, exit_ip, exit_country_code, exit_timezone, exit_locale, exit_asn_class,
			pubkey_ed25519, agent_cert_fingerprint, status, max_bytes_month, meta
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		RETURNING `+edgeNodeSelectCols,
		n.Name, n.ZoneID, pq.Array(n.Roles), n.PublicAddr, n.TunnelAddr, n.MgmtEntryAddr, n.ConnectMode,
		n.ProviderRegion, n.ExitIP, n.ExitCountryCode, n.ExitTimezone, n.ExitLocale, n.ExitASNClass,
		n.PubkeyEd25519, n.AgentCertFingerprint, n.Status, n.MaxBytesMonth, string(n.Meta),
	)
	return scanEdgeNode(row)
}

func (s *sqlZoneStore) UpdateNode(ctx context.Context, n EdgeNode) (*EdgeNode, error) {
	row := s.db.QueryRowContext(ctx, `
		UPDATE berth_edge_nodes SET
			name = $2, zone_id = $3, roles = $4, public_addr = $5, tunnel_addr = $6,
			mgmt_entry_addr = $7, connect_mode = $8, provider_region = $9,
			exit_ip = $10, exit_country_code = $11, exit_timezone = $12, exit_locale = $13, exit_asn_class = $14,
			pubkey_ed25519 = $15, agent_cert_fingerprint = $16, status = $17,
			max_bytes_month = $18, meta = $19::jsonb, updated_at = NOW()
		WHERE id = $1
		RETURNING `+edgeNodeSelectCols,
		n.ID, n.Name, n.ZoneID, pq.Array(n.Roles), n.PublicAddr, n.TunnelAddr,
		n.MgmtEntryAddr, n.ConnectMode, n.ProviderRegion,
		n.ExitIP, n.ExitCountryCode, n.ExitTimezone, n.ExitLocale, n.ExitASNClass,
		n.PubkeyEd25519, n.AgentCertFingerprint, n.Status, n.MaxBytesMonth, string(n.Meta),
	)
	return scanEdgeNode(row)
}

func (s *sqlZoneStore) RecordHeartbeat(ctx context.Context, nodeID int64, upd EdgeHeartbeatUpdate, at time.Time) (*EdgeNode, error) {
	var metaParam sql.NullString
	if trimmed := strings.TrimSpace(string(upd.Meta)); trimmed != "" {
		metaParam = sql.NullString{String: trimmed, Valid: true}
	}
	row := s.db.QueryRowContext(ctx, `
		UPDATE berth_edge_nodes SET
			status = CASE WHEN status = 'suspended' OR $2 = '' THEN status ELSE $2 END,
			exit_ip = CASE WHEN $3 <> '' THEN $3 ELSE exit_ip END,
			exit_country_code = CASE WHEN $4 <> '' THEN $4 ELSE exit_country_code END,
			exit_timezone = CASE WHEN $5 <> '' THEN $5 ELSE exit_timezone END,
			exit_locale = CASE WHEN $6 <> '' THEN $6 ELSE exit_locale END,
			exit_asn_class = CASE WHEN $7 <> '' THEN $7 ELSE exit_asn_class END,
			meta = COALESCE(meta, '{}'::jsonb) || COALESCE($8::jsonb, '{}'::jsonb),
			last_heartbeat_at = $9,
			updated_at = NOW()
		WHERE id = $1
		RETURNING `+edgeNodeSelectCols,
		nodeID, upd.Status, upd.ExitIP, upd.ExitCountryCode, upd.ExitTimezone,
		upd.ExitLocale, upd.ExitASNClass, metaParam, at,
	)
	return scanEdgeNode(row)
}

func (s *sqlZoneStore) ListLinks(ctx context.Context) ([]ServerLink, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, src_node_id, dst_node_id, direction, link_class, weight, rtt_ms, enabled, created_at, updated_at
		FROM berth_server_links
		ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]ServerLink, 0, 16)
	for rows.Next() {
		var l ServerLink
		if err := rows.Scan(
			&l.ID, &l.SrcNodeID, &l.DstNodeID, &l.Direction, &l.LinkClass,
			&l.Weight, &l.RTTMs, &l.Enabled, &l.CreatedAt, &l.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *sqlZoneStore) CreateLink(ctx context.Context, l ServerLink) (*ServerLink, error) {
	var created ServerLink
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO berth_server_links (src_node_id, dst_node_id, direction, link_class, weight, rtt_ms, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, src_node_id, dst_node_id, direction, link_class, weight, rtt_ms, enabled, created_at, updated_at`,
		l.SrcNodeID, l.DstNodeID, l.Direction, l.LinkClass, l.Weight, l.RTTMs, l.Enabled,
	).Scan(
		&created.ID, &created.SrcNodeID, &created.DstNodeID, &created.Direction, &created.LinkClass,
		&created.Weight, &created.RTTMs, &created.Enabled, &created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		return nil, mapZoneSQLError(err)
	}
	return &created, nil
}

func (s *sqlZoneStore) DeleteLink(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM berth_server_links WHERE id = $1`, id)
	if err != nil {
		return mapZoneSQLError(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrEdgeZoneNotFound
	}
	return nil
}

func mapZoneSQLError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEdgeZoneNotFound
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23505":
			return fmt.Errorf("%w: %s", ErrEdgeZoneConflict, pqErr.Detail)
		case "23503", "23514":
			return fmt.Errorf("%w: %s", ErrEdgeZoneInvalid, pqErr.Message)
		}
	}
	return err
}

// ---------- In-Memory BerthZoneStore (for unit/E2E tests & standalone harnesses) ----------

type MemoryZoneStore struct {
	mu         sync.RWMutex
	nextZoneID int64
	nextNodeID int64
	nextLinkID int64
	zones      map[int64]NetworkZone
	nodes      map[int64]EdgeNode
	links      map[int64]ServerLink
}

// NewMemoryZoneStore creates an in-memory zone store pre-seeded with default Berth v2 zones.
func NewMemoryZoneStore(seedDefaults bool) *MemoryZoneStore {
	st := &MemoryZoneStore{
		zones: make(map[int64]NetworkZone),
		nodes: make(map[int64]EdgeNode),
		links: make(map[int64]ServerLink),
	}
	if seedDefaults {
		defaults := []NetworkZone{
			{Slug: "centre_isvoro", DisplayName: "Centre (Isvoro)", IsCentre: true, DefaultMgmtPolicy: "direct_allowed"},
			{Slug: "cn_mainland", DisplayName: "China Mainland", IsCentre: false, DefaultMgmtPolicy: "entry_required", GeoCountryCodes: []string{"CN"}},
			{Slug: "overseas", DisplayName: "Overseas", IsCentre: false, DefaultMgmtPolicy: "direct_preferred"},
			{Slug: "home_direct", DisplayName: "Home Direct", IsCentre: false, DefaultMgmtPolicy: "direct_preferred"},
		}
		for _, z := range defaults {
			_, _ = st.CreateZone(context.Background(), z)
		}
	}
	return st
}

func (m *MemoryZoneStore) ListZones(context.Context) ([]NetworkZone, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]NetworkZone, 0, len(m.zones))
	for _, z := range m.zones {
		out = append(out, z)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemoryZoneStore) CreateZone(_ context.Context, z NetworkZone) (*NetworkZone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.zones {
		if existing.Slug == z.Slug {
			return nil, ErrEdgeZoneConflict
		}
		if z.IsCentre && existing.IsCentre {
			return nil, ErrEdgeZoneConflict
		}
	}
	m.nextZoneID++
	now := time.Now()
	z.ID = m.nextZoneID
	z.CreatedAt = now
	z.UpdatedAt = now
	m.zones[z.ID] = z
	cp := z
	return &cp, nil
}

func (m *MemoryZoneStore) ListNodes(context.Context) ([]EdgeNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]EdgeNode, 0, len(m.nodes))
	for _, n := range m.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemoryZoneStore) GetNode(_ context.Context, id int64) (*EdgeNode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.nodes[id]
	if !ok {
		return nil, ErrEdgeZoneNotFound
	}
	cp := n
	return &cp, nil
}

func (m *MemoryZoneStore) CreateNode(_ context.Context, n EdgeNode) (*EdgeNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.zones[n.ZoneID]; !ok {
		return nil, ErrEdgeZoneInvalid
	}
	for _, existing := range m.nodes {
		if existing.Name == n.Name {
			return nil, ErrEdgeZoneConflict
		}
	}
	m.nextNodeID++
	now := time.Now()
	n.ID = m.nextNodeID
	n.CreatedAt = now
	n.UpdatedAt = now
	m.nodes[n.ID] = n
	cp := n
	return &cp, nil
}

func (m *MemoryZoneStore) UpdateNode(_ context.Context, n EdgeNode) (*EdgeNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.nodes[n.ID]
	if !ok {
		return nil, ErrEdgeZoneNotFound
	}
	n.CreatedAt = cur.CreatedAt
	n.UsedBytesMonth = cur.UsedBytesMonth
	n.ReservedBytesMonth = cur.ReservedBytesMonth
	n.LastHeartbeatAt = cur.LastHeartbeatAt
	n.UpdatedAt = time.Now()
	m.nodes[n.ID] = n
	cp := n
	return &cp, nil
}

func (m *MemoryZoneStore) RecordHeartbeat(_ context.Context, nodeID int64, upd EdgeHeartbeatUpdate, at time.Time) (*EdgeNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.nodes[nodeID]
	if !ok {
		return nil, ErrEdgeZoneNotFound
	}
	if cur.Status != EdgeNodeStatusSuspended {
		cur.Status = upd.Status
	}
	if upd.ExitIP != "" {
		cur.ExitIP = upd.ExitIP
	}
	if upd.ExitCountryCode != "" {
		cur.ExitCountryCode = upd.ExitCountryCode
	}
	if upd.ExitTimezone != "" {
		cur.ExitTimezone = upd.ExitTimezone
	}
	if upd.ExitLocale != "" {
		cur.ExitLocale = upd.ExitLocale
	}
	if upd.ExitASNClass != "" {
		cur.ExitASNClass = upd.ExitASNClass
	}
	if len(upd.Meta) > 0 {
		cur.Meta = upd.Meta
	}
	t := at
	cur.LastHeartbeatAt = &t
	cur.UpdatedAt = at
	m.nodes[nodeID] = cur
	cp := cur
	return &cp, nil
}

func (m *MemoryZoneStore) ListLinks(context.Context) ([]ServerLink, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ServerLink, 0, len(m.links))
	for _, l := range m.links {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemoryZoneStore) CreateLink(_ context.Context, l ServerLink) (*ServerLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nodes[l.SrcNodeID]; !ok {
		return nil, ErrEdgeZoneInvalid
	}
	if _, ok := m.nodes[l.DstNodeID]; !ok {
		return nil, ErrEdgeZoneInvalid
	}
	for _, ex := range m.links {
		if ex.SrcNodeID == l.SrcNodeID && ex.DstNodeID == l.DstNodeID {
			return nil, ErrEdgeZoneConflict
		}
	}
	m.nextLinkID++
	now := time.Now()
	l.ID = m.nextLinkID
	l.CreatedAt = now
	l.UpdatedAt = now
	m.links[l.ID] = l
	cp := l
	return &cp, nil
}

func (m *MemoryZoneStore) DeleteLink(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.links[id]; !ok {
		return ErrEdgeZoneNotFound
	}
	delete(m.links, id)
	return nil
}
