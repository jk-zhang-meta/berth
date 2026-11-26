package edge

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ProbeTarget describes a peer berth-edge node pushed by Central for FR-125 auto-probing.
type ProbeTarget struct {
	NodeID   int64  `json:"node_id"`
	NodeName string `json:"node_name"`
	Addr     string `json:"addr"`
}

// MeasuredPeerLink is a directional reachability and RTT measurement from this node to TargetNodeID.
type MeasuredPeerLink struct {
	TargetNodeID   int64  `json:"target_node_id"`
	TargetName     string `json:"target_name,omitempty"`
	Reachable      bool   `json:"reachable"`
	RTTMs          int    `json:"rtt_ms"`
	LinkClass      string `json:"link_class"` // direct | reverse_tunnel
	MeasuredAtUnix int64  `json:"measured_at_unix"`
}

// PeerProber implements MeshHarbor FR-125 style peer auto-discovery: every online berth-edge
// periodically probes peer /healthz endpoints (and connected reverse-tunnel peers) and reports
// real directional reachability + EWMA-smoothed RTT back to Berth Central.
type PeerProber struct {
	selfNodeID int64
	revHub     *ReverseTunnelHub
	httpClient *http.Client
	interval   time.Duration

	mu       sync.RWMutex
	targets  []ProbeTarget
	measured map[int64]MeasuredPeerLink
	kickCh   chan struct{}
}

// NewPeerProber constructs a bounded-concurrency FR-125 peer prober.
func NewPeerProber(selfNodeID int64, revHub *ReverseTunnelHub, interval time.Duration) *PeerProber {
	if interval <= 0 {
		interval = 20 * time.Second
	}
	return &PeerProber{
		selfNodeID: selfNodeID,
		revHub:     revHub,
		httpClient: &http.Client{
			Timeout: 2500 * time.Millisecond,
			Transport: &http.Transport{
				MaxIdleConns:        16,
				IdleConnTimeout:     30 * time.Second,
				DisableKeepAlives:   true,
				ResponseHeaderTimeout: 2500 * time.Millisecond,
			},
		},
		interval: interval,
		measured: make(map[int64]MeasuredPeerLink),
		kickCh:   make(chan struct{}, 1),
	}
}

// UpdateTargets replaces the Central-advertised peer probe list and triggers an immediate probe on first load.
func (p *PeerProber) UpdateTargets(targets []ProbeTarget) {
	if p == nil {
		return
	}
	clean := make([]ProbeTarget, 0, len(targets))
	seen := make(map[int64]struct{}, len(targets))
	for _, t := range targets {
		addr := strings.TrimSpace(t.Addr)
		addr = strings.TrimPrefix(addr, "http://")
		addr = strings.TrimPrefix(addr, "https://")
		addr = strings.TrimRight(addr, "/")
		if t.NodeID <= 0 || t.NodeID == p.selfNodeID || addr == "" {
			continue
		}
		if _, dup := seen[t.NodeID]; dup {
			continue
		}
		seen[t.NodeID] = struct{}{}
		clean = append(clean, ProbeTarget{
			NodeID:   t.NodeID,
			NodeName: t.NodeName,
			Addr:     addr,
		})
	}

	p.mu.Lock()
	hadTargets := len(p.targets) > 0
	p.targets = clean
	// Prune direct measurements for targets removed from the fleet.
	for id, m := range p.measured {
		if m.LinkClass != "reverse_tunnel" {
			if _, ok := seen[id]; !ok {
				delete(p.measured, id)
			}
		}
	}
	p.mu.Unlock()

	if !hadTargets && len(clean) > 0 {
		select {
		case p.kickCh <- struct{}{}:
		default:
		}
	}
}

// Run executes periodic peer probes until ctx is cancelled.
func (p *PeerProber) Run(ctx context.Context) {
	if p == nil {
		return
	}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.kickCh:
			p.ProbeOnce(ctx)
		case <-ticker.C:
			p.ProbeOnce(ctx)
		}
	}
}

// ProbeOnce runs one bounded-concurrency measurement sweep across all direct targets and live reverse tunnels.
func (p *PeerProber) ProbeOnce(ctx context.Context) {
	if p == nil {
		return
	}
	p.mu.RLock()
	targets := append([]ProbeTarget(nil), p.targets...)
	p.mu.RUnlock()

	var revPeers []int64
	if p.revHub != nil {
		revPeers = p.revHub.ConnectedNodeIDs()
	}

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	// 1. Probe direct peer targets.
	for _, tgt := range targets {
		wg.Add(1)
		go func(t ProbeTarget) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			reachable, rttMs := p.probeDirect(ctx, t.Addr)
			p.recordSample(t.NodeID, t.NodeName, "direct", reachable, rttMs)
		}(tgt)
	}

	// 2. Probe connected reverse-tunnel landing peers directly over their live H2 reverse tunnel.
	revSet := make(map[int64]struct{}, len(revPeers))
	for _, peerID := range revPeers {
		revSet[peerID] = struct{}{}
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			reachable, rttMs := p.probeReverseTunnel(ctx, id)
			p.recordSample(id, "", "reverse_tunnel", reachable, rttMs)
		}(peerID)
	}

	wg.Wait()

	// Remove stale reverse_tunnel entries for peers that disconnected.
	p.mu.Lock()
	for id, m := range p.measured {
		if m.LinkClass == "reverse_tunnel" {
			if _, alive := revSet[id]; !alive {
				delete(p.measured, id)
			}
		}
	}
	p.mu.Unlock()
}

func (p *PeerProber) probeDirect(ctx context.Context, addr string) (bool, int) {
	pctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, "http://"+addr+"/healthz", nil)
	if err != nil {
		return false, 0
	}
	start := time.Now()
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false, 0
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, 0
	}
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return true, ms
}

func (p *PeerProber) probeReverseTunnel(ctx context.Context, nodeID int64) (bool, int) {
	if p.revHub == nil {
		return false, 0
	}
	pctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, fmt.Sprintf("http://node-%d.edge.internal/healthz", nodeID), nil)
	if err != nil {
		return false, 0
	}
	start := time.Now()
	resp, err := p.revHub.RoundTrip(nodeID, req)
	if err != nil {
		return false, 0
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, 0
	}
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return true, ms
}

func (p *PeerProber) recordSample(targetID int64, targetName, linkClass string, reachable bool, sampleMs int) {
	nowUnix := time.Now().Unix()
	p.mu.Lock()
	defer p.mu.Unlock()
	prev, exists := p.measured[targetID]
	rtt := sampleMs
	if reachable && exists && prev.Reachable && prev.RTTMs > 0 {
		// EWMA smoothing (70% previous + 30% latest) prevents route flapping on transient jitter.
		rtt = (prev.RTTMs*7 + sampleMs*3) / 10
		if rtt < 1 {
			rtt = 1
		}
	}
	if targetName == "" {
		targetName = prev.TargetName
	}
	p.measured[targetID] = MeasuredPeerLink{
		TargetNodeID:   targetID,
		TargetName:     targetName,
		Reachable:      reachable,
		RTTMs:          rtt,
		LinkClass:      linkClass,
		MeasuredAtUnix: nowUnix,
	}
}

// Snapshot returns the latest sorted peer measurements and currently connected reverse-tunnel node IDs.
func (p *PeerProber) Snapshot() ([]MeasuredPeerLink, []int64) {
	if p == nil {
		return nil, nil
	}
	p.mu.RLock()
	links := make([]MeasuredPeerLink, 0, len(p.measured))
	for _, m := range p.measured {
		links = append(links, m)
	}
	p.mu.RUnlock()
	sort.Slice(links, func(i, j int) bool { return links[i].TargetNodeID < links[j].TargetNodeID })

	var liveRev []int64
	if p.revHub != nil {
		liveRev = p.revHub.ConnectedNodeIDs()
		if liveRev == nil {
			liveRev = []int64{}
		}
	}
	return links, liveRev
}
