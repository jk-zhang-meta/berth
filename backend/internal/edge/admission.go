package edge

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
)

var (
	ErrGrantConcurrencyLimit = errors.New("edge: landing grant concurrency limit exceeded")
	ErrGrantRPMLimit         = errors.New("edge: landing grant RPM limit exceeded")
	ErrLandingNodeMismatch   = errors.New("edge: lease landing_node_id does not match this node")
	ErrStreamRevoked         = errors.New("edge: active stream terminated by revocation or snapshot expiry")
)

// GrantLimits configures per-grant runtime concurrency and RPM enforcement at Landing.
type GrantLimits struct {
	MaxConcurrency int
	MaxRPM         int
}

// SliceRefiller requests the next disjoint byte slice for grantID from Berth Central.
type SliceRefiller func(ctx context.Context, grantID int64, wantBytes int64) (sliceID string, grantedBytes int64, expiresAt time.Time, err error)

type rpmWindow struct {
	mu         sync.Mutex
	timestamps []int64
}

func (w *rpmWindow) allow(limit int, now time.Time) bool {
	if limit <= 0 {
		return true
	}
	cutoff := now.Add(-time.Minute).UnixNano()
	nowNs := now.UnixNano()
	w.mu.Lock()
	defer w.mu.Unlock()
	kept := w.timestamps[:0]
	for _, ts := range w.timestamps {
		if ts > cutoff {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= limit {
		w.timestamps = kept
		return false
	}
	w.timestamps = append(kept, nowNs)
	return true
}

type activeStreamEntry struct {
	id        uint64
	claims    *edgeproto.SessionLeaseClaims
	cancel    context.CancelCauseFunc
	onRevoke  func(reason error)
	revokeOnce sync.Once
}

func (e *activeStreamEntry) terminate(reason error) {
	e.revokeOnce.Do(func() {
		if e.onRevoke != nil {
			e.onRevoke(reason)
		}
		if e.cancel != nil {
			e.cancel(reason)
		}
	})
}

// AdmissionGate is the SINGLE fenced admission authority shared across HTTP, SSE,
// WebSocket, and Compat execution paths (Codex Blockers #1.1, #1.2, #1.5):
//   - Verifies Ed25519 lease signature + bound claims + landing node match
//   - Enforces fresh Central-signed RevocationSnapshot (fails closed when missing/stale)
//   - Tracks all active streams by (lease_id, grant_id, cage_id, api_key_id) and
//     immediately terminates live HTTP/SSE/WS streams on revocation or snapshot staleness
//   - Enforces per-grant concurrency, RPM, and durable pre-debited disjoint byte-slice WAL
type AdmissionGate struct {
	centralPubKey ed25519.PublicKey
	wal           *edgeproto.GrantWAL
	refiller      SliceRefiller
	sliceBytes    int64
	lowWatermark  int64
	nowFn         func() time.Time

	mu              sync.RWMutex
	snapshot        *edgeproto.RevocationSnapshot
	grantLimits     map[int64]GrantLimits
	grantInflight   map[int64]int
	grantRPM        map[int64]*rpmWindow
	refillMuByGrant map[int64]*sync.Mutex
	activeStreams   map[uint64]*activeStreamEntry
	nextStreamID    atomic.Uint64
}

// NewAdmissionGate constructs a single fenced AdmissionGate.
// wal and refiller may be nil on pure Ingress Relay nodes (which verify leases &
// revocations without performing Landing byte-slice debiting).
func NewAdmissionGate(
	centralPubKey ed25519.PublicKey,
	wal *edgeproto.GrantWAL,
	refiller SliceRefiller,
	sliceBytes, lowWatermark int64,
) *AdmissionGate {
	if sliceBytes <= 0 {
		sliceBytes = DefaultGrantSliceBytes
	}
	if lowWatermark <= 0 {
		lowWatermark = min(DefaultGrantLowWatermark, sliceBytes/4)
	}
	return &AdmissionGate{
		centralPubKey:   centralPubKey,
		wal:             wal,
		refiller:        refiller,
		sliceBytes:      sliceBytes,
		lowWatermark:    lowWatermark,
		nowFn:           time.Now,
		grantLimits:     make(map[int64]GrantLimits),
		grantInflight:   make(map[int64]int),
		grantRPM:        make(map[int64]*rpmWindow),
		refillMuByGrant: make(map[int64]*sync.Mutex),
		activeStreams:   make(map[uint64]*activeStreamEntry),
	}
}

// SetNowFunc overrides the clock for deterministic unit tests.
func (g *AdmissionGate) SetNowFunc(fn func() time.Time) {
	if fn != nil {
		g.nowFn = fn
	}
}

// SetGrantLimits configures concurrency/RPM caps for a landing grant.
func (g *AdmissionGate) SetGrantLimits(grantID int64, limits GrantLimits) {
	g.mu.Lock()
	g.grantLimits[grantID] = limits
	g.mu.Unlock()
}

// UpdateSnapshot verifies a signed Central RevocationSnapshot, installs it if
// monotonic, updates WAL revocations, and IMMEDIATELY terminates any active
// HTTP/SSE/WS streams invalidated by the new snapshot!
func (g *AdmissionGate) UpdateSnapshot(snap *edgeproto.RevocationSnapshot) error {
	now := g.nowFn()
	if err := edgeproto.VerifyRevocationSnapshot(g.centralPubKey, snap, now); err != nil {
		return err
	}

	var toTerminate []*activeStreamEntry
	var termReasons []error

	g.mu.Lock()
	if g.snapshot != nil && snap.Seq < g.snapshot.Seq {
		g.mu.Unlock()
		return edgeproto.ErrRevocationSnapshotBehind
	}
	cp := *snap
	g.snapshot = &cp

	for _, st := range g.activeStreams {
		if err := cp.IsAuthorized(st.claims, now); err != nil {
			toTerminate = append(toTerminate, st)
			termReasons = append(termReasons, err)
		}
	}
	g.mu.Unlock()

	if g.wal != nil {
		for _, gid := range snap.RevokedGrantIDs {
			_ = g.wal.RevokeGrant(gid)
		}
	}
	for i, st := range toTerminate {
		st.terminate(fmt.Errorf("%w: %v", ErrStreamRevoked, termReasons[i]))
	}
	return nil
}

// SweepFreshness checks all active streams against the current snapshot and wall clock.
// If the revocation snapshot is missing or expired (stale), ALL active streams are
// immediately terminated fail-closed (Codex Blocker #1.2).
func (g *AdmissionGate) SweepFreshness() int {
	now := g.nowFn()
	var toTerminate []*activeStreamEntry
	var termReasons []error

	g.mu.RLock()
	snap := g.snapshot
	for _, st := range g.activeStreams {
		if err := snap.IsAuthorized(st.claims, now); err != nil {
			toTerminate = append(toTerminate, st)
			termReasons = append(termReasons, err)
		}
	}
	g.mu.RUnlock()

	for i, st := range toTerminate {
		st.terminate(fmt.Errorf("%w: %v", ErrStreamRevoked, termReasons[i]))
	}
	return len(toTerminate)
}

// StartFreshnessWatchdog periodically runs SweepFreshness until ctx is cancelled.
func (g *AdmissionGate) StartFreshnessWatchdog(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.SweepFreshness()
		}
	}
}

// ActiveStreamCount returns the number of currently admitted active streams.
func (g *AdmissionGate) ActiveStreamCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.activeStreams)
}

func (g *AdmissionGate) getGrantRefillLock(grantID int64) *sync.Mutex {
	g.mu.Lock()
	defer g.mu.Unlock()
	m, ok := g.refillMuByGrant[grantID]
	if !ok {
		m = &sync.Mutex{}
		g.refillMuByGrant[grantID] = m
	}
	return m
}

func (g *AdmissionGate) ensureSliceCapacity(ctx context.Context, grantID int64, minNeeded int64) error {
	if g.wal == nil || grantID <= 0 {
		return nil
	}
	if !g.wal.NeedsRefill(grantID, max(g.lowWatermark, minNeeded)) {
		return nil
	}
	if g.refiller == nil {
		return nil
	}
	refillMu := g.getGrantRefillLock(grantID)
	refillMu.Lock()
	defer refillMu.Unlock()

	if !g.wal.NeedsRefill(grantID, max(g.lowWatermark, minNeeded)) {
		return nil
	}
	want := max(g.sliceBytes, minNeeded)
	sliceID, granted, exp, err := g.refiller(ctx, grantID, want)
	if err != nil {
		return err
	}
	if granted <= 0 {
		return edgeproto.ErrGrantSliceExhausted
	}
	return g.wal.AddSlice(sliceID, grantID, granted, exp)
}

// AdmittedStream represents a live stream fenced by AdmissionGate.
type AdmittedStream struct {
	gate        *AdmissionGate
	id          uint64
	claims      *edgeproto.SessionLeaseClaims
	ctx         context.Context
	cancel      context.CancelCauseFunc
	releaseOnce sync.Once
}

// Context returns the stream's cancellable context (cancelled immediately on revocation/stale snapshot).
func (s *AdmittedStream) Context() context.Context { return s.ctx }

// Claims returns the verified Ed25519 SessionLeaseClaims for this stream.
func (s *AdmittedStream) Claims() *edgeproto.SessionLeaseClaims { return s.claims }

// PreDebit durably pre-debits exactly chunkBytes BEFORE forwarding in either direction.
// Transparently requests the next disjoint slice from Berth Central if below watermark,
// failing closed with edgeproto.ErrGrantSliceExhausted if quota is exhausted.
func (s *AdmittedStream) PreDebit(ctx context.Context, chunkBytes int64) (string, error) {
	if s.gate.wal == nil || s.claims.GrantID <= 0 || chunkBytes <= 0 {
		return "", nil
	}
	if err := s.ctx.Err(); err != nil {
		return "", context.Cause(s.ctx)
	}
	now := s.gate.nowFn()
	if debitID, err := s.gate.wal.PreDebit(s.claims.GrantID, chunkBytes, now); err == nil {
		// Proactively trigger refill if below low watermark (best-effort).
		if s.gate.wal.NeedsRefill(s.claims.GrantID, s.gate.lowWatermark) {
			_ = s.gate.ensureSliceCapacity(ctx, s.claims.GrantID, chunkBytes)
		}
		return debitID, nil
	} else if !errors.Is(err, edgeproto.ErrGrantSliceExhausted) {
		return "", err
	}

	// Refill synchronously and retry once.
	if err := s.gate.ensureSliceCapacity(ctx, s.claims.GrantID, chunkBytes); err != nil {
		return "", edgeproto.ErrGrantSliceExhausted
	}
	return s.gate.wal.PreDebit(s.claims.GrantID, chunkBytes, s.gate.nowFn())
}

// PreDebitUpTo durably pre-debits min(wantBytes, remaining) so streaming stops at
// the exact last admitted byte without overspending.
func (s *AdmittedStream) PreDebitUpTo(ctx context.Context, wantBytes int64) (int64, string, error) {
	if s.gate.wal == nil || s.claims.GrantID <= 0 || wantBytes <= 0 {
		return wantBytes, "", nil
	}
	if err := s.ctx.Err(); err != nil {
		return 0, "", context.Cause(s.ctx)
	}
	if s.gate.wal.NeedsRefill(s.claims.GrantID, s.gate.lowWatermark) {
		_ = s.gate.ensureSliceCapacity(ctx, s.claims.GrantID, wantBytes)
	}
	admitted, debitID, err := s.gate.wal.PreDebitUpTo(s.claims.GrantID, wantBytes, s.gate.nowFn())
	if errors.Is(err, edgeproto.ErrGrantSliceExhausted) {
		if refillErr := s.gate.ensureSliceCapacity(ctx, s.claims.GrantID, wantBytes); refillErr == nil {
			return s.gate.wal.PreDebitUpTo(s.claims.GrantID, wantBytes, s.gate.nowFn())
		}
	}
	return admitted, debitID, err
}

// RefundConfirmedUnsent refunds strictly unused tail bytes after an in-process short read/write.
func (s *AdmittedStream) RefundConfirmedUnsent(debitID string, unusedBytes int64) {
	if s.gate.wal == nil || s.claims.GrantID <= 0 || debitID == "" || unusedBytes <= 0 {
		return
	}
	_ = s.gate.wal.RefundConfirmedUnsent(debitID, s.claims.GrantID, unusedBytes)
}

// Release unregisters the stream and releases per-grant concurrency capacity.
func (s *AdmittedStream) Release() {
	s.releaseOnce.Do(func() {
		s.cancel(nil)
		s.gate.mu.Lock()
		delete(s.gate.activeStreams, s.id)
		if s.claims.GrantID > 0 {
			if cur := s.gate.grantInflight[s.claims.GrantID]; cur <= 1 {
				delete(s.gate.grantInflight, s.claims.GrantID)
			} else {
				s.gate.grantInflight[s.claims.GrantID] = cur - 1
			}
		}
		s.gate.mu.Unlock()
	})
}

// Admit verifies the Ed25519 lease, enforces the current fresh RevocationSnapshot,
// checks expectedLandingNodeID (when > 0), checks grant concurrency/RPM/WAL budget,
// and registers the live stream for instant revocation termination.
func (g *AdmissionGate) Admit(
	parentCtx context.Context,
	leaseToken string,
	expectedLandingNodeID int64,
	onRevoke func(reason error),
) (*AdmittedStream, error) {
	now := g.nowFn()

	claims, err := edgeproto.VerifyLease(g.centralPubKey, leaseToken, now)
	if err != nil {
		return nil, err
	}
	if expectedLandingNodeID > 0 && claims.LandingNodeID != expectedLandingNodeID {
		return nil, fmt.Errorf("%w: lease=%d self=%d", ErrLandingNodeMismatch, claims.LandingNodeID, expectedLandingNodeID)
	}

	g.mu.Lock()
	snap := g.snapshot
	if err := snap.IsAuthorized(claims, now); err != nil {
		g.mu.Unlock()
		return nil, err
	}

	// Enforce per-grant concurrency & RPM limits at the fenced owner.
	if claims.GrantID > 0 {
		lim := g.grantLimits[claims.GrantID]
		if lim.MaxConcurrency > 0 && g.grantInflight[claims.GrantID] >= lim.MaxConcurrency {
			g.mu.Unlock()
			return nil, ErrGrantConcurrencyLimit
		}
		if lim.MaxRPM > 0 {
			win, ok := g.grantRPM[claims.GrantID]
			if !ok {
				win = &rpmWindow{}
				g.grantRPM[claims.GrantID] = win
			}
			if !win.allow(lim.MaxRPM, now) {
				g.mu.Unlock()
				return nil, ErrGrantRPMLimit
			}
		}
		g.grantInflight[claims.GrantID]++
	}

	streamCtx, cancel := context.WithCancelCause(parentCtx)
	streamID := g.nextStreamID.Add(1)
	g.activeStreams[streamID] = &activeStreamEntry{
		id:       streamID,
		claims:   claims,
		cancel:   cancel,
		onRevoke: onRevoke,
	}
	g.mu.Unlock()

	stream := &AdmittedStream{
		gate:   g,
		id:     streamID,
		claims: claims,
		ctx:    streamCtx,
		cancel: cancel,
	}

	// On Landing nodes (wal != nil) with a bound grant, verify at least 1 byte is available
	// (requesting a disjoint slice from Central if needed) before admitting the request!
	if g.wal != nil && claims.GrantID > 0 {
		if g.wal.Remaining(claims.GrantID) <= 0 {
			if err := g.ensureSliceCapacity(streamCtx, claims.GrantID, 1); err != nil {
				stream.Release()
				return nil, edgeproto.ErrGrantSliceExhausted
			}
		}
		if g.wal.Remaining(claims.GrantID) <= 0 {
			stream.Release()
			return nil, edgeproto.ErrGrantSliceExhausted
		}
	}

	return stream, nil
}
