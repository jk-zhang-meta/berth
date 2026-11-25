package edgeproto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func genKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func TestLeaseAndRevocationSnapshotAuthorization(t *testing.T) {
	pub, priv := genKeyPair(t)
	otherPub, _ := genKeyPair(t)
	now := time.Unix(1_700_000_000, 0)

	claims := SessionLeaseClaims{
		LeaseID:           "11111111-1111-1111-1111-111111111111",
		JTI:               "jti-001",
		UserID:            42,
		APIKeyID:          77,
		WorkSessionID:     100,
		Platform:          "openai",
		AccountID:         501,
		CageID:            88,
		CageEpoch:         3,
		GrantID:           9001,
		IngressNodeID:     10,
		LandingNodeID:     20,
		RouteChain:        []RouteHop{{NodeID: 10, NodeName: "gz", Role: "ingress_relay", LinkClass: "direct"}, {NodeID: 20, NodeName: "tokyo", Role: "landing", LinkClass: "iplc"}},
		CohortTimezone:    "Asia/Tokyo",
		CohortCountryCode: "JP",
		CohortLocale:      "ja_JP.UTF-8",
		RevSeq:            5,
		LeaseEpoch:        1,
		IssuedAt:          now.Unix(),
		ExpiresAt:         now.Add(15 * time.Minute).Unix(),
	}

	tok, err := SignLease(priv, "", claims)
	require.NoError(t, err)

	got, err := VerifyLease(pub, tok, now.Add(time.Minute))
	require.NoError(t, err)
	require.Equal(t, claims.LeaseID, got.LeaseID)
	require.Equal(t, claims.CageEpoch, got.CageEpoch)
	require.Equal(t, claims.GrantID, got.GrantID)
	require.Len(t, got.RouteChain, 2)

	// Wrong public key fails closed.
	_, err = VerifyLease(otherPub, tok, now)
	require.ErrorIs(t, err, ErrLeaseSignatureInvalid)

	// Expired lease fails closed.
	_, err = VerifyLease(pub, tok, now.Add(16*time.Minute))
	require.ErrorIs(t, err, ErrLeaseExpired)

	// Build valid signed revocation snapshot.
	snap := &RevocationSnapshot{
		Seq:              5,
		IssuedAt:         now.Unix(),
		ValidUntil:       now.Add(60 * time.Second).Unix(),
		RevokedLeaseIDs:  []string{},
		RevokedGrantIDs:  []int64{},
		RevokedAPIKeyIDs: []int64{},
		CageMinEpochs:    map[int64]int64{88: 3},
	}
	require.NoError(t, SignRevocationSnapshot(priv, "", snap))
	require.NoError(t, VerifyAndAuthorize(pub, snap, got, now.Add(10*time.Second)))

	// Missing snapshot fails closed.
	var nilSnap *RevocationSnapshot
	require.ErrorIs(t, nilSnap.IsAuthorized(got, now), ErrRevocationSnapshotMissing)

	// Stale/expired snapshot fails closed.
	require.ErrorIs(t, snap.IsAuthorized(got, now.Add(61*time.Second)), ErrRevocationSnapshotStale)

	// Snapshot behind lease rev_seq fails closed.
	behindSnap := *snap
	behindSnap.Seq = 4
	require.ErrorIs(t, behindSnap.IsAuthorized(got, now.Add(5*time.Second)), ErrRevocationSnapshotBehind)

	// Tampered snapshot signature fails closed.
	tampered := *snap
	tampered.Seq = 99
	require.ErrorIs(t, VerifyRevocationSnapshot(pub, &tampered, now.Add(5*time.Second)), ErrRevocationSnapshotInvalid)

	// Revoked lease ID rejected.
	revLease := *snap
	revLease.RevokedLeaseIDs = []string{claims.LeaseID}
	require.ErrorIs(t, revLease.IsAuthorized(got, now.Add(5*time.Second)), ErrLeaseRevoked)

	// Revoked grant ID rejected.
	revGrant := *snap
	revGrant.RevokedGrantIDs = []int64{claims.GrantID}
	require.ErrorIs(t, revGrant.IsAuthorized(got, now.Add(5*time.Second)), ErrGrantRevoked)

	// Revoked API key rejected.
	revKey := *snap
	revKey.RevokedAPIKeyIDs = []int64{claims.APIKeyID}
	require.ErrorIs(t, revKey.IsAuthorized(got, now.Add(5*time.Second)), ErrAPIKeyRevoked)

	// Stale CageEpoch rejected.
	bumpedCage := *snap
	bumpedCage.CageMinEpochs = map[int64]int64{88: 4}
	require.ErrorIs(t, bumpedCage.IsAuthorized(got, now.Add(5*time.Second)), ErrCageEpochStale)

	// Node HTTP request signing round-trip.
	body := []byte(`{"status":"active"}`)
	sig, err := SignNodeRequest(priv, 20, "POST", "/api/v1/internal/edge/heartbeat", now.Unix(), body)
	require.NoError(t, err)
	require.NoError(t, VerifyNodeRequest(pub, 20, "POST", "/api/v1/internal/edge/heartbeat", now.Unix(), body, sig, now.Add(5*time.Second)))
	require.ErrorIs(t, VerifyNodeRequest(pub, 20, "POST", "/api/v1/internal/edge/heartbeat", now.Unix(), []byte("tampered"), sig, now.Add(5*time.Second)), ErrNodeAuthInvalid)
	require.ErrorIs(t, VerifyNodeRequest(pub, 20, "POST", "/api/v1/internal/edge/heartbeat", now.Unix(), body, sig, now.Add(45*time.Second)), ErrNodeAuthInvalid)
}

func TestBHE1AttestationAndAntiReplay(t *testing.T) {
	pub, priv := genKeyPair(t)
	now := time.Unix(1_700_000_100, 0)
	guard := NewNonceGuard(30*time.Second, 90*time.Second, 1024)
	lookup := func(nodeID int64) (ed25519.PublicKey, error) {
		if nodeID == 7 {
			return pub, nil
		}
		return nil, errors.New("not found")
	}

	// IPv4 frame + WrapConn/AcceptAttestedConn over net.Pipe.
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()

	clientIP := netip.MustParseAddr("198.51.100.42")
	errCh := make(chan error, 1)
	go func() {
		ac, err := WrapConn(c1, priv, 7, clientIP, now)
		if err != nil {
			errCh <- err
			return
		}
		_, err = ac.Write([]byte("hello-central"))
		errCh <- err
	}()

	srvConn, err := AcceptAttestedConn(c2, lookup, guard, 2*time.Second, now.Add(2*time.Second))
	require.NoError(t, err)
	require.Equal(t, clientIP, srvConn.Attestation().ClientIP)
	require.Equal(t, int64(7), srvConn.Attestation().EntryNodeID)

	payload := make([]byte, len("hello-central"))
	_, err = io.ReadFull(srvConn, payload)
	require.NoError(t, err)
	require.Equal(t, "hello-central", string(payload))
	require.NoError(t, <-errCh)

	// IPv6 frame + exact replay rejection.
	v6IP := netip.MustParseAddr("2001:db8::99")
	rawV6, _, err := EncodeBHE1(priv, 7, v6IP, now)
	require.NoError(t, err)
	require.Equal(t, 118, len(rawV6))

	att, err := ReadAndVerifyPreface(bytes.NewReader(rawV6), lookup, guard, now)
	require.NoError(t, err)
	require.Equal(t, v6IP, att.ClientIP)

	// Replaying the exact same frame MUST fail with ErrBHE1Replay!
	_, err = ReadAndVerifyPreface(bytes.NewReader(rawV6), lookup, guard, now.Add(time.Second))
	require.ErrorIs(t, err, ErrBHE1Replay)

	// Clock skew > 30s rejected.
	rawSkew, _, err := EncodeBHE1(priv, 7, clientIP, now.Add(-35*time.Second))
	require.NoError(t, err)
	_, err = ReadAndVerifyPreface(bytes.NewReader(rawSkew), lookup, guard, now)
	require.ErrorIs(t, err, ErrBHE1ClockSkew)

	// Tampered byte rejected before nonce pollution.
	rawTampered, _, err := EncodeBHE1(priv, 7, clientIP, now)
	require.NoError(t, err)
	rawTampered[6] ^= 0xFF
	_, err = ReadAndVerifyPreface(bytes.NewReader(rawTampered), lookup, guard, now)
	require.ErrorIs(t, err, ErrBHE1BadSignature)

	// Unknown entry node rejected.
	rawUnknown, _, err := EncodeBHE1(priv, 999, clientIP, now)
	require.NoError(t, err)
	_, err = ReadAndVerifyPreface(bytes.NewReader(rawUnknown), lookup, guard, now)
	require.ErrorIs(t, err, ErrBHE1UnknownNode)
}

func TestReverseTunnelGenerationFencingAndBidirectionalH2(t *testing.T) {
	pub, priv := genKeyPair(t)
	guard := NewNonceGuard(30*time.Second, 90*time.Second, 1024)
	lookup := func(nodeID int64) (ed25519.PublicKey, error) {
		if nodeID == 55 {
			return pub, nil
		}
		return nil, errors.New("unknown")
	}

	var onlineEvents atomic.Int32
	reg := NewReverseTunnelRegistry(func(nodeID int64, online bool, gen uint64) {
		if online {
			onlineEvents.Add(1)
		}
	})
	defer reg.CloseAll()

	startReverseLanding := func(gen uint64, replyTag string) (net.Conn, <-chan struct{}, error) {
		hubConn, landingConn := net.Pipe()
		// Handshake BRT1 from landing -> hub.
		go func() {
			_ = WriteReverseTunnelReg(landingConn, priv, 55, gen, time.Now())
			h2Srv := &http2.Server{}
			h2Srv.ServeConn(landingConn, &http2.ServeConnOpts{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Gen-Tag", replyTag)
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("pong:" + replyTag))
				}),
			})
		}()
		parsed, err := ReadAndVerifyReverseTunnelReg(hubConn, lookup, guard, time.Now())
		if err != nil {
			_ = hubConn.Close()
			return nil, nil, err
		}
		done, err := reg.RegisterReverseTunnel(parsed.NodeID, parsed.Generation, hubConn)
		if err != nil {
			return nil, nil, err
		}
		return landingConn, done, nil
	}

	// Register generation 2.
	lConn2, done2, err := startReverseLanding(2, "gen-2")
	require.NoError(t, err)
	defer func() { _ = lConn2.Close() }()
	require.True(t, reg.HasLiveTunnel(55))
	require.Equal(t, uint64(2), reg.ActiveGeneration(55))

	req, _ := http.NewRequest(http.MethodPost, "http://node-55.edge.internal/edge/v1/execute", nil)
	resp, err := reg.RoundTrip(55, req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, "pong:gen-2", string(body))

	// Stale generation 1 MUST be rejected without disturbing generation 2!
	_, _, err = startReverseLanding(1, "gen-1-stale")
	require.ErrorIs(t, err, ErrStaleGeneration)
	require.Equal(t, uint64(2), reg.ActiveGeneration(55))

	// Newer generation 3 MUST immediately evict generation 2!
	lConn3, done3, err := startReverseLanding(3, "gen-3")
	require.NoError(t, err)
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("generation 2 was not evicted immediately")
	}
	require.Equal(t, uint64(3), reg.ActiveGeneration(55))

	resp, err = reg.RoundTrip(55, req)
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, "pong:gen-3", string(body))

	// Closing landing side MUST withdraw route automatically.
	_ = lConn3.Close()
	select {
	case <-done3:
	case <-time.After(2 * time.Second):
		t.Fatal("generation 3 route was not withdrawn on disconnect")
	}
	require.False(t, reg.HasLiveTunnel(55))
	_, err = reg.RoundTrip(55, req)
	require.ErrorIs(t, err, ErrReverseTunnelUnavailable)
}

func TestGrantWALPreDebitCrashRecoveryAndExactCutoff(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "grant.wal")
	now := time.Now()

	wal, err := OpenGrantWAL(walPath)
	require.NoError(t, err)

	// Add 1000-byte slice; duplicate slice_id MUST be ignored!
	require.NoError(t, wal.AddSlice("slice-1", 42, 1000, now.Add(time.Hour)))
	require.NoError(t, wal.AddSlice("slice-1", 42, 1000, now.Add(time.Hour)))
	require.Equal(t, int64(1000), wal.Remaining(42))

	// Pre-debit 400 bytes, then simulate an ungraceful crash (close without refunding/settling).
	debitID, err := wal.PreDebit(42, 400, now)
	require.NoError(t, err)
	require.NotEmpty(t, debitID)
	require.Equal(t, int64(600), wal.Remaining(42))
	require.NoError(t, wal.Close())

	// Append a half-written corrupted line to simulate mid-write power loss.
	f, err := os.OpenFile(walPath, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	_, err = f.WriteString(`{"op":"pre_debit","grant_id":42,"by`)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Reopen WAL after crash: uncertain 400B chunk MUST remain conservatively charged (600B left).
	wal2, err := OpenGrantWAL(walPath)
	require.NoError(t, err)
	defer func() { _ = wal2.Close() }()
	require.Equal(t, int64(600), wal2.Remaining(42))

	// Replaying slice-1 after restart still cannot double-spend!
	require.NoError(t, wal2.AddSlice("slice-1", 42, 1000, now.Add(time.Hour)))
	require.Equal(t, int64(600), wal2.Remaining(42))

	// PreDebitUpTo 800B stops at exact remaining 600B!
	admitted, _, err := wal2.PreDebitUpTo(42, 800, now)
	require.NoError(t, err)
	require.Equal(t, int64(600), admitted)
	require.Equal(t, int64(0), wal2.Remaining(42))

	// Next byte fails closed with ErrGrantSliceExhausted!
	_, _, err = wal2.PreDebitUpTo(42, 1, now)
	require.ErrorIs(t, err, ErrGrantSliceExhausted)

	// Compact & reopen preserves seen slices and remaining=0.
	require.NoError(t, wal2.Compact())
	require.NoError(t, wal2.Close())

	wal3, err := OpenGrantWAL(walPath)
	require.NoError(t, err)
	defer func() { _ = wal3.Close() }()
	require.Equal(t, int64(0), wal3.Remaining(42))
	require.NoError(t, wal3.AddSlice("slice-1", 42, 1000, now.Add(time.Hour)))
	require.Equal(t, int64(0), wal3.Remaining(42))
}

func TestOutboxWALPersistenceFlushAndCompaction(t *testing.T) {
	dir := t.TempDir()
	outboxPath := filepath.Join(dir, "outbox.wal")

	ob, err := OpenOutboxWAL(outboxPath)
	require.NoError(t, err)

	require.NoError(t, ob.Append(UsageReceipt{ReceiptID: "r-1", NodeID: 20, GrantID: 9, IngressBytes: 100, EgressBytes: 250, RequestCount: 1, StatusCode: 200}))
	require.NoError(t, ob.Append(UsageReceipt{ReceiptID: "r-2", NodeID: 20, GrantID: 9, IngressBytes: 50, EgressBytes: 75, RequestCount: 1, StatusCode: 200}))
	require.NoError(t, ob.Close())

	// Reopen after crash: both receipts survive durably.
	ob2, err := OpenOutboxWAL(outboxPath)
	require.NoError(t, err)
	defer func() { _ = ob2.Close() }()
	require.Equal(t, 2, ob2.PendingCount())

	// First flush fails partway (ACKs only r-1).
	n, err := ob2.FlushOnce(context.Background(), 10, func(ctx context.Context, batch []UsageReceipt) ([]string, error) {
		require.Len(t, batch, 2)
		return []string{"r-1"}, errors.New("central temporary error")
	})
	require.Error(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, 1, ob2.PendingCount())

	// Second flush delivers r-2 and compacts WAL.
	var delivered []string
	n, err = ob2.FlushOnce(context.Background(), 10, func(ctx context.Context, batch []UsageReceipt) ([]string, error) {
		for _, r := range batch {
			delivered = append(delivered, r.ReceiptID)
		}
		return delivered, nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, []string{"r-2"}, delivered)
	require.Equal(t, 0, ob2.PendingCount())

	// Reopen after compaction confirms empty pending queue.
	require.NoError(t, ob2.Close())
	ob3, err := OpenOutboxWAL(outboxPath)
	require.NoError(t, err)
	defer func() { _ = ob3.Close() }()
	require.Equal(t, 0, ob3.PendingCount())
}
