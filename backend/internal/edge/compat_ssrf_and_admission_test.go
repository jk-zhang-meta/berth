package edge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/stretchr/testify/require"
)

type staticResolver struct {
	records map[string][]string
}

func (r staticResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips := r.records[host]
	out := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func TestCompatSSRFGuard_AllowlistIPv4AndRedirects(t *testing.T) {
	resolver := staticResolver{
		records: map[string][]string{
			"api.openai.com":    {"104.18.7.192"},
			"api.anthropic.com": {"169.254.169.254", "10.0.0.5", "2001:db8::1"}, // poisoned DNS!
			"api.x.ai":          {"127.0.0.1"},
			"evil.internal":     {"192.168.1.10"},
		},
	}
	guard := NewCompatSSRFGuard(nil, nil, resolver)

	// 1. Official provider HTTPS URL passes ValidateURL and resolves to public IPv4.
	host, port, isTest, err := guard.ValidateURL("https://api.openai.com/v1/responses")
	require.NoError(t, err)
	require.Equal(t, "api.openai.com", host)
	require.Equal(t, "443", port)
	require.False(t, isTest)

	ip, err := guard.ResolveAndValidateIPv4(context.Background(), host, port)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("104.18.7.192"), ip)

	// 2. Non-https scheme, non-allowlisted host/port, and userinfo MUST be blocked.
	_, _, _, err = guard.ValidateURL("http://api.openai.com/v1/responses")
	require.ErrorIs(t, err, ErrSSRFSchemeBlocked)

	_, _, _, err = guard.ValidateURL("https://api.openai.com:8443/v1/responses")
	require.ErrorIs(t, err, ErrSSRFAuthorityBlocked)

	_, _, _, err = guard.ValidateURL("https://evil.internal/v1/responses")
	require.ErrorIs(t, err, ErrSSRFAuthorityBlocked)

	_, _, _, err = guard.ValidateURL("https://user:pass@api.openai.com/v1/responses")
	require.ErrorIs(t, err, ErrSSRFUserInfoBlocked)

	// 3. DNS returning IMDS/RFC1918/IPv6/loopback MUST fail closed!
	_, err = guard.ResolveAndValidateIPv4(context.Background(), "api.anthropic.com", "443")
	require.ErrorIs(t, err, ErrSSRFPrivateIPBlocked)

	_, err = guard.ResolveAndValidateIPv4(context.Background(), "api.x.ai", "443")
	require.ErrorIs(t, err, ErrSSRFPrivateIPBlocked)

	// 4. IsPublicIPv4 rejects private, loopback, IMDS, CGNAT, and IPv6.
	for _, blocked := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1",
		"169.254.169.254", "100.64.0.1", "224.0.0.1", "::1", "2606:4700::1",
	} {
		require.False(t, IsPublicIPv4(netip.MustParseAddr(blocked)), "expected blocked: %s", blocked)
	}
	require.True(t, IsPublicIPv4(netip.MustParseAddr("1.1.1.1")))

	// 5. Redirect from test-allowlisted server to disallowed internal URL MUST be blocked!
	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirSrv.Close()

	testGuard := NewCompatSSRFGuard(nil, []string{redirSrv.Listener.Addr().String()}, nil)
	client := testGuard.NewSafeHTTPClient(nil)
	_, err = client.Get(redirSrv.URL + "/start")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrSSRFSchemeBlocked)
}

func TestAdmissionGate_ConcurrencyRPMAndLiveStreamRevocation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	curTime := time.Unix(1_700_001_000, 0)
	wal, err := edgeproto.OpenGrantWAL(filepath.Join(t.TempDir(), "grant.wal"))
	require.NoError(t, err)
	defer func() { _ = wal.Close() }()
	require.NoError(t, wal.AddSlice("s1", 7, 10000, curTime.Add(time.Hour)))

	gate := NewAdmissionGate(pub, wal, nil, 4096, 1024)
	gate.SetNowFunc(func() time.Time { return curTime })
	gate.SetGrantLimits(7, GrantLimits{MaxConcurrency: 1, MaxRPM: 2})

	leaseClaims := edgeproto.SessionLeaseClaims{
		LeaseID:       "lease-abc",
		JTI:           "jti-abc",
		UserID:        42,
		APIKeyID:      101,
		AccountID:     501,
		CageID:        88,
		CageEpoch:     2,
		GrantID:       7,
		LandingNodeID: 20,
		RevSeq:        1,
		IssuedAt:      curTime.Unix(),
		ExpiresAt:     curTime.Add(10 * time.Minute).Unix(),
	}
	tok, err := edgeproto.SignLease(priv, "", leaseClaims)
	require.NoError(t, err)

	// Missing snapshot MUST fail closed!
	_, err = gate.Admit(context.Background(), tok, 20, nil)
	require.ErrorIs(t, err, edgeproto.ErrRevocationSnapshotMissing)

	// Install fresh snapshot seq=1 valid for 60s.
	snap1 := &edgeproto.RevocationSnapshot{
		Seq:           1,
		IssuedAt:      curTime.Unix(),
		ValidUntil:    curTime.Add(60 * time.Second).Unix(),
		CageMinEpochs: map[int64]int64{88: 2},
	}
	require.NoError(t, edgeproto.SignRevocationSnapshot(priv, "", snap1))
	require.NoError(t, gate.UpdateSnapshot(snap1))

	// Wrong landing_node_id rejected.
	_, err = gate.Admit(context.Background(), tok, 99, nil)
	require.ErrorIs(t, err, ErrLandingNodeMismatch)

	// Admit stream #1 cleanly.
	var revokedCount atomic.Int32
	s1, err := gate.Admit(context.Background(), tok, 20, func(error) {
		revokedCount.Add(1)
	})
	require.NoError(t, err)
	require.Equal(t, 1, gate.ActiveStreamCount())

	// Second concurrent stream rejected by MaxConcurrency=1.
	_, err = gate.Admit(context.Background(), tok, 20, nil)
	require.ErrorIs(t, err, ErrGrantConcurrencyLimit)

	// Bump CageMinEpoch to 3 in snapshot seq=2 -> s1 MUST be cancelled & onRevoke fired immediately!
	snap2 := &edgeproto.RevocationSnapshot{
		Seq:           2,
		IssuedAt:      curTime.Unix(),
		ValidUntil:    curTime.Add(60 * time.Second).Unix(),
		CageMinEpochs: map[int64]int64{88: 3},
	}
	require.NoError(t, edgeproto.SignRevocationSnapshot(priv, "", snap2))
	require.NoError(t, gate.UpdateSnapshot(snap2))
	require.Equal(t, int32(1), revokedCount.Load())
	require.Error(t, s1.Context().Err())
	s1.Release()

	// Mint lease at CageEpoch=3; test stale snapshot watchdog cancellation.
	leaseClaims.CageEpoch = 3
	leaseClaims.RevSeq = 2
	tok3, err := edgeproto.SignLease(priv, "", leaseClaims)
	require.NoError(t, err)
	s2, err := gate.Admit(context.Background(), tok3, 20, func(error) {
		revokedCount.Add(1)
	})
	require.NoError(t, err)
	defer s2.Release()

	// Advance clock past snapshot ValidUntil -> SweepFreshness closes active stream fail-closed!
	curTime = curTime.Add(65 * time.Second)
	closed := gate.SweepFreshness()
	require.Equal(t, 1, closed)
	require.Equal(t, int32(2), revokedCount.Load())
	require.Error(t, s2.Context().Err())
}
