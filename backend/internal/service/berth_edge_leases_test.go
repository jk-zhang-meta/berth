package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/stretchr/testify/require"
)

func TestBerthEdgeLeaseService_MintRenewRevokeFailoverAndStrictEgress(t *testing.T) {
	ctx := context.Background()

	// Verify signing key generation, persistence, and reload.
	keyPath := filepath.Join(t.TempDir(), "edge_signing.key")
	pub1, priv1, kid1, err := LoadOrGenerateEdgeSigningKey("", keyPath)
	require.NoError(t, err)
	pub2, _, kid2, err := LoadOrGenerateEdgeSigningKey("", keyPath)
	require.NoError(t, err)
	require.Equal(t, pub1, pub2)
	require.Equal(t, kid1, kid2)

	revSeq := int64(1)
	zoneStore := NewMemoryZoneStore(true)
	zoneSvc := NewBerthZoneServiceWithStore(zoneStore)
	grantStore := NewMemoryLandingGrantStore(zoneStore, &revSeq)
	grantSvc := NewBerthLandingGrantServiceWithStore(grantStore)
	leaseStore := NewMemoryEdgeLeaseStore(&revSeq)
	leaseSvc := NewBerthEdgeLeaseServiceWithStore(leaseStore, zoneSvc, grantSvc, pub1, priv1, kid1)

	zones, err := zoneSvc.ListZones(ctx)
	require.NoError(t, err)
	zoneBySlug := map[string]int64{}
	for _, z := range zones {
		zoneBySlug[z.Slug] = z.ID
	}

	relayCN, err := zoneSvc.CreateNode(ctx, EdgeNode{Name: "gz-relay", ZoneID: zoneBySlug["cn_mainland"], Roles: []string{EdgeRoleIngressRelay}, TunnelAddr: "10.0.1.1:9443", Status: EdgeNodeStatusActive})
	require.NoError(t, err)
	landingJP1, err := zoneSvc.CreateNode(ctx, EdgeNode{Name: "tokyo-1", ZoneID: zoneBySlug["overseas"], Roles: []string{EdgeRoleLanding}, TunnelAddr: "10.0.2.1:9443", Status: EdgeNodeStatusActive, ExitCountryCode: "JP", ExitTimezone: "Asia/Tokyo", ExitLocale: "ja_JP.UTF-8"})
	require.NoError(t, err)
	landingJP2, err := zoneSvc.CreateNode(ctx, EdgeNode{Name: "tokyo-2", ZoneID: zoneBySlug["overseas"], Roles: []string{EdgeRoleLanding}, TunnelAddr: "10.0.2.2:9443", Status: EdgeNodeStatusActive, ExitCountryCode: "JP", ExitTimezone: "Asia/Tokyo", ExitLocale: "ja_JP.UTF-8"})
	require.NoError(t, err)
	landingUS, err := zoneSvc.CreateNode(ctx, EdgeNode{Name: "houston-1", ZoneID: zoneBySlug["overseas"], Roles: []string{EdgeRoleLanding}, TunnelAddr: "10.0.3.1:9443", Status: EdgeNodeStatusActive, ExitCountryCode: "US", ExitTimezone: "America/Chicago", ExitLocale: "en_US.UTF-8"})
	require.NoError(t, err)

	_, err = zoneSvc.CreateLink(ctx, ServerLink{SrcNodeID: relayCN.ID, DstNodeID: landingJP1.ID, Direction: LinkDirectionOneWay, LinkClass: LinkClassIPLC, Weight: 10, RTTMs: 30, Enabled: true})
	require.NoError(t, err)
	_, err = zoneSvc.CreateLink(ctx, ServerLink{SrcNodeID: relayCN.ID, DstNodeID: landingJP2.ID, Direction: LinkDirectionOneWay, LinkClass: LinkClassIPLC, Weight: 10, RTTMs: 35, Enabled: true})
	require.NoError(t, err)
	_, err = zoneSvc.CreateLink(ctx, ServerLink{SrcNodeID: relayCN.ID, DstNodeID: landingUS.ID, Direction: LinkDirectionOneWay, LinkClass: LinkClassDirect, Weight: 20, RTTMs: 120, Enabled: true})
	require.NoError(t, err)

	grant, err := grantSvc.CreateGrant(ctx, CreateLandingGrantInput{
		NodeID:        landingJP1.ID,
		GranteeUserID: 42,
		MaxBytes:      1024 * 1024,
	})
	require.NoError(t, err)

	// Mint lease for CN user targeting tokyo-1.
	minted, err := leaseSvc.MintLease(ctx, MintLeaseInput{
		UserID:          42,
		APIKeyID:        77,
		WorkSessionID:   1001,
		Platform:        "openai",
		AccountID:       501,
		CageID:          88,
		CageEpoch:       2,
		GrantID:         grant.ID,
		LandingNodeID:   landingJP1.ID,
		PeerCountryCode: "CN",
	})
	require.NoError(t, err)
	require.Equal(t, "cn_mainland", minted.ClientZone)
	require.Equal(t, relayCN.ID, minted.IngressNode.ID)
	require.Equal(t, "Asia/Tokyo", minted.Cage.Timezone)
	require.Len(t, minted.RouteChain, 2)

	// Verify signed Ed25519 lease token & signed RevocationSnapshot!
	claims, err := edgeproto.VerifyLease(pub1, minted.Token, time.Now())
	require.NoError(t, err)
	require.Equal(t, minted.LeaseID, claims.LeaseID)
	require.Equal(t, int64(88), claims.CageID)
	require.Equal(t, int64(2), claims.CageEpoch)

	snap, err := leaseSvc.BuildRevocationSnapshot(ctx, time.Now())
	require.NoError(t, err)
	require.NoError(t, edgeproto.VerifyAndAuthorize(pub1, snap, claims, time.Now()))

	// Renew increments lease_epoch.
	renewed, err := leaseSvc.RenewLease(ctx, 42, minted.LeaseID)
	require.NoError(t, err)
	require.Equal(t, int64(2), renewed.LeaseEpoch)

	// Failover with a same-cohort JP candidate returns Action="switched" + fresh signed lease!
	foSame, err := leaseSvc.CoordinateFailover(ctx, EdgeFailoverRequest{
		LeaseID:         minted.LeaseID,
		FailedAccountID: 501,
		StatusCode:      429,
		Candidates: []FailoverCandidate{
			{AccountID: 502, CageID: 89, CageEpoch: 1, LandingNodeID: landingJP2.ID, CohortTimezone: "Asia/Tokyo", CohortCountryCode: "JP", CohortLocale: "ja_JP.UTF-8"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "switched", foSame.Action)
	require.NotNil(t, foSame.Lease)
	require.Equal(t, int64(502), foSame.Lease.AccountID)

	// Failover with ONLY cross-cohort US candidate MUST NOT switch silently; returns cage_rebind_required!
	foCross, err := leaseSvc.CoordinateFailover(ctx, EdgeFailoverRequest{
		LeaseID:         minted.LeaseID,
		FailedAccountID: 501,
		StatusCode:      529,
		Candidates: []FailoverCandidate{
			{AccountID: 601, CageID: 90, CageEpoch: 1, LandingNodeID: landingUS.ID, CohortTimezone: "America/Chicago", CohortCountryCode: "US", CohortLocale: "en_US.UTF-8"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, "cage_rebind_required", foCross.Action)
	require.Nil(t, foCross.Lease)
	require.NotNil(t, foCross.RecommendedCohort)
	require.Equal(t, "America/Chicago", foCross.RecommendedCohort.CohortTimezone)

	// Revoke lease -> next RevocationSnapshot rejects original lease claims immediately!
	newSeq, err := leaseSvc.RevokeLease(ctx, 42, false, minted.LeaseID)
	require.NoError(t, err)
	require.Greater(t, newSeq, int64(1))
	snapAfter, err := leaseSvc.BuildRevocationSnapshot(ctx, time.Now())
	require.NoError(t, err)
	require.ErrorIs(t, edgeproto.VerifyAndAuthorize(pub1, snapAfter, claims, time.Now()), edgeproto.ErrLeaseRevoked)

	// EDGE_DATA_PLANE_STRICT=true blocks direct AI provider egress from Central.
	leaseSvc.SetEdgeDataPlaneStrict(true)
	require.ErrorIs(t, leaseSvc.AssertDirectProviderEgressAllowed(), ErrCentralDirectEgressBlocked)

	// OAuth task dispatch to Landing node.
	task := leaseSvc.EnqueueOAuthTask(EdgeOAuthTask{
		NodeID:    landingJP1.ID,
		AccountID: 501,
		Kind:      "token_refresh",
		TargetURL: "https://auth.openai.com/oauth/token",
		Method:    "POST",
	})
	pending := leaseSvc.ListPendingOAuthTasks(landingJP1.ID)
	require.Len(t, pending, 1)
	require.Equal(t, task.TaskID, pending[0].TaskID)
	doneTask, err := leaseSvc.CompleteOAuthTask(landingJP1.ID, task.TaskID, 200, `{"ok":true}`, "")
	require.NoError(t, err)
	require.Equal(t, "completed", doneTask.Status)
	require.Empty(t, leaseSvc.ListPendingOAuthTasks(landingJP1.ID))
}

type failoverAutoStore struct {
	*MemoryEdgeLeaseStore
	candidates []FailoverCandidate
}

func (f *failoverAutoStore) ListAuthorizedFailoverCandidates(_ context.Context, _, _ int64, _ string, excludeAccountID int64) ([]FailoverCandidate, error) {
	var out []FailoverCandidate
	for _, c := range f.candidates {
		if c.AccountID != excludeAccountID {
			out = append(out, c)
		}
	}
	return out, nil
}

func TestBerthEdgeLeaseService_CoordinateFailoverAutoResolvesCandidatesFromStore(t *testing.T) {
	ctx := context.Background()
	pub, priv, kid, err := LoadOrGenerateEdgeSigningKey("", filepath.Join(t.TempDir(), "k.pem"))
	require.NoError(t, err)

	revSeq := int64(1)
	zoneStore := NewMemoryZoneStore(true)
	zoneSvc := NewBerthZoneServiceWithStore(zoneStore)
	grantStore := NewMemoryLandingGrantStore(zoneStore, &revSeq)
	grantSvc := NewBerthLandingGrantServiceWithStore(grantStore)
	autoStore := &failoverAutoStore{MemoryEdgeLeaseStore: NewMemoryEdgeLeaseStore(&revSeq)}
	leaseSvc := NewBerthEdgeLeaseServiceWithStore(autoStore, zoneSvc, grantSvc, pub, priv, kid)

	zones, err := zoneSvc.ListZones(ctx)
	require.NoError(t, err)
	zoneBySlug := map[string]int64{}
	for _, z := range zones {
		zoneBySlug[z.Slug] = z.ID
	}
	relay, err := zoneSvc.CreateNode(ctx, EdgeNode{Name: "relay-1", ZoneID: zoneBySlug["overseas"], Roles: []string{EdgeRoleIngressRelay}, TunnelAddr: "10.1.0.1:9443", Status: EdgeNodeStatusActive})
	require.NoError(t, err)
	sg1, err := zoneSvc.CreateNode(ctx, EdgeNode{Name: "sg-1", ZoneID: zoneBySlug["overseas"], Roles: []string{EdgeRoleLanding}, TunnelAddr: "10.1.1.1:9443", Status: EdgeNodeStatusActive, ExitCountryCode: "SG", ExitTimezone: "Asia/Singapore", ExitLocale: "en_SG.UTF-8"})
	require.NoError(t, err)
	sg2, err := zoneSvc.CreateNode(ctx, EdgeNode{Name: "sg-2", ZoneID: zoneBySlug["overseas"], Roles: []string{EdgeRoleLanding}, TunnelAddr: "10.1.1.2:9443", Status: EdgeNodeStatusActive, ExitCountryCode: "SG", ExitTimezone: "Asia/Singapore", ExitLocale: "en_SG.UTF-8"})
	require.NoError(t, err)
	us1, err := zoneSvc.CreateNode(ctx, EdgeNode{Name: "us-1", ZoneID: zoneBySlug["overseas"], Roles: []string{EdgeRoleLanding}, TunnelAddr: "10.1.2.1:9443", Status: EdgeNodeStatusActive, ExitCountryCode: "US", ExitTimezone: "America/Los_Angeles", ExitLocale: "en_US.UTF-8"})
	require.NoError(t, err)
	for _, dst := range []*EdgeNode{sg1, sg2, us1} {
		_, err = zoneSvc.CreateLink(ctx, ServerLink{SrcNodeID: relay.ID, DstNodeID: dst.ID, Direction: LinkDirectionOneWay, LinkClass: LinkClassDirect, Weight: 10, RTTMs: 25, Enabled: true})
		require.NoError(t, err)
	}

	gSG1, err := grantSvc.CreateGrant(ctx, CreateLandingGrantInput{NodeID: sg1.ID, GranteeUserID: 7, MaxBytes: 1024 * 1024})
	require.NoError(t, err)
	gSG2, err := grantSvc.CreateGrant(ctx, CreateLandingGrantInput{NodeID: sg2.ID, GranteeUserID: 7, MaxBytes: 1024 * 1024})
	require.NoError(t, err)
	gUS1, err := grantSvc.CreateGrant(ctx, CreateLandingGrantInput{NodeID: us1.ID, GranteeUserID: 7, MaxBytes: 1024 * 1024})
	require.NoError(t, err)

	minted, err := leaseSvc.MintLease(ctx, MintLeaseInput{
		UserID: 7, APIKeyID: 9, WorkSessionID: 101, Platform: "anthropic",
		AccountID: 23, CageID: 23, CageEpoch: 1, GrantID: gSG1.ID, LandingNodeID: sg1.ID,
	})
	require.NoError(t, err)

	// 1. Edge sends empty Candidates -> Central auto-discovers same-cohort sg2 account #29 -> Action="switched"!
	autoStore.candidates = []FailoverCandidate{
		{AccountID: 24, CageID: 24, CageEpoch: 1, GrantID: gUS1.ID, LandingNodeID: us1.ID, CohortTimezone: "America/Los_Angeles", CohortCountryCode: "US", CohortLocale: "en_US.UTF-8"},
		{AccountID: 29, CageID: 29, CageEpoch: 1, GrantID: gSG2.ID, LandingNodeID: sg2.ID, CohortTimezone: "Asia/Singapore", CohortCountryCode: "SG", CohortLocale: "en_SG.UTF-8"},
	}
	foSame, err := leaseSvc.CoordinateFailover(ctx, EdgeFailoverRequest{
		LeaseID: minted.LeaseID, FailedAccountID: 23, StatusCode: 429,
	})
	require.NoError(t, err)
	require.Equal(t, "switched", foSame.Action)
	require.NotNil(t, foSame.Lease)
	require.Equal(t, int64(29), foSame.Lease.AccountID)

	// 2. When only cross-cohort US account #24 remains -> returns cage_rebind_required WITH RecommendedCohort!
	autoStore.candidates = []FailoverCandidate{
		{AccountID: 24, CageID: 24, CageEpoch: 1, GrantID: gUS1.ID, LandingNodeID: us1.ID, CohortTimezone: "America/Los_Angeles", CohortCountryCode: "US", CohortLocale: "en_US.UTF-8"},
	}
	foCross, err := leaseSvc.CoordinateFailover(ctx, EdgeFailoverRequest{
		LeaseID: minted.LeaseID, FailedAccountID: 23, StatusCode: 429,
	})
	require.NoError(t, err)
	require.Equal(t, "cage_rebind_required", foCross.Action)
	require.Nil(t, foCross.Lease)
	require.NotNil(t, foCross.RecommendedCohort)
	require.Equal(t, int64(24), foCross.RecommendedCohort.AccountID)
	require.Equal(t, "America/Los_Angeles", foCross.RecommendedCohort.CohortTimezone)
}
