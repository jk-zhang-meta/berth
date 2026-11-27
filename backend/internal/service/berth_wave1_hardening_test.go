package service

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestWave1_ReservedEdgeInternalHostAndUTF8Truncation(t *testing.T) {
	require.True(t, IsReservedEdgeInternalHost("node-9.edge.internal"))
	require.True(t, IsReservedEdgeInternalHost("NODE-9.EDGE.INTERNAL."))
	require.True(t, IsReservedEdgeInternalHost("edge.internal"))
	require.False(t, IsReservedEdgeInternalHost("myedge.internal.example.com"))
	require.False(t, IsReservedEdgeInternalHost("1.2.3.4"))

	// Long Chinese node name must fit within 100 UTF-8 bytes, stay valid UTF-8, and keep -u<uid>.
	longCN := strings.Repeat("休斯顿家宽落地节点", 8) // 72 runes = 216 bytes
	formatted := formatEdgeLandingProxyName(longCN, 42)
	require.LessOrEqual(t, len(formatted), 100)
	require.True(t, utf8.ValidString(formatted))
	require.True(t, strings.HasPrefix(formatted, "edge-landing-"))
	require.True(t, strings.HasSuffix(formatted, "-u42"))

	// TruncateUTF8Bytes never splits multi-byte runes.
	trunc := TruncateUTF8Bytes("你好世界abc", 5)
	require.True(t, utf8.ValidString(trunc))
	require.LessOrEqual(t, len(trunc), 5)
	require.Equal(t, "你", trunc)
}

func TestWave1_ZoneHeartbeatPreservesDrainingAndSuspended(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryZoneStore(true)
	svc := NewBerthZoneServiceWithStore(store)
	zones, err := svc.ListZones(ctx)
	require.NoError(t, err)

	n, err := svc.CreateNode(ctx, EdgeNode{
		Name:   "houston(drain-test)",
		ZoneID: zones[0].ID,
		Roles:  []string{EdgeRoleLanding},
		Status: EdgeNodeStatusDraining,
		Meta:   []byte(`{"agent_version":"0.2.25"}`),
	})
	require.NoError(t, err)

	// Heartbeat reporting active must NOT clobber draining status.
	hb, err := svc.RecordHeartbeat(ctx, n.ID, EdgeHeartbeatUpdate{Status: EdgeNodeStatusActive}, time.Now())
	require.NoError(t, err)
	require.Equal(t, EdgeNodeStatusDraining, hb.Status)

	// Duplicate node rename must return conflict and UpdateNode preserves meta when omitted.
	_, err = svc.CreateNode(ctx, EdgeNode{
		Name:   "houston(existing)",
		ZoneID: zones[0].ID,
		Roles:  []string{EdgeRoleLanding},
		Status: EdgeNodeStatusActive,
	})
	require.NoError(t, err)
	_, err = svc.UpdateNode(ctx, EdgeNode{
		ID:     n.ID,
		Name:   "houston(existing)",
		ZoneID: zones[0].ID,
		Roles:  []string{EdgeRoleLanding},
		Status: EdgeNodeStatusDraining,
	})
	require.ErrorIs(t, err, ErrEdgeZoneConflict)

	updated, err := svc.UpdateNode(ctx, EdgeNode{
		ID:     n.ID,
		Name:   "houston(renamed)",
		ZoneID: zones[0].ID,
		Roles:  []string{EdgeRoleLanding},
		Status: EdgeNodeStatusDraining,
	})
	require.NoError(t, err)
	require.JSONEq(t, `{"agent_version":"0.2.25"}`, string(updated.Meta))
}

func TestWave1_ApproveGrantRequiresLandingRole(t *testing.T) {
	ctx := context.Background()
	revSeq := int64(1)
	zoneStore := NewMemoryZoneStore(true)
	grantSvc := NewBerthLandingGrantServiceWithStore(NewMemoryLandingGrantStore(zoneStore, &revSeq))
	zones, err := zoneStore.ListZones(ctx)
	require.NoError(t, err)

	// Create transit-only node (no landing role).
	transit, err := zoneStore.CreateNode(ctx, EdgeNode{
		Name:   "relay-only",
		ZoneID: zones[0].ID,
		Roles:  []string{EdgeRoleTransit},
		Status: EdgeNodeStatusActive,
	})
	require.NoError(t, err)

	// Create a pending grant for a node while it was landing, then remove landing role before approval.
	landing, err := zoneStore.CreateNode(ctx, EdgeNode{
		Name:   "landing-then-removed",
		ZoneID: zones[0].ID,
		Roles:  []string{EdgeRoleLanding},
		Status: EdgeNodeStatusActive,
	})
	require.NoError(t, err)
	pending, err := grantSvc.ApplyForLandingNode(ctx, ApplyLandingGrantInput{
		NodeID:        landing.ID,
		GranteeUserID: 7,
		RequestReason: "dev",
		MaxAccounts:   1,
	})
	require.NoError(t, err)
	landing.Roles = []string{EdgeRoleTransit}
	_, err = zoneStore.UpdateNode(ctx, *landing)
	require.NoError(t, err)

	maxAcc := 1
	_, err = grantSvc.ApproveGrant(ctx, ApproveLandingGrantInput{
		GrantID:     pending.ID,
		AdminID:     1,
		MaxAccounts: &maxAcc,
	})
	require.ErrorIs(t, err, ErrLandingGrantInvalid)

	// Direct CreateGrant on transit-only node is also rejected.
	_, err = grantSvc.CreateGrant(ctx, CreateLandingGrantInput{
		NodeID:        transit.ID,
		GranteeUserID: 7,
	})
	require.ErrorIs(t, err, ErrLandingGrantInvalid)
}

func TestWave1_LeaseSiblingKeyRedactionExpiryAndFailoverCallerCheck(t *testing.T) {
	ctx := context.Background()
	pub, priv, kid, err := LoadOrGenerateEdgeSigningKey("", filepath.Join(t.TempDir(), "k.pem"))
	require.NoError(t, err)

	revSeq := int64(1)
	zoneStore := NewMemoryZoneStore(true)
	zoneSvc := NewBerthZoneServiceWithStore(zoneStore)
	grantSvc := NewBerthLandingGrantServiceWithStore(NewMemoryLandingGrantStore(zoneStore, &revSeq))
	leaseStore := NewMemoryEdgeLeaseStore(&revSeq)
	leaseSvc := NewBerthEdgeLeaseServiceWithStore(leaseStore, zoneSvc, grantSvc, pub, priv, kid)

	zones, err := zoneSvc.ListZones(ctx)
	require.NoError(t, err)
	relay, err := zoneSvc.CreateNode(ctx, EdgeNode{
		Name:          "relay-hk",
		ZoneID:        zones[2].ID,
		Roles:         []string{EdgeRoleIngressRelay},
		PublicAddr:    "https://relay.example.com:19443",
		TunnelAddr:    "10.0.0.1:19443",
		ExitIP:        "198.51.100.1",
		PubkeyEd25519: "secret-pub-1",
		Status:        EdgeNodeStatusActive,
		Meta:          []byte(`{"internal_ip":"10.0.0.1"}`),
	})
	require.NoError(t, err)
	rogue, err := zoneSvc.CreateNode(ctx, EdgeNode{
		Name:   "rogue-node",
		ZoneID: zones[2].ID,
		Roles:  []string{EdgeRoleTransit},
		Status: EdgeNodeStatusActive,
	})
	require.NoError(t, err)
	landing, err := zoneSvc.CreateNode(ctx, EdgeNode{
		Name:            "tokyo-home",
		ZoneID:          zones[2].ID,
		Roles:           []string{EdgeRoleLanding},
		TunnelAddr:      "10.0.0.2:19443",
		ExitIP:          "203.0.113.99",
		ExitCountryCode: "JP",
		ExitTimezone:    "Asia/Tokyo",
		ExitLocale:      "ja_JP.UTF-8",
		PubkeyEd25519:   "secret-pub-2",
		Status:          EdgeNodeStatusActive,
		Meta:            []byte(`{"agent_version":"0.2.25"}`),
	})
	require.NoError(t, err)
	_, err = zoneSvc.CreateLink(ctx, ServerLink{
		SrcNodeID: relay.ID, DstNodeID: landing.ID,
		Direction: LinkDirectionOneWay, LinkClass: LinkClassDirect,
		Weight: 5, RTTMs: 10, Enabled: true,
	})
	require.NoError(t, err)

	shortExp := time.Now().Add(2 * time.Minute)
	grant, err := grantSvc.CreateGrant(ctx, CreateLandingGrantInput{
		NodeID: landing.ID, GranteeUserID: 42, MaxBytes: 1024 * 1024, ExpiresAt: &shortExp,
	})
	require.NoError(t, err)

	minted, err := leaseSvc.MintLease(ctx, MintLeaseInput{
		UserID: 42, APIKeyID: 101, Platform: "openai", AccountID: 501,
		CageID: 501, CageEpoch: 1, GrantID: grant.ID, LandingNodeID: landing.ID,
	})
	require.NoError(t, err)

	// S-1: Tenant lease response redacts sensitive node infrastructure fields and fixes AcceptLanguage.
	require.NotNil(t, minted.LandingNode)
	require.Empty(t, minted.LandingNode.ExitIP)
	require.Empty(t, minted.LandingNode.TunnelAddr)
	require.Empty(t, minted.LandingNode.PubkeyEd25519)
	require.Empty(t, minted.LandingNode.Meta)
	require.NotNil(t, minted.IngressNode)
	require.Equal(t, "https://relay.example.com:19443", minted.IngressNode.PublicAddr)
	require.Empty(t, minted.IngressNode.TunnelAddr)
	require.Empty(t, minted.IngressNode.ExitIP)
	require.Contains(t, minted.Cage.AcceptLanguage, "ja-JP")
	// Lease expiry capped at grant expiry.
	require.False(t, minted.ExpiresAt.After(shortExp.Add(time.Second)))

	// S-1: Sibling API key belonging to same user cannot renew or revoke another API key's lease.
	_, err = leaseSvc.RenewLeaseWithKey(ctx, 42, 202, minted.LeaseID)
	require.ErrorIs(t, err, ErrEdgeLeaseForbidden)
	_, err = leaseSvc.RevokeLeaseWithKey(ctx, 42, 202, false, minted.LeaseID)
	require.ErrorIs(t, err, ErrEdgeLeaseForbidden)

	// Same API key can renew.
	renewed, err := leaseSvc.RenewLeaseWithKey(ctx, 42, 101, minted.LeaseID)
	require.NoError(t, err)
	require.Equal(t, int64(2), renewed.LeaseEpoch)

	// S-1: Unrelated Edge node cannot trigger failover for another lease.
	_, err = leaseSvc.CoordinateFailover(ctx, EdgeFailoverRequest{
		LeaseID:         minted.LeaseID,
		CallerNodeID:    rogue.ID,
		FailedAccountID: 501,
		StatusCode:      429,
	})
	require.ErrorIs(t, err, ErrEdgeLeaseForbidden)

	// S-1: Mismatched failed_account_id is rejected.
	_, err = leaseSvc.CoordinateFailover(ctx, EdgeFailoverRequest{
		LeaseID:         minted.LeaseID,
		CallerNodeID:    landing.ID,
		FailedAccountID: 999,
		StatusCode:      429,
	})
	require.ErrorIs(t, err, ErrEdgeLeaseForbidden)

	// Expired lease cannot be renewed or failed over.
	leaseStore.mu.Lock()
	leaseStore.leases[minted.LeaseID].ExpiresAt = time.Now().Add(-time.Minute)
	leaseStore.mu.Unlock()
	_, err = leaseSvc.RenewLeaseWithKey(ctx, 42, 101, minted.LeaseID)
	require.ErrorIs(t, err, ErrEdgeLeaseRevoked)
	_, err = leaseSvc.CoordinateFailover(ctx, EdgeFailoverRequest{
		LeaseID:         minted.LeaseID,
		CallerNodeID:    landing.ID,
		FailedAccountID: 501,
		StatusCode:      429,
	})
	require.ErrorIs(t, err, ErrEdgeLeaseRevoked)
}

func TestWave1_CheckManagedProxyDeleteAllowedAndNarrowExitUpdate(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	mkt := &MarketplaceService{db: db}

	// Active landing grant blocks deletion with 409.
	mock.ExpectQuery(`SELECT EXISTS\([\s\S]*berth_landing_node_grants`).
		WithArgs(int64(55)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	err = mkt.CheckManagedProxyDeleteAllowed(context.Background(), 55)
	require.ErrorIs(t, err, ErrProxyManagedInUse)

	// No active grant, active marketplace rental order blocks deletion with 409.
	mock.ExpectQuery(`SELECT EXISTS\([\s\S]*berth_landing_node_grants`).
		WithArgs(int64(56)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery(`SELECT EXISTS\([\s\S]*berth_marketplace_orders`).
		WithArgs(int64(56)).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	err = mkt.CheckManagedProxyDeleteAllowed(context.Background(), 56)
	require.ErrorIs(t, err, ErrProxyManagedInUse)

	// Narrow exit profile update touches only exit_* columns conditionally on transport identity.
	now := time.Now()
	p := &Proxy{
		ID:              55,
		Protocol:        "https",
		Host:            "node-15.edge.internal",
		Port:            443,
		ExitIP:          "68.77.201.111",
		ExitCountryCode: "US",
		ExitTimezone:    "America/Chicago",
		ExitISP:         "Berth Edge Landing",
		ExitCheckedAt:   &now,
	}
	mock.ExpectExec(`UPDATE proxies[\s\S]*WHERE id = \$1[\s\S]*AND protocol = \$12[\s\S]*AND host = \$13[\s\S]*AND port = \$14`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	updated, err := mkt.UpdateProxyExitProfile(context.Background(), p, "https", "node-15.edge.internal", 443)
	require.NoError(t, err)
	require.True(t, updated)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestWave1_OAuthTaskRejectsNonLandingNodeAndCancelsOnRevoke(t *testing.T) {
	ctx := context.Background()
	pub, priv, kid, err := LoadOrGenerateEdgeSigningKey("", filepath.Join(t.TempDir(), "k.pem"))
	require.NoError(t, err)

	revSeq := int64(1)
	zoneStore := NewMemoryZoneStore(true)
	zoneSvc := NewBerthZoneServiceWithStore(zoneStore)
	grantSvc := NewBerthLandingGrantServiceWithStore(NewMemoryLandingGrantStore(zoneStore, &revSeq))
	leaseSvc := NewBerthEdgeLeaseServiceWithStore(NewMemoryEdgeLeaseStore(&revSeq), zoneSvc, grantSvc, pub, priv, kid)

	zones, err := zoneSvc.ListZones(ctx)
	require.NoError(t, err)
	transit, err := zoneSvc.CreateNode(ctx, EdgeNode{
		Name:   "transit-only",
		ZoneID: zones[0].ID,
		Roles:  []string{EdgeRoleTransit},
		Status: EdgeNodeStatusActive,
	})
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://auth.openai.com/oauth/token", nil)
	require.NoError(t, err)
	_, err = leaseSvc.ExecuteOAuthTaskSyncForAccount(ctx, "node-"+strings.TrimSpace(strings.TrimPrefix(EdgeInternalProxyHost(transit.ID), "node-")), 0, req)
	require.Error(t, err)

	// Enqueued pending OAuth tasks are cancelled cleanly when CancelPendingOAuthTasksForNode is called.
	landing, err := zoneSvc.CreateNode(ctx, EdgeNode{
		Name:   "landing-cancel",
		ZoneID: zones[0].ID,
		Roles:  []string{EdgeRoleLanding},
		Status: EdgeNodeStatusActive,
	})
	require.NoError(t, err)
	task := leaseSvc.EnqueueOAuthTask(EdgeOAuthTask{
		NodeID: landing.ID, AccountID: 10, Kind: "oauth_exchange",
		TargetURL: "https://auth.openai.com/oauth/token", Method: http.MethodPost,
	})
	nCancelled := leaseSvc.CancelPendingOAuthTasksForNode(landing.ID, "landing grant revoked")
	require.Equal(t, 1, nCancelled)
	snap, ok := leaseSvc.ConsumeOAuthTask(task.TaskID)
	require.True(t, ok)
	require.Equal(t, "failed", snap.Status)
	require.Contains(t, snap.Error, "revoked")
}
