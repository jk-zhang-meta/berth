package service

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestBerthZoneService_FR138ClientZoneResolution(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryZoneStore(true)
	svc := NewBerthZoneServiceWithStore(store)

	now := time.Now()
	freshObs := now.Add(-2 * time.Hour)
	staleObs := now.Add(-48 * time.Hour)

	// 1. Admin pinned zone overrides everything.
	res, err := svc.ResolveClientZone(ctx, ZoneResolutionInput{
		PinnedZoneSlug:    "cn_mainland",
		PreferredZoneSlug: "overseas",
		PeerCountryCode:   "US",
		Now:               now,
	})
	require.NoError(t, err)
	require.Equal(t, ZoneResolutionResolved, res.Status)
	require.Equal(t, "cn_mainland", res.Zone.Slug)
	require.Equal(t, "pinned", res.Source)

	// 1b. Stale admin pin fails closed!
	res, err = svc.ResolveClientZone(ctx, ZoneResolutionInput{
		PinnedZoneSlug: "nonexistent_zone",
		Now:            now,
	})
	require.ErrorIs(t, err, ErrEdgeZoneUnresolved)
	require.Equal(t, ZoneResolutionUnresolvedStrict, res.Status)

	// 2. Explicit client preference works for non-centre zones, ignores centre_isvoro.
	res, err = svc.ResolveClientZone(ctx, ZoneResolutionInput{
		PreferredZoneSlug: "home_direct",
		PeerCountryCode:   "CN",
		Now:               now,
	})
	require.NoError(t, err)
	require.Equal(t, "home_direct", res.Zone.Slug)
	require.Equal(t, "explicit_preference", res.Source)

	res, err = svc.ResolveClientZone(ctx, ZoneResolutionInput{
		PreferredZoneSlug: "centre_isvoro",
		PeerCountryCode:   "CN",
		Now:               now,
	})
	require.NoError(t, err)
	require.Equal(t, "cn_mainland", res.Zone.Slug)
	require.Equal(t, "bhe1_geoip", res.Source)

	// 3. Fresh physical probe overrides VPN-masked peer IP.
	res, err = svc.ResolveClientZone(ctx, ZoneResolutionInput{
		PhysicalCountryCode: "CN",
		PhysicalObservedAt:  &freshObs,
		PeerCountryCode:     "US",
		DefaultRouteVPN:     true,
		Now:                 now,
	})
	require.NoError(t, err)
	require.Equal(t, "cn_mainland", res.Zone.Slug)
	require.Equal(t, "auto_physical", res.Source)

	// 4. When VPN is active and physical probe is stale, hold last_clean_zone_slug.
	res, err = svc.ResolveClientZone(ctx, ZoneResolutionInput{
		PhysicalCountryCode: "CN",
		PhysicalObservedAt:  &staleObs,
		PeerCountryCode:     "US",
		DefaultRouteVPN:     true,
		LastCleanZoneSlug:   "cn_mainland",
		Now:                 now,
	})
	require.NoError(t, err)
	require.Equal(t, "cn_mainland", res.Zone.Slug)
	require.Equal(t, "auto_vpn_held", res.Source)

	// 5. Fallback to overseas when no match.
	res, err = svc.ResolveClientZone(ctx, ZoneResolutionInput{
		PeerCountryCode: "JP",
		Now:             now,
	})
	require.NoError(t, err)
	require.Equal(t, "overseas", res.Zone.Slug)
	require.Equal(t, "fallback", res.Source)
}

func TestBerthZoneService_DijkstraOneWayIPLCAndReverseTunnel(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryZoneStore(true)
	svc := NewBerthZoneServiceWithStore(store)

	zones, err := svc.ListZones(ctx)
	require.NoError(t, err)
	zoneID := map[string]int64{}
	for _, z := range zones {
		zoneID[z.Slug] = z.ID
	}

	sh, err := svc.CreateNode(ctx, EdgeNode{Name: "tencent-sh", ZoneID: zoneID["cn_mainland"], Roles: []string{EdgeRoleIngressRelay}, TunnelAddr: "10.0.0.1:9443", Status: EdgeNodeStatusActive})
	require.NoError(t, err)
	iplc, err := svc.CreateNode(ctx, EdgeNode{Name: "sh-jp-iplc", ZoneID: zoneID["cn_mainland"], Roles: []string{EdgeRoleTransit}, TunnelAddr: "10.0.0.2:9443", Status: EdgeNodeStatusActive})
	require.NoError(t, err)
	hk, err := svc.CreateNode(ctx, EdgeNode{Name: "po0-hk", ZoneID: zoneID["overseas"], Roles: []string{EdgeRoleTransit}, TunnelAddr: "10.0.0.3:9443", Status: EdgeNodeStatusActive})
	require.NoError(t, err)
	jpTransit, err := svc.CreateNode(ctx, EdgeNode{Name: "hyonix-tokyo", ZoneID: zoneID["overseas"], Roles: []string{EdgeRoleTransit}, TunnelAddr: "10.0.0.4:9443", Status: EdgeNodeStatusActive})
	require.NoError(t, err)
	tokyoHome, err := svc.CreateNode(ctx, EdgeNode{Name: "tokyo-home", ZoneID: zoneID["home_direct"], Roles: []string{EdgeRoleLanding}, ConnectMode: ConnectModeReverseTunnel, Status: EdgeNodeStatusActive})
	require.NoError(t, err)

	// Fast asymmetric 1-way IPLC path: tencent-sh -> sh-jp-iplc -> hyonix-tokyo (cost 20+20=40).
	_, err = svc.CreateLink(ctx, ServerLink{SrcNodeID: sh.ID, DstNodeID: iplc.ID, Direction: LinkDirectionOneWay, LinkClass: LinkClassIPLC, Weight: 10, RTTMs: 10, Enabled: true})
	require.NoError(t, err)
	_, err = svc.CreateLink(ctx, ServerLink{SrcNodeID: iplc.ID, DstNodeID: jpTransit.ID, Direction: LinkDirectionOneWay, LinkClass: LinkClassIPLC, Weight: 10, RTTMs: 10, Enabled: true})
	require.NoError(t, err)
	// Slower fallback via HK (cost 80+80=160).
	_, err = svc.CreateLink(ctx, ServerLink{SrcNodeID: sh.ID, DstNodeID: hk.ID, Direction: LinkDirectionBidirectional, LinkClass: LinkClassDirect, Weight: 50, RTTMs: 30, Enabled: true})
	require.NoError(t, err)
	_, err = svc.CreateLink(ctx, ServerLink{SrcNodeID: hk.ID, DstNodeID: jpTransit.ID, Direction: LinkDirectionBidirectional, LinkClass: LinkClassDirect, Weight: 50, RTTMs: 30, Enabled: true})
	require.NoError(t, err)
	// Reverse-tunnel last hop: hyonix-tokyo =(reverse_tunnel)=> tokyo-home.
	_, err = svc.CreateLink(ctx, ServerLink{SrcNodeID: jpTransit.ID, DstNodeID: tokyoHome.ID, Direction: LinkDirectionOneWay, LinkClass: LinkClassReverseTunnel, Weight: 5, RTTMs: 5, Enabled: true})
	require.NoError(t, err)

	// When reverse tunnel for tokyo-home is LIVE, Dijkstra picks 1-way IPLC path!
	hops, cost, err := svc.FindShortestPath(ctx, sh.ID, tokyoHome.ID, map[int64]bool{tokyoHome.ID: true})
	require.NoError(t, err)
	require.Equal(t, 50, cost)
	require.Len(t, hops, 4)
	require.Equal(t, []string{"tencent-sh", "sh-jp-iplc", "hyonix-tokyo", "tokyo-home"}, []string{hops[0].NodeName, hops[1].NodeName, hops[2].NodeName, hops[3].NodeName})
	require.Equal(t, LinkClassIPLC, hops[1].LinkClass)
	require.Equal(t, LinkClassReverseTunnel, hops[3].LinkClass)

	// One-way IPLC CANNOT be traversed backwards (hyonix-tokyo -> sh-jp-iplc is forbidden!).
	revHops, revCost, err := svc.FindShortestPath(ctx, jpTransit.ID, sh.ID, nil)
	require.NoError(t, err)
	require.Equal(t, 160, revCost)
	require.Equal(t, "po0-hk", revHops[1].NodeName)

	// When reverse tunnel disappears, route to tokyo-home MUST be withdrawn!
	_, _, err = svc.FindShortestPath(ctx, sh.ID, tokyoHome.ID, map[int64]bool{})
	require.ErrorIs(t, err, ErrNoRouteAvailable)

	// If sh-jp-iplc goes offline, Dijkstra seamlessly routes via po0-hk!
	_, err = svc.RecordHeartbeat(ctx, iplc.ID, EdgeHeartbeatUpdate{Status: EdgeNodeStatusOffline}, time.Now())
	require.NoError(t, err)
	hops, cost, err = svc.FindShortestPath(ctx, sh.ID, tokyoHome.ID, map[int64]bool{tokyoHome.ID: true})
	require.NoError(t, err)
	require.Equal(t, 170, cost)
	require.Equal(t, "po0-hk", hops[1].NodeName)
}

func TestBerthZoneService_SQLMockListZones(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	now := time.Now()
	rows := sqlmock.NewRows([]string{
		"id", "slug", "display_name", "is_centre", "default_mgmt_policy",
		"dns_hint_domains", "geo_country_codes", "created_at", "updated_at",
	}).AddRow(1, "cn_mainland", "China Mainland", false, "entry_required", pq.Array([]string{}), pq.Array([]string{"CN"}), now, now)

	mock.ExpectQuery(`SELECT id, slug, display_name`).WillReturnRows(rows)

	svc := NewBerthZoneService(db)
	zones, err := svc.ListZones(context.Background())
	require.NoError(t, err)
	require.Len(t, zones, 1)
	require.Equal(t, "cn_mainland", zones[0].Slug)
	require.Equal(t, []string{"CN"}, zones[0].GeoCountryCodes)
	require.NoError(t, mock.ExpectationsWereMet())
}


func TestBerthZoneService_PublicAddrEntryAndEndToEndRTTRouting(t *testing.T) {
	ctx := context.Background()
	svc := NewBerthZoneServiceWithStore(NewMemoryZoneStore(true))
	zones, err := svc.ListZones(ctx)
	require.NoError(t, err)
	cnZoneID := zones[1].ID
	overseasZoneID := zones[2].ID

	// Two CN zone relay nodes identified as entries purely by public_addr (no separate ingress_relay tag needed).
	gz, err := svc.CreateNode(ctx, EdgeNode{
		Name:       "gz",
		ZoneID:     cnZoneID,
		Roles:      []string{EdgeRoleTransit},
		PublicAddr: "http://1.1.1.1:19443",
		Status:     EdgeNodeStatusActive,
	})
	require.NoError(t, err)
	sh, err := svc.CreateNode(ctx, EdgeNode{
		Name:       "sh",
		ZoneID:     cnZoneID,
		Roles:      []string{EdgeRoleTransit},
		PublicAddr: "http://2.2.2.2:19443",
		Status:     EdgeNodeStatusActive,
	})
	require.NoError(t, err)
	// Internal-only IPLC jump box (empty public_addr -> never picked as direct client entry).
	jump, err := svc.CreateNode(ctx, EdgeNode{
		Name:       "iplc-jump",
		ZoneID:     cnZoneID,
		Roles:      []string{EdgeRoleTransit},
		TunnelAddr: "10.0.0.1:19443",
		Status:     EdgeNodeStatusActive,
	})
	require.NoError(t, err)
	landing, err := svc.CreateNode(ctx, EdgeNode{
		Name:        "la-land",
		ZoneID:      overseasZoneID,
		Roles:       []string{EdgeRoleLanding},
		ConnectMode: ConnectModeReverseTunnel,
		Status:      EdgeNodeStatusActive,
	})
	require.NoError(t, err)

	_, err = svc.CreateLink(ctx, ServerLink{SrcNodeID: gz.ID, DstNodeID: jump.ID, Direction: LinkDirectionOneWay, LinkClass: LinkClassIPLC, Weight: 5, RTTMs: 10, Enabled: true})
	require.NoError(t, err)
	_, err = svc.CreateLink(ctx, ServerLink{SrcNodeID: jump.ID, DstNodeID: landing.ID, Direction: LinkDirectionOneWay, LinkClass: LinkClassDirect, Weight: 5, RTTMs: 120, Enabled: true})
	require.NoError(t, err)
	_, err = svc.CreateLink(ctx, ServerLink{SrcNodeID: sh.ID, DstNodeID: landing.ID, Direction: LinkDirectionOneWay, LinkClass: LinkClassDirect, Weight: 5, RTTMs: 125, Enabled: true})
	require.NoError(t, err)

	// Without client RTT, sh path (130) beats gz->jump->la (140), and jump is never picked as client entry.
	entry, hops, cost, err := svc.SelectBestIngressAndRouteWithRTT(ctx, cnZoneID, landing.ID, map[int64]bool{landing.ID: true}, nil)
	require.NoError(t, err)
	require.Equal(t, sh.ID, entry.ID)
	require.Equal(t, 130, cost)
	require.Equal(t, sh.ID, hops[0].NodeID)

	// With client RTT (Guangzhou client: 8ms to gz, 45ms to sh), gz wins end-to-end (148 < 175)!
	entry2, hops2, cost2, err := svc.SelectBestIngressAndRouteWithRTT(ctx, cnZoneID, landing.ID, map[int64]bool{landing.ID: true}, map[int64]int{
		gz.ID: 8,
		sh.ID: 45,
	})
	require.NoError(t, err)
	require.Equal(t, gz.ID, entry2.ID)
	require.Equal(t, 148, cost2)
	require.Equal(t, gz.ID, hops2[0].NodeID)
}

func TestBerthZoneService_FR125AutoMeasuredTopologyAndOverrides(t *testing.T) {
	ctx := context.Background()
	svc := NewBerthZoneServiceWithStore(NewMemoryZoneStore(true))
	zones, err := svc.ListZones(ctx)
	require.NoError(t, err)
	cnZoneID := zones[1].ID
	overseasZoneID := zones[2].ID

	// Zero static berth_server_links configured! Pure FR-125 auto-probed mesh!
	gz, err := svc.CreateNode(ctx, EdgeNode{Name: "po0-gz", ZoneID: cnZoneID, Roles: []string{EdgeRoleTransit}, PublicAddr: "http://81.71.126.162:19443", TunnelAddr: "172.31.8.41:19443", Status: EdgeNodeStatusActive})
	require.NoError(t, err)
	po0hk, err := svc.CreateNode(ctx, EdgeNode{Name: "po0-hk", ZoneID: overseasZoneID, Roles: []string{EdgeRoleTransit}, TunnelAddr: "10.42.2.114:19443", Status: EdgeNodeStatusActive})
	require.NoError(t, err)
	hyHK, err := svc.CreateNode(ctx, EdgeNode{Name: "hyonix-hk", ZoneID: overseasZoneID, Roles: []string{EdgeRoleTransit}, PublicAddr: "http://1.2.3.4:19443", TunnelAddr: "1.2.3.4:19443", Status: EdgeNodeStatusActive})
	require.NoError(t, err)
	hyLA, err := svc.CreateNode(ctx, EdgeNode{Name: "hyonix-la", ZoneID: overseasZoneID, Roles: []string{EdgeRoleTransit}, PublicAddr: "http://5.6.7.8:19443", TunnelAddr: "5.6.7.8:19443", Status: EdgeNodeStatusActive})
	require.NoError(t, err)
	houston, err := svc.CreateNode(ctx, EdgeNode{Name: "houston-vm100", ZoneID: overseasZoneID, Roles: []string{EdgeRoleLanding}, ConnectMode: ConnectModeReverseTunnel, Status: EdgeNodeStatusActive})
	require.NoError(t, err)

	now := time.Now()
	// 1. ProbeTargetsForNode excludes self and reverse_tunnel nodes.
	targets, err := svc.ProbeTargetsForNode(ctx, gz.ID)
	require.NoError(t, err)
	require.Len(t, targets, 3)

	// 2. Report real directional probes (no static links!):
	//    po0-gz -> po0-hk (7ms IPLC), po0-gz -> hyonix-la (220ms public)
	//    po0-hk -> hyonix-hk (3ms), po0-hk -> hyonix-la (145ms)
	//    hyonix-hk -> hyonix-la (140ms)
	//    hyonix-la -> houston-vm100 (reverse_tunnel, 18ms)
	_, err = svc.RecordHeartbeat(ctx, gz.ID, EdgeHeartbeatUpdate{
		Status: EdgeNodeStatusActive,
		MeasuredLinks: []MeasuredPeerLink{
			{TargetNodeID: po0hk.ID, Reachable: true, RTTMs: 7, LinkClass: LinkClassDirect, MeasuredAtUnix: now.Unix()},
			{TargetNodeID: hyLA.ID, Reachable: true, RTTMs: 220, LinkClass: LinkClassDirect, MeasuredAtUnix: now.Unix()},
		},
	}, now)
	require.NoError(t, err)
	_, err = svc.RecordHeartbeat(ctx, po0hk.ID, EdgeHeartbeatUpdate{
		Status: EdgeNodeStatusActive,
		MeasuredLinks: []MeasuredPeerLink{
			{TargetNodeID: hyHK.ID, Reachable: true, RTTMs: 3, LinkClass: LinkClassDirect, MeasuredAtUnix: now.Unix()},
			{TargetNodeID: hyLA.ID, Reachable: true, RTTMs: 145, LinkClass: LinkClassDirect, MeasuredAtUnix: now.Unix()},
		},
	}, now)
	require.NoError(t, err)
	_, err = svc.RecordHeartbeat(ctx, hyHK.ID, EdgeHeartbeatUpdate{
		Status: EdgeNodeStatusActive,
		MeasuredLinks: []MeasuredPeerLink{
			{TargetNodeID: hyLA.ID, Reachable: true, RTTMs: 140, LinkClass: LinkClassDirect, MeasuredAtUnix: now.Unix()},
		},
	}, now)
	require.NoError(t, err)
	_, err = svc.RecordHeartbeat(ctx, hyLA.ID, EdgeHeartbeatUpdate{
		Status:             EdgeNodeStatusActive,
		MeasuredLinks:      []MeasuredPeerLink{{TargetNodeID: houston.ID, Reachable: true, RTTMs: 18, LinkClass: LinkClassReverseTunnel, MeasuredAtUnix: now.Unix()}},
		LiveReverseTunnels: []int64{houston.ID},
	}, now)
	require.NoError(t, err)

	// 3. Pure auto-probed Dijkstra chooses po0-gz -> po0-hk -> hyonix-hk -> hyonix-la -> houston-vm100 (7+3+140+18 = 168ms < 7+145+18 = 170ms < 220+18 = 238ms)!
	liveRev := svc.LiveReverseTunnelsSnapshot(now)
	require.True(t, liveRev[houston.ID])

	entry, hops, cost, err := svc.SelectBestIngressAndRouteWithRTT(ctx, cnZoneID, houston.ID, liveRev, nil)
	require.NoError(t, err)
	require.Equal(t, gz.ID, entry.ID)
	require.Equal(t, 168, cost)
	require.Equal(t, []string{"po0-gz", "po0-hk", "hyonix-hk", "hyonix-la", "houston-vm100"},
		[]string{hops[0].NodeName, hops[1].NodeName, hops[2].NodeName, hops[3].NodeName, hops[4].NodeName})
	require.Equal(t, LinkClassReverseTunnel, hops[4].LinkClass)

	// 4. ListMeasuredTopology exposes all 6 live auto-discovered edges.
	topo, err := svc.ListMeasuredTopology(ctx)
	require.NoError(t, err)
	require.Len(t, topo, 6)

	// 5. Optional static disabled link acts as a hard blocklist on measured edge (po0-hk -> hyonix-hk)!
	_, err = svc.CreateLink(ctx, ServerLink{SrcNodeID: po0hk.ID, DstNodeID: hyHK.ID, Direction: LinkDirectionOneWay, LinkClass: LinkClassDirect, Enabled: false})
	require.NoError(t, err)
	_, hops2, cost2, err := svc.SelectBestIngressAndRouteWithRTT(ctx, cnZoneID, houston.ID, liveRev, nil)
	require.NoError(t, err)
	require.Equal(t, 170, cost2)
	require.Equal(t, []string{"po0-gz", "po0-hk", "hyonix-la", "houston-vm100"},
		[]string{hops2[0].NodeName, hops2[1].NodeName, hops2[2].NodeName, hops2[3].NodeName})

	// 5b. Snapshot-only heartbeat (empty Status + empty slices from edge revocation refresh)
	// must NEVER wipe existing measured links or live reverse tunnels!
	_, err = svc.RecordHeartbeat(ctx, hyLA.ID, EdgeHeartbeatUpdate{
		Status:             "",
		MeasuredLinks:      []MeasuredPeerLink{},
		LiveReverseTunnels: []int64{},
	}, now.Add(500*time.Millisecond))
	require.NoError(t, err)
	liveRevSnap := svc.LiveReverseTunnelsSnapshot(now.Add(500 * time.Millisecond))
	require.True(t, liveRevSnap[houston.ID])
	_, hopsSnap, _, err := svc.SelectBestIngressAndRouteWithRTT(ctx, cnZoneID, houston.ID, liveRevSnap, nil)
	require.NoError(t, err)
	require.Len(t, hopsSnap, 4)

	// 6. When hyonix-la reports houston-vm100 disconnected (empty non-nil LiveReverseTunnels), route is immediately withdrawn!
	_, err = svc.RecordHeartbeat(ctx, hyLA.ID, EdgeHeartbeatUpdate{
		Status:             EdgeNodeStatusActive,
		MeasuredLinks:      []MeasuredPeerLink{},
		LiveReverseTunnels: []int64{},
	}, now.Add(time.Second))
	require.NoError(t, err)
	liveRevAfter := svc.LiveReverseTunnelsSnapshot(now.Add(time.Second))
	require.False(t, liveRevAfter[houston.ID])
	_, _, _, err = svc.SelectBestIngressAndRouteWithRTT(ctx, cnZoneID, houston.ID, liveRevAfter, nil)
	require.ErrorIs(t, err, ErrNoRouteAvailable)
}

func TestSQLZoneStoreUpdateNode_SyncsLandingProxiesAndPreservesCustomNames(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	now := time.Now()
	store := &sqlZoneStore{db: db}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT name FROM berth_edge_nodes WHERE id = \$1 FOR UPDATE`).
		WithArgs(int64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("houston(host)"))
	mock.ExpectQuery(`UPDATE berth_edge_nodes SET`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "zone_id", "roles", "public_addr", "tunnel_addr", "mgmt_entry_addr",
			"connect_mode", "provider_region", "exit_ip", "exit_country_code", "exit_timezone",
			"exit_locale", "exit_asn_class", "pubkey_ed25519", "agent_cert_fingerprint",
			"status", "max_bytes_month", "used_bytes_month", "reserved_bytes_month",
			"last_heartbeat_at", "meta", "created_at", "updated_at",
		}).AddRow(
			int64(9), "Houston (母机)", int64(3), pq.Array([]string{EdgeRoleLanding}), "", "", "",
			ConnectModeReverseTunnel, "us-houston", "68.77.201.111", "US", "America/Chicago",
			"en_US.UTF-8", "residential", "", "", EdgeNodeStatusActive, int64(0), int64(0), int64(0),
			now, []byte(`{}`), now, now,
		))
	mock.ExpectQuery(`SELECT p\.id, p\.name, p\.host, COALESCE\(g\.grantee_user_id, 0\)`).
		WithArgs(int64(9), ProxySourceTypeEdgeLandingGrant).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "host", "grantee_user_id"}).
			AddRow(int64(56), "edge-landing-houston(host)-u1", "houston(host).edge.internal", int64(1)).
			AddRow(int64(57), "我的母机专属代理", "houston(host).edge.internal", int64(2)))

	// Default auto-generated name updates + host upgrades to canonical node-9.edge.internal.
	mock.ExpectExec(`UPDATE proxies\s+SET name = \$2, host = \$3, updated_at = NOW\(\)\s+WHERE id = \$1`).
		WithArgs(int64(56), "edge-landing-Houston (母机)-u1", "node-9.edge.internal").
		WillReturnResult(sqlmock.NewResult(0, 1))
	// Custom user-defined proxy name is preserved, while legacy host still upgrades to node-9.edge.internal.
	mock.ExpectExec(`UPDATE proxies\s+SET name = \$2, host = \$3, updated_at = NOW\(\)\s+WHERE id = \$1`).
		WithArgs(int64(57), "我的母机专属代理", "node-9.edge.internal").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	updated, err := store.UpdateNode(context.Background(), EdgeNode{
		ID:          9,
		Name:        "Houston (母机)",
		ZoneID:      3,
		Roles:       []string{EdgeRoleLanding},
		ConnectMode: ConnectModeReverseTunnel,
		Status:      EdgeNodeStatusActive,
		Meta:        []byte(`{}`),
	})
	require.NoError(t, err)
	require.Equal(t, "Houston (母机)", updated.Name)
	require.NoError(t, mock.ExpectationsWereMet())
}
