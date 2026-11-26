package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jk-zhang-meta/berth/internal/edge"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
)

var (
	version = "2.1.0-edge"
	commit  = "dev"
)

func main() {
	var (
		configPath     = flag.String("config", "", "Path to YAML/JSON berth-edge config file")
		nodeID         = flag.Int64("node-id", 0, "Override edge node ID")
		nodeName       = flag.String("node-name", "", "Override edge node name")
		rolesCSV       = flag.String("roles", "", "Comma-separated roles (ingress_relay,transit,landing,compat,mgmt_entry)")
		listenAddr     = flag.String("listen", "", "HTTP/2 + HTTP/1.1 data-plane listen address")
		centralURL     = flag.String("central-url", "", "Berth Central base URL")
		centralPubKey  = flag.String("central-pubkey", "", "Berth Central Ed25519 public key (base64url/hex)")
		mgmtListen     = flag.String("mgmt-entry-listen", "", "BHE1 management entry TCP listen address (default :18443)")
		mgmtTarget     = flag.String("mgmt-central-target", "", "Hardcoded Berth Central host:port for BHE1 forwarding")
		revHubAddr     = flag.String("reverse-tunnel-hub", "", "Reverse tunnel hub listen address (Transit role)")
		revDialAddr    = flag.String("reverse-tunnel-dial", "", "Reverse tunnel hub dial address (NAT Landing role)")
		walDir         = flag.String("wal-dir", "", "Directory for GrantWAL and OutboxWAL files")
		showVersion    = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("berth-edge %s (commit: %s)\n", version, commit)
		return
	}

	var cfg *edge.Config
	var err error
	if *configPath != "" {
		cfg, err = edge.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
	} else {
		cfg = &edge.Config{}
	}

	if *nodeID > 0 {
		cfg.NodeID = *nodeID
	}
	if *nodeName != "" {
		cfg.NodeName = *nodeName
	}
	if *rolesCSV != "" {
		cfg.Roles = nil
		for _, r := range strings.Split(*rolesCSV, ",") {
			if r = strings.TrimSpace(r); r != "" {
				cfg.Roles = append(cfg.Roles, r)
			}
		}
	}
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}
	if *centralURL != "" {
		cfg.CentralURL = *centralURL
	}
	if *centralPubKey != "" {
		cfg.CentralPubKey = *centralPubKey
	}
	if *mgmtListen != "" {
		cfg.MgmtEntryListenAddr = *mgmtListen
	}
	if *mgmtTarget != "" {
		cfg.MgmtCentralTarget = *mgmtTarget
	}
	if *revHubAddr != "" {
		cfg.ReverseTunnelHubAddr = *revHubAddr
	}
	if *revDialAddr != "" {
		cfg.ReverseTunnelDialAddr = *revDialAddr
	}
	if *walDir != "" {
		cfg.WALDir = *walDir
	}
	cfg.ApplyDefaults()

	if cfg.NodeID <= 0 {
		log.Fatal("berth-edge: --node-id or config.node_id is required")
	}
	if len(cfg.Roles) == 0 {
		log.Fatal("berth-edge: at least one role is required")
	}

	nodePriv, err := loadNodePrivateKey(cfg)
	if err != nil {
		log.Fatalf("load node private key: %v", err)
	}
	var cPub ed25519.PublicKey
	if cfg.CentralPubKey != "" {
		cPub, err = edge.ParseEd25519PublicKey(cfg.CentralPubKey)
		if err != nil {
			log.Fatalf("parse central_pubkey: %v", err)
		}
	}

	if cfg.WALDir == "" {
		cfg.WALDir = filepath.Join(os.TempDir(), fmt.Sprintf("berth-edge-%d", cfg.NodeID))
	}

	// Always initialize lightweight GrantWAL and OutboxWAL so any server can
	// dynamically hot-enable the "landing" role via Central heartbeat without restart.
	grantWAL, err := edgeproto.OpenGrantWAL(filepath.Join(cfg.WALDir, "grant_wal.jsonl"))
	if err != nil {
		log.Fatalf("open grant WAL: %v", err)
	}
	defer func() { _ = grantWAL.Close() }()

	outboxWAL, err := edgeproto.OpenOutboxWAL(filepath.Join(cfg.WALDir, "outbox_wal.jsonl"))
	if err != nil {
		log.Fatalf("open outbox WAL: %v", err)
	}
	defer func() { _ = outboxWAL.Close() }()

	var centralClient *edge.CentralClient
	if cfg.CentralURL != "" {
		centralClient = edge.NewCentralClient(cfg.CentralURL, cfg.NodeID, nodePriv, nil)
	}

	var revHub *edge.ReverseTunnelHub
	if cfg.ReverseTunnelHubAddr != "" {
		peerKeys := make(map[int64]ed25519.PublicKey, len(cfg.PeerPublicKeys))
		for id, raw := range cfg.PeerPublicKeys {
			if pk, pkErr := edge.ParseEd25519PublicKey(raw); pkErr == nil {
				peerKeys[id] = pk
			}
		}
		revHub = edge.NewReverseTunnelHub(func(id int64) (ed25519.PublicKey, error) {
			if pk, ok := peerKeys[id]; ok {
				return pk, nil
			}
			return nil, errors.New("unknown peer node")
		}, nil)
	}

	srv, err := edge.NewEdgeServer(edge.EdgeServerOptions{
		Config:        cfg,
		CentralPubKey: cPub,
		CentralClient: centralClient,
		GrantWAL:      grantWAL,
		OutboxWAL:     outboxWAL,
		ReverseHub:    revHub,
	})
	if err != nil {
		log.Fatalf("init edge server: %v", err)
	}

	exePath, selfSHA256, selfErr := edge.ComputeSelfSHA256()
	if selfErr != nil {
		log.Printf("berth-edge[%s] warning: compute self sha256 failed (auto-update disabled): %v", cfg.NodeName, selfErr)
	}
	var updater *edge.SelfUpdater
	if exePath != "" && selfSHA256 != "" && !strings.EqualFold(os.Getenv("BERTH_EDGE_DISABLE_AUTO_UPDATE"), "true") {
		updater = edge.NewSelfUpdater(exePath, selfSHA256)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup

	// Background revocation snapshot freshness watchdog.
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Gate().StartFreshnessWatchdog(ctx, 500*time.Millisecond)
	}()

	// Background heartbeat + dynamic role hot-sync + SHA-256 auto-update + OAuth task loop.
	if centralClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runHeartbeatLoop(ctx, stop, cfg, centralClient, srv, updater, selfSHA256)
		}()
	}

	// Background durable outbox flusher.
	if outboxWAL != nil && centralClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outboxWAL.RunFlusher(ctx, 500*time.Millisecond, 30*time.Second, centralClient.FlushUsageOutbox)
		}()
	}

	// BHE1 Management-Entry TCP proxy (:18443).
	if cfg.HasRole(edge.RoleMgmtEntry) && cfg.MgmtCentralTarget != "" {
		proxy := edge.NewMgmtEntryProxy(cfg.NodeID, nodePriv, cfg.MgmtCentralTarget)
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("berth-edge[%s] mgmt_entry BHE1 listening on %s -> %s", cfg.NodeName, cfg.MgmtEntryListenAddr, cfg.MgmtCentralTarget)
			if err := proxy.ListenAndServe(ctx, cfg.MgmtEntryListenAddr); err != nil {
				log.Printf("mgmt_entry stopped: %v", err)
			}
		}()
	}

	// Reverse-Tunnel Hub (Transit role).
	if revHub != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("berth-edge[%s] reverse_tunnel hub listening on %s", cfg.NodeName, cfg.ReverseTunnelHubAddr)
			if err := revHub.ListenAndServe(ctx, cfg.ReverseTunnelHubAddr); err != nil {
				log.Printf("reverse_tunnel hub stopped: %v", err)
			}
		}()
	}

	// Reverse-Tunnel Outbound Client (NAT/Home Landing role).
	if cfg.ReverseTunnelDialAddr != "" {
		revClient := edge.NewReverseTunnelClient(cfg.NodeID, nodePriv, cfg.ReverseTunnelDialAddr, srv.Handler())
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("berth-edge[%s] reverse_tunnel dialing %s", cfg.NodeName, cfg.ReverseTunnelDialAddr)
			_ = revClient.Run(ctx)
		}()
	}

	// Primary HTTP/2 + HTTP/1.1 data-plane listener.
	if cfg.ListenAddr != "" {
		ln, err := net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			log.Fatalf("listen %s: %v", cfg.ListenAddr, err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("berth-edge[%s] data-plane listening on %s roles=%v", cfg.NodeName, ln.Addr(), cfg.Roles)
			if err := srv.Serve(ctx, ln); err != nil {
				log.Printf("data-plane server stopped: %v", err)
			}
		}()
	}

	<-ctx.Done()
	log.Printf("berth-edge[%s] shutting down...", cfg.NodeName)
	if outboxWAL != nil && centralClient != nil {
		flushCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, _ = outboxWAL.FlushOnce(flushCtx, 100, centralClient.FlushUsageOutbox)
		cancel()
	}
	wg.Wait()
}

func runHeartbeatLoop(
	ctx context.Context,
	triggerRestart context.CancelFunc,
	cfg *edge.Config,
	client *edge.CentralClient,
	srv *edge.EdgeServer,
	updater *edge.SelfUpdater,
	selfSHA256 string,
) {
	agentVersion := version
	if commit != "" && commit != "dev" {
		agentVersion = fmt.Sprintf("%s-%s", version, commit)
	}
	report := edge.HeartbeatReport{
		Status:       "active",
		AgentVersion: agentVersion,
		AgentArch:    runtime.GOOS + "/" + runtime.GOARCH,
		AgentSHA256:  selfSHA256,
	}
	tick := func() {
		if res, err := client.HeartbeatFull(ctx, report); err == nil {
			_ = srv.Gate().UpdateSnapshot(res.RevocationSnapshot)
			if len(res.NodeRoles) > 0 {
				prev := srv.Roles()
				if srv.ApplyRuntimeRoles(res.NodeRoles) {
					log.Printf("berth-edge[%s] runtime roles hot-updated: %v -> %v", cfg.NodeName, prev, srv.Roles())
				}
			}
			if updater != nil && res.EdgeRelease != nil {
				if updated, uErr := updater.MaybeUpdate(ctx, res.EdgeRelease, client.DownloadBinary, triggerRestart); uErr != nil {
					log.Printf("berth-edge[%s] auto-update failed (will retry with backoff): %v", cfg.NodeName, uErr)
				} else if updated {
					return
				}
			}
		}
		if srv.HasRole(edge.RoleLanding) || srv.HasRole(edge.RoleCompat) {
			_, _ = srv.ExecutePendingOAuthTasks(ctx)
		}
	}
	tick()
	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}

func loadNodePrivateKey(cfg *edge.Config) (ed25519.PrivateKey, error) {
	if cfg.NodePrivateKey != "" {
		return edge.ParseEd25519PrivateKey(cfg.NodePrivateKey)
	}
	if cfg.NodePrivateKeyFile != "" {
		raw, err := os.ReadFile(cfg.NodePrivateKeyFile)
		if err != nil {
			return nil, err
		}
		return edge.ParseEd25519PrivateKey(string(raw))
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}
