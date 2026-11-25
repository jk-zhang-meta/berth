package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/jk-zhang-meta/berth/internal/config"
	"github.com/jk-zhang-meta/berth/internal/handler"
	"github.com/jk-zhang-meta/berth/internal/handler/admin"
	"github.com/jk-zhang-meta/berth/internal/pkg/cage"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/jk-zhang-meta/berth/internal/service"
)

type berthV2Deps struct {
	db                   *sql.DB
	cfg                  *config.Config
	adminService         service.AdminService
	oAuthRefreshAPI      *service.OAuthRefreshAPI
	marketplace          *service.MarketplaceService
	paymentService       *service.PaymentService
	paymentConfigService *service.PaymentConfigService
	stewardStore         *service.StewardStore
	cnProviderHandler    *admin.CNProviderHandler
	handlers             *handler.Handlers
}

// wireBerthV2 initializes all Berth v2 subsystems (Account Cage + WAL Refresh,
// Adaptive Concurrency Advisor, Marketplace Online Payment Closure, and
// MeshHarbor-style Zones / Admin Landing Grants / Edge Session Leases) via a
// single clean bootstrap outside wire_gen.go so future Sub2API merges stay thin.
func wireBerthV2(deps berthV2Deps) (func(), error) {
	var cleanups []func()
	runCleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	// Track A: Account Cage + OAuth Refresh WAL journal.
	cagePool := cage.NewCageTransportPool()
	cageService := service.NewBerthAccountCageService(deps.db, cagePool)
	if deps.oAuthRefreshAPI != nil && deps.db != nil {
		walStore := service.NewPostgresOAuthRefreshWALStore(deps.db)
		refreshWAL := service.NewBerthOAuthRefreshWAL(walStore, cageService)
		deps.oAuthRefreshAPI.SetRefreshWAL(refreshWAL)
	}

	// Track B: Adaptive Concurrency Advisor + CNProvider Steward RBAC.
	concurrencyAdvisor := service.NewBerthConcurrencyAdvisor(deps.db)
	if managedAdmin, ok := deps.adminService.(interface {
		SetConcurrencyAdvisor(*service.BerthConcurrencyAdvisor)
	}); ok {
		managedAdmin.SetConcurrencyAdvisor(concurrencyAdvisor)
	}
	if deps.cnProviderHandler != nil && deps.stewardStore != nil {
		deps.cnProviderHandler.SetStewards(deps.stewardStore)
	}
	if deps.handlers != nil {
		deps.handlers.BerthConcurrency = handler.NewBerthConcurrencyHandler(concurrencyAdvisor, deps.stewardStore)
	}
	if deps.db != nil {
		ctx, cancel := context.WithCancel(context.Background())
		concurrencyAdvisor.Start(ctx)
		cleanups = append(cleanups, func() {
			cancel()
			concurrencyAdvisor.Stop()
		})
	}

	// Track C: Marketplace crash-safe online payment closure & 15s reconciler.
	if deps.db != nil && deps.marketplace != nil && deps.paymentService != nil && deps.paymentConfigService != nil && deps.handlers != nil && deps.handlers.Marketplace != nil {
		marketplacePayment := service.NewMarketplacePaymentService(
			deps.db,
			deps.marketplace,
			deps.paymentService,
			deps.paymentConfigService,
		)
		deps.handlers.Marketplace.SetMarketplacePayment(marketplacePayment)
	}

	// Track D: MeshHarbor Logical Zones, Admin Landing Node Grants & Edge Lease Hub.
	if deps.db != nil && deps.handlers != nil {
		pub, priv, err := loadOrGenerateBerthEdgeSigningKey(deps.cfg)
		if err != nil {
			runCleanup()
			return nil, fmt.Errorf("berth-v2 edge signing key: %w", err)
		}
		keyID := edgeproto.KeyIDFromPublicKey(pub)
		zoneService := service.NewBerthZoneService(deps.db)
		grantService := service.NewBerthLandingGrantService(deps.db)
		edgeLeaseService := service.NewBerthEdgeLeaseService(deps.db, zoneService, grantService, pub, priv, keyID)
		deps.handlers.BerthEdge = handler.NewBerthEdgeHandler(zoneService, grantService, edgeLeaseService)
	}

	return runCleanup, nil
}

func loadOrGenerateBerthEdgeSigningKey(cfg *config.Config) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if rawEnv := strings.TrimSpace(os.Getenv("BERTH_EDGE_SIGNING_PRIVATE_KEY")); rawEnv != "" {
		raw, err := base64.RawURLEncoding.DecodeString(rawEnv)
		if err != nil {
			raw, err = base64.StdEncoding.DecodeString(rawEnv)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("decode BERTH_EDGE_SIGNING_PRIVATE_KEY: %w", err)
		}
		switch len(raw) {
		case ed25519.SeedSize:
			priv := ed25519.NewKeyFromSeed(raw)
			return priv.Public().(ed25519.PublicKey), priv, nil
		case ed25519.PrivateKeySize:
			priv := ed25519.PrivateKey(raw)
			return priv.Public().(ed25519.PublicKey), priv, nil
		default:
			return nil, nil, fmt.Errorf("unexpected Ed25519 key length %d", len(raw))
		}
	}

	keyPath := strings.TrimSpace(os.Getenv("BERTH_EDGE_SIGNING_KEY_FILE"))
	if keyPath == "" && cfg != nil && strings.TrimSpace(cfg.Pricing.DataDir) != "" {
		keyPath = filepath.Join(cfg.Pricing.DataDir, "berth-edge-signing.key")
	}
	if keyPath != "" {
		if data, err := os.ReadFile(keyPath); err == nil {
			trimmed := strings.TrimSpace(string(data))
			if raw, decErr := base64.RawURLEncoding.DecodeString(trimmed); decErr == nil && len(raw) == ed25519.SeedSize {
				priv := ed25519.NewKeyFromSeed(raw)
				return priv.Public().(ed25519.PublicKey), priv, nil
			}
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if keyPath != "" {
		if mkErr := os.MkdirAll(filepath.Dir(keyPath), 0o700); mkErr == nil {
			encoded := base64.RawURLEncoding.EncodeToString(priv.Seed())
			if wrErr := os.WriteFile(keyPath, []byte(encoded+"\n"), 0o600); wrErr != nil {
				log.Printf("Warning: unable to persist Berth Edge signing key to %s: %v", keyPath, wrErr)
			}
		}
	}
	return pub, priv, nil
}
