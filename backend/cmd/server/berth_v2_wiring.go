package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
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

func validateBerthV2Deps(deps berthV2Deps) error {
	var missing []string
	if deps.db == nil {
		missing = append(missing, "db")
	}
	if deps.adminService == nil {
		missing = append(missing, "adminService")
	}
	if deps.oAuthRefreshAPI == nil {
		missing = append(missing, "oAuthRefreshAPI")
	}
	if deps.marketplace == nil {
		missing = append(missing, "marketplace")
	}
	if deps.paymentService == nil {
		missing = append(missing, "paymentService")
	}
	if deps.paymentConfigService == nil {
		missing = append(missing, "paymentConfigService")
	}
	if deps.stewardStore == nil {
		missing = append(missing, "stewardStore")
	}
	if deps.cnProviderHandler == nil {
		missing = append(missing, "cnProviderHandler")
	}
	if deps.handlers == nil {
		missing = append(missing, "handlers")
	} else if deps.handlers.Marketplace == nil {
		missing = append(missing, "handlers.Marketplace")
	}
	if len(missing) > 0 {
		return fmt.Errorf("berth-v2 wiring failed: missing required dependencies: %s", strings.Join(missing, ", "))
	}
	return nil
}

// wireBerthV2 initializes all Berth v2 subsystems (Account Cage + WAL Refresh,
// Adaptive Concurrency Advisor, Marketplace Online Payment Closure, and
// MeshHarbor-style Zones / Admin Landing Grants / Edge Session Leases) via a
// single clean bootstrap outside wire_gen.go so future Sub2API merges stay thin.
// Fails closed at startup if any required production dependency is missing.
func wireBerthV2(deps berthV2Deps) (func(), error) {
	if err := validateBerthV2Deps(deps); err != nil {
		return nil, err
	}

	var cleanups []func()
	runCleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	// Track A: Account Cage + OAuth Refresh WAL journal.
	cagePool := cage.NewCageTransportPool()
	cageService := service.NewBerthAccountCageService(deps.db, cagePool)
	walStore := service.NewPostgresOAuthRefreshWALStore(deps.db)
	refreshWAL := service.NewBerthOAuthRefreshWAL(walStore, cageService)
	deps.oAuthRefreshAPI.SetRefreshWAL(refreshWAL)

	// Track B: Adaptive Concurrency Advisor + CNProvider Steward RBAC.
	concurrencyAdvisor := service.NewBerthConcurrencyAdvisor(deps.db)
	managedAdmin, ok := deps.adminService.(interface {
		SetConcurrencyAdvisor(*service.BerthConcurrencyAdvisor)
	})
	if !ok {
		runCleanup()
		return nil, errors.New("berth-v2 wiring failed: adminService does not implement SetConcurrencyAdvisor")
	}
	managedAdmin.SetConcurrencyAdvisor(concurrencyAdvisor)
	deps.cnProviderHandler.SetStewards(deps.stewardStore)
	deps.handlers.BerthConcurrency = handler.NewBerthConcurrencyHandler(concurrencyAdvisor, deps.stewardStore)

	ctx, cancel := context.WithCancel(context.Background())
	concurrencyAdvisor.Start(ctx)
	cleanups = append(cleanups, func() {
		cancel()
		concurrencyAdvisor.Stop()
	})

	// Track C: Marketplace crash-safe online payment closure & 15s reconciler.
	marketplacePayment := service.NewMarketplacePaymentService(
		deps.db,
		deps.marketplace,
		deps.paymentService,
		deps.paymentConfigService,
	)
	deps.handlers.Marketplace.SetMarketplacePayment(marketplacePayment)

	// Track D: MeshHarbor Logical Zones, Admin Landing Node Grants & Edge Lease Hub.
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
	deps.handlers.BerthEdge.SetAccountLookup(deps.adminService)

	return runCleanup, nil
}

func parseEd25519KeyBytes(raw []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	switch len(raw) {
	case ed25519.SeedSize:
		priv := ed25519.NewKeyFromSeed(raw)
		return priv.Public().(ed25519.PublicKey), priv, nil
	case ed25519.PrivateKeySize:
		// Reconstruct from seed and reject mismatched public halves (Codex Review Medium).
		reconstructed := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !bytes.Equal(reconstructed[ed25519.SeedSize:], raw[ed25519.SeedSize:]) {
			return nil, nil, errors.New("inconsistent 64-byte Ed25519 private key: embedded public key does not match seed")
		}
		return reconstructed.Public().(ed25519.PublicKey), reconstructed, nil
	default:
		return nil, nil, fmt.Errorf("unexpected Ed25519 key length %d", len(raw))
	}
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
		return parseEd25519KeyBytes(raw)
	}

	keyPath := strings.TrimSpace(os.Getenv("BERTH_EDGE_SIGNING_KEY_FILE"))
	if keyPath == "" && cfg != nil && strings.TrimSpace(cfg.Pricing.DataDir) != "" {
		keyPath = filepath.Join(cfg.Pricing.DataDir, "berth-edge-signing.key")
	}
	if keyPath != "" {
		if data, err := os.ReadFile(keyPath); err == nil {
			trimmed := strings.TrimSpace(string(data))
			raw, decErr := base64.RawURLEncoding.DecodeString(trimmed)
			if decErr != nil {
				raw, decErr = base64.StdEncoding.DecodeString(trimmed)
			}
			if decErr != nil {
				return nil, nil, fmt.Errorf("decode key file %s: %w", keyPath, decErr)
			}
			return parseEd25519KeyBytes(raw)
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
