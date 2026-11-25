package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestWireBerthV2_FailsClosedOnMissingDependencies(t *testing.T) {
	cleanup, err := wireBerthV2(berthV2Deps{})
	if err == nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("expected wireBerthV2 to fail when required dependencies are nil")
	}
	for _, want := range []string{"db", "adminService", "oAuthRefreshAPI", "marketplace", "paymentService", "stewardStore", "handlers"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to mention missing %q, got: %v", want, err)
		}
	}
}

func TestLoadOrGenerateBerthEdgeSigningKey_RejectsInconsistent64ByteKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	corrupted := make([]byte, ed25519.PrivateKeySize)
	copy(corrupted, priv)
	corrupted[ed25519.SeedSize] ^= 0xff // flip public half byte

	t.Setenv("BERTH_EDGE_SIGNING_PRIVATE_KEY", base64.RawURLEncoding.EncodeToString(corrupted))
	if _, _, err := loadOrGenerateBerthEdgeSigningKey(nil); err == nil || !strings.Contains(err.Error(), "inconsistent 64-byte Ed25519") {
		t.Fatalf("expected inconsistent 64-byte key rejection, got: %v", err)
	}

	// Valid 64-byte key must succeed and match reconstructed public key.
	t.Setenv("BERTH_EDGE_SIGNING_PRIVATE_KEY", base64.RawURLEncoding.EncodeToString(priv))
	pub, loaded, err := loadOrGenerateBerthEdgeSigningKey(nil)
	if err != nil {
		t.Fatalf("expected valid 64-byte key to load, got: %v", err)
	}
	if !pub.Equal(priv.Public()) || !loaded.Equal(priv) {
		t.Fatal("loaded key mismatch")
	}
}
