package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestEdgeServer_ApplyRuntimeRolesHotToggle(t *testing.T) {
	srv, err := NewEdgeServer(EdgeServerOptions{
		Config: &Config{
			NodeID:   7,
			NodeName: "hyonix-sg",
			Roles:    []string{RoleIngressRelay, RoleTransit},
		},
	})
	if err != nil {
		t.Fatalf("new edge server: %v", err)
	}
	if srv.HasRole(RoleLanding) {
		t.Fatalf("expected landing role initially disabled")
	}
	if !srv.HasRole(RoleTransit) {
		t.Fatalf("expected transit role initially enabled")
	}

	// Hot-enable landing role (as pushed from Central heartbeat after Admin toggles Landing).
	if !srv.ApplyRuntimeRoles([]string{RoleIngressRelay, RoleTransit, RoleLanding}) {
		t.Fatalf("expected ApplyRuntimeRoles to report change")
	}
	if !srv.HasRole(RoleLanding) {
		t.Fatalf("expected landing role hot-enabled")
	}

	// Identical role set is a no-op.
	if srv.ApplyRuntimeRoles([]string{RoleIngressRelay, RoleTransit, RoleLanding}) {
		t.Fatalf("expected identical role set to return changed=false")
	}

	// Hot-disable landing role.
	if !srv.ApplyRuntimeRoles([]string{RoleIngressRelay, RoleTransit}) {
		t.Fatalf("expected landing removal to report change")
	}
	if srv.HasRole(RoleLanding) {
		t.Fatalf("expected landing role hot-disabled")
	}
}

func TestSelfUpdater_SHA256VerifiedAtomicSwapAndMismatchReject(t *testing.T) {
	dir := t.TempDir()
	exePath := filepath.Join(dir, "berth-edge")
	initialPayload := []byte("berth-edge-v1-binary")
	if err := os.WriteFile(exePath, initialPayload, 0o755); err != nil {
		t.Fatalf("write initial exe: %v", err)
	}
	initSum, err := ComputeFileSHA256(exePath)
	if err != nil {
		t.Fatalf("compute initial sha: %v", err)
	}

	updater := NewSelfUpdater(exePath, initSum)
	updater.verifyCommand = func(_ context.Context, _ string) error { return nil }

	// 1. Mismatched SHA-256 MUST fail closed and leave original binary untouched!
	badPayload := []byte("corrupted-payload")
	applied := false
	updated, err := updater.MaybeUpdate(
		context.Background(),
		&EdgeReleaseInfo{
			Version:      "2.1.0-edge",
			SHA256:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			DownloadPath: "/api/v1/internal/edge/binary/linux/amd64",
		},
		func(_ context.Context, _ string, dst io.Writer) error {
			_, werr := dst.Write(badPayload)
			return werr
		},
		func() { applied = true },
	)
	if err == nil || updated || applied {
		t.Fatalf("expected sha mismatch rejection, got updated=%v applied=%v err=%v", updated, applied, err)
	}
	cur, _ := os.ReadFile(exePath)
	if string(cur) != string(initialPayload) {
		t.Fatalf("original binary was modified on mismatch!")
	}

	// 2. Exact matching SHA-256 MUST atomically swap binary and invoke onApplied!
	newPayload := []byte("berth-edge-v2-binary-verified")
	sumBytes := sha256.Sum256(newPayload)
	newSum := hex.EncodeToString(sumBytes[:])
	updated, err = updater.MaybeUpdate(
		context.Background(),
		&EdgeReleaseInfo{
			Version:      "2.1.0-edge",
			SHA256:       newSum,
			DownloadPath: "/api/v1/internal/edge/binary/linux/amd64",
		},
		func(_ context.Context, _ string, dst io.Writer) error {
			_, werr := dst.Write(newPayload)
			return werr
		},
		func() { applied = true },
	)
	if err != nil || !updated || !applied {
		t.Fatalf("expected verified swap to succeed, got updated=%v applied=%v err=%v", updated, applied, err)
	}
	cur, _ = os.ReadFile(exePath)
	if string(cur) != string(newPayload) {
		t.Fatalf("expected swapped binary content, got %q", string(cur))
	}

	// 3. Re-invoking with the same SHA-256 is an immediate no-op!
	applied = false
	updated, err = updater.MaybeUpdate(
		context.Background(),
		&EdgeReleaseInfo{
			Version:      "2.1.0-edge",
			SHA256:       newSum,
			DownloadPath: "/api/v1/internal/edge/binary/linux/amd64",
		},
		func(_ context.Context, _ string, _ io.Writer) error {
			t.Fatalf("download should not be called when already up-to-date")
			return nil
		},
		func() { applied = true },
	)
	if err != nil || updated || applied {
		t.Fatalf("expected no-op when already on target sha, got updated=%v applied=%v err=%v", updated, applied, err)
	}
}
