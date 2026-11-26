package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EdgeReleaseInfo mirrors Berth Central's staged berth-edge binary descriptor.
type EdgeReleaseInfo struct {
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Version      string `json:"version"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	DownloadPath string `json:"download_path"`
}

// ComputeFileSHA256 computes the lowercase hex SHA-256 digest of filePath.
func ComputeFileSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeSelfSHA256 returns the resolved executable path and SHA-256 digest of the running binary.
func ComputeSelfSHA256() (string, string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	if resolved, rErr := filepath.EvalSymlinks(exe); rErr == nil {
		exe = resolved
	}
	sum, err := ComputeFileSHA256(exe)
	if err != nil {
		return exe, "", err
	}
	return exe, sum, nil
}

// SelfUpdater performs SHA-256-verified atomic in-place upgrades of the berth-edge binary
// when Berth Central advertises a newer staged release matching this host's OS/arch.
type SelfUpdater struct {
	exePath       string
	selfSHA256    string
	verifyCommand func(ctx context.Context, candidatePath string) error

	mu            sync.Mutex
	inProgress    bool
	failedSHA256  string
	nextRetryAt   time.Time
	failCount     int
}

// NewSelfUpdater constructs a SelfUpdater for exePath with current digest selfSHA256.
func NewSelfUpdater(exePath, selfSHA256 string) *SelfUpdater {
	return &SelfUpdater{
		exePath:       exePath,
		selfSHA256:    strings.ToLower(strings.TrimSpace(selfSHA256)),
		verifyCommand: defaultVerifyEdgeBinary,
	}
}

func defaultVerifyEdgeBinary(ctx context.Context, candidatePath string) error {
	vctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(vctx, candidatePath, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("candidate --version smoke check failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if !strings.Contains(strings.ToLower(string(out)), "berth-edge") {
		return fmt.Errorf("candidate --version output unexpected: %q", strings.TrimSpace(string(out)))
	}
	return nil
}

// MaybeUpdate downloads, SHA-256 verifies, smoke-checks, and atomically swaps exePath when
// rel advertises a different SHA-256 than selfSHA256. Calls onApplied after atomic swap succeeds.
func (u *SelfUpdater) MaybeUpdate(
	ctx context.Context,
	rel *EdgeReleaseInfo,
	download func(ctx context.Context, downloadPath string, dst io.Writer) error,
	onApplied func(),
) (bool, error) {
	if u == nil || rel == nil || u.exePath == "" || u.selfSHA256 == "" || download == nil {
		return false, nil
	}
	wantSHA := strings.ToLower(strings.TrimSpace(rel.SHA256))
	if wantSHA == "" || wantSHA == u.selfSHA256 || strings.TrimSpace(rel.DownloadPath) == "" {
		return false, nil
	}

	u.mu.Lock()
	if u.inProgress {
		u.mu.Unlock()
		return false, nil
	}
	if u.failedSHA256 == wantSHA && time.Now().Before(u.nextRetryAt) {
		u.mu.Unlock()
		return false, nil
	}
	u.inProgress = true
	u.mu.Unlock()

	defer func() {
		u.mu.Lock()
		u.inProgress = false
		u.mu.Unlock()
	}()

	err := u.apply(ctx, rel, wantSHA, download)
	if err != nil {
		u.mu.Lock()
		if u.failedSHA256 != wantSHA {
			u.failedSHA256 = wantSHA
			u.failCount = 1
		} else {
			u.failCount++
		}
		backoff := time.Minute
		if u.failCount == 2 {
			backoff = 5 * time.Minute
		} else if u.failCount >= 3 {
			backoff = 15 * time.Minute
		}
		u.nextRetryAt = time.Now().Add(backoff)
		u.mu.Unlock()
		return false, err
	}

	u.mu.Lock()
	u.selfSHA256 = wantSHA
	u.failedSHA256 = ""
	u.failCount = 0
	u.mu.Unlock()

	log.Printf("berth-edge auto-update applied: version=%s sha256=%s path=%s", rel.Version, wantSHA[:12], u.exePath)
	if onApplied != nil {
		onApplied()
	}
	return true, nil
}

func (u *SelfUpdater) apply(
	ctx context.Context,
	rel *EdgeReleaseInfo,
	wantSHA string,
	download func(ctx context.Context, downloadPath string, dst io.Writer) error,
) error {
	dir := filepath.Dir(u.exePath)
	tmp, err := os.CreateTemp(dir, ".berth-edge-update-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	mw := io.MultiWriter(tmp, hasher)
	dlCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	dlErr := download(dlCtx, rel.DownloadPath, mw)
	cancel()
	closeErr := tmp.Close()
	if dlErr != nil {
		return fmt.Errorf("download %s: %w", rel.DownloadPath, dlErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close temp file: %w", closeErr)
	}

	gotSHA := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(gotSHA, wantSHA) {
		return fmt.Errorf("sha256 mismatch: want %s got %s", wantSHA, gotSHA)
	}

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return fmt.Errorf("chmod candidate: %w", err)
	}
	if u.verifyCommand != nil {
		if err := u.verifyCommand(ctx, tmpPath); err != nil {
			return err
		}
	}

	if err := os.Rename(tmpPath, u.exePath); err != nil {
		return fmt.Errorf("atomic rename %s -> %s: %w", tmpPath, u.exePath, err)
	}
	cleanup = false
	return nil
}

// ErrDownloadFailed indicates a non-200 HTTP response from Central binary endpoint.
var ErrDownloadFailed = errors.New("edge: binary download failed")
