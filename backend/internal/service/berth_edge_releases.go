package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	EnvEdgeReleaseDir     = "BERTH_EDGE_RELEASE_DIR"
	DefaultEdgeReleaseDir = "/app/data/edge-releases"
)

// EdgeBinaryRelease describes a staged berth-edge binary served by Berth Central
// to authenticated edge nodes for SHA-256-verified self-update.
type EdgeBinaryRelease struct {
	OS           string    `json:"os"`
	Arch         string    `json:"arch"`
	Version      string    `json:"version"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	UpdatedAt    time.Time `json:"updated_at"`
	DownloadPath string    `json:"download_path"`
}

type edgeReleaseCacheEntry struct {
	size    int64
	modNano int64
	verMod  int64
	release EdgeBinaryRelease
}

var (
	edgeReleaseCacheMu sync.RWMutex
	edgeReleaseCache   = map[string]edgeReleaseCacheEntry{}
)

// ResolveEdgeReleaseDir returns the configured directory for staged berth-edge binaries.
func ResolveEdgeReleaseDir() string {
	if v := strings.TrimSpace(os.Getenv(EnvEdgeReleaseDir)); v != "" {
		return v
	}
	return DefaultEdgeReleaseDir
}

func validateEdgePlatform(goos, goarch string) (string, string, bool) {
	o := strings.ToLower(strings.TrimSpace(goos))
	a := strings.ToLower(strings.TrimSpace(goarch))
	switch o {
	case "linux", "darwin":
	default:
		return "", "", false
	}
	switch a {
	case "amd64", "arm64":
	default:
		return "", "", false
	}
	return o, a, true
}

// ParseEdgeArchPair splits "linux/amd64" (or defaults to "linux", "amd64").
func ParseEdgeArchPair(raw string) (string, string) {
	parts := strings.Split(strings.TrimSpace(raw), "/")
	if len(parts) == 2 {
		if o, a, ok := validateEdgePlatform(parts[0], parts[1]); ok {
			return o, a
		}
	}
	return "linux", "amd64"
}

// LookupEdgeRelease finds and caches the staged berth-edge binary metadata for (goos, goarch).
// Returns (nil, "", nil) when no binary has been staged for that platform.
func LookupEdgeRelease(dir, goos, goarch string) (*EdgeBinaryRelease, string, error) {
	o, a, ok := validateEdgePlatform(goos, goarch)
	if !ok {
		return nil, "", fmt.Errorf("%w: unsupported edge platform %s/%s", ErrEdgeZoneInvalid, goos, goarch)
	}
	if strings.TrimSpace(dir) == "" {
		dir = ResolveEdgeReleaseDir()
	}
	binPath := filepath.Join(dir, fmt.Sprintf("berth-edge-%s-%s", o, a))
	st, err := os.Stat(binPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil
		}
		return nil, "", err
	}
	if st.IsDir() || st.Size() == 0 {
		return nil, "", nil
	}

	verPath := binPath + ".version"
	var verMod int64
	if vst, verr := os.Stat(verPath); verr == nil && !vst.IsDir() {
		verMod = vst.ModTime().UnixNano()
	}

	edgeReleaseCacheMu.RLock()
	cached, found := edgeReleaseCache[binPath]
	edgeReleaseCacheMu.RUnlock()
	if found && cached.size == st.Size() && cached.modNano == st.ModTime().UnixNano() && cached.verMod == verMod {
		cp := cached.release
		return &cp, binPath, nil
	}

	f, err := os.Open(binPath)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))

	ver := "sha256:" + sum[:12]
	if rawVer, verr := os.ReadFile(verPath); verr == nil {
		if trimmed := strings.TrimSpace(string(rawVer)); trimmed != "" {
			ver = trimmed
		}
	}

	rel := EdgeBinaryRelease{
		OS:           o,
		Arch:         a,
		Version:      ver,
		SHA256:       sum,
		Size:         st.Size(),
		UpdatedAt:    st.ModTime().UTC(),
		DownloadPath: fmt.Sprintf("/api/v1/internal/edge/binary/%s/%s", o, a),
	}
	edgeReleaseCacheMu.Lock()
	edgeReleaseCache[binPath] = edgeReleaseCacheEntry{
		size:    st.Size(),
		modNano: st.ModTime().UnixNano(),
		verMod:  verMod,
		release: rel,
	}
	edgeReleaseCacheMu.Unlock()
	return &rel, binPath, nil
}

// ListEdgeReleases enumerates all staged berth-edge binaries currently available in dir.
func ListEdgeReleases(dir string) []EdgeBinaryRelease {
	platforms := [][2]string{
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"darwin", "arm64"},
		{"darwin", "amd64"},
	}
	out := make([]EdgeBinaryRelease, 0, len(platforms))
	for _, p := range platforms {
		if rel, _, err := LookupEdgeRelease(dir, p[0], p[1]); err == nil && rel != nil {
			out = append(out, *rel)
		}
	}
	return out
}
