// Package edge implements the standalone lightweight berth-edge multi-role daemon
// (ingress_relay, transit, landing, compat, mgmt_entry) with zero heavy server deps.
package edge

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	RoleIngressRelay = "ingress_relay"
	RoleTransit      = "transit"
	RoleLanding      = "landing"
	RoleCompat       = "compat"
	RoleMgmtEntry    = "mgmt_entry"

	DefaultGrantSliceBytes   int64 = 16 * 1024 * 1024
	DefaultGrantLowWatermark int64 = 4 * 1024 * 1024
	DefaultPreDebitChunkSize int64 = 32 * 1024
)

// Config holds declarative configuration for a berth-edge daemon instance.
// Compatible with both YAML and JSON files via gopkg.in/yaml.v3.
type Config struct {
	NodeID                 int64         `yaml:"node_id" json:"node_id"`
	NodeName               string        `yaml:"node_name" json:"node_name"`
	Roles                  []string      `yaml:"roles" json:"roles"`
	CentralURL             string        `yaml:"central_url" json:"central_url"`
	CentralPubKey          string        `yaml:"central_pubkey" json:"central_pubkey"`
	NodePrivateKey         string        `yaml:"node_private_key" json:"node_private_key"`
	NodePrivateKeyFile     string        `yaml:"node_private_key_file" json:"node_private_key_file"`
	ListenAddr             string        `yaml:"listen_addr" json:"listen_addr"`
	MgmtEntryListenAddr    string        `yaml:"mgmt_entry_listen_addr" json:"mgmt_entry_listen_addr"`
	MgmtCentralTarget      string        `yaml:"mgmt_central_target" json:"mgmt_central_target"`
	ReverseTunnelHubAddr   string        `yaml:"reverse_tunnel_hub_addr" json:"reverse_tunnel_hub_addr"`
	ReverseTunnelDialAddr  string        `yaml:"reverse_tunnel_dial_addr" json:"reverse_tunnel_dial_addr"`
	WALDir                 string        `yaml:"wal_dir" json:"wal_dir"`
	HeartbeatInterval      time.Duration `yaml:"heartbeat_interval" json:"heartbeat_interval"`
	GrantSliceBytes        int64         `yaml:"grant_slice_bytes" json:"grant_slice_bytes"`
	GrantLowWatermark      int64         `yaml:"grant_low_watermark" json:"grant_low_watermark"`
	PreDebitChunkSize      int64         `yaml:"pre_debit_chunk_size" json:"pre_debit_chunk_size"`
	MaxConcurrentStreams   int           `yaml:"max_concurrent_streams" json:"max_concurrent_streams"`
	AllowedUpstreamHosts   []string      `yaml:"allowed_upstream_hosts" json:"allowed_upstream_hosts"`
	TestAllowLoopbackHosts []string      `yaml:"test_allow_loopback_hosts" json:"test_allow_loopback_hosts"`
	DefaultUpstreamBaseURL string        `yaml:"default_upstream_base_url" json:"default_upstream_base_url"`
	PeerPublicKeys         map[int64]string `yaml:"peer_public_keys" json:"peer_public_keys"`
}

// LoadConfig reads a YAML or JSON config file and applies sane 1C1G defaults.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("edge: parse config %s: %w", path, err)
	}
	cfg.ApplyDefaults()
	return &cfg, nil
}

// ApplyDefaults populates safe 1C1G defaults for unset fields.
func (c *Config) ApplyDefaults() {
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = 15 * time.Second
	}
	if c.GrantSliceBytes <= 0 {
		c.GrantSliceBytes = DefaultGrantSliceBytes
	}
	if c.GrantLowWatermark <= 0 {
		c.GrantLowWatermark = min(DefaultGrantLowWatermark, c.GrantSliceBytes/4)
	}
	if c.PreDebitChunkSize <= 0 {
		c.PreDebitChunkSize = DefaultPreDebitChunkSize
	}
	if c.MaxConcurrentStreams <= 0 {
		c.MaxConcurrentStreams = 256
	}
	if c.MgmtEntryListenAddr == "" && c.HasRole(RoleMgmtEntry) {
		c.MgmtEntryListenAddr = ":18443"
	}
}

// HasRole reports whether this node runs the specified role.
func (c *Config) HasRole(role string) bool {
	return slices.Contains(c.Roles, role)
}

// ParseEd25519PrivateKey decodes a 32-byte seed or 64-byte private key from base64url/base64/hex.
func ParseEd25519PrivateKey(raw string) (ed25519.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("edge: empty ed25519 private key")
	}
	for _, dec := range []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		hex.DecodeString,
	} {
		b, err := dec(raw)
		if err != nil {
			continue
		}
		switch len(b) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(b), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(b), nil
		}
	}
	return nil, errors.New("edge: invalid ed25519 private key encoding")
}

// ParseEd25519PublicKey decodes a 32-byte Ed25519 public key from base64url/base64/hex.
func ParseEd25519PublicKey(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("edge: empty ed25519 public key")
	}
	for _, dec := range []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		hex.DecodeString,
	} {
		b, err := dec(raw)
		if err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, errors.New("edge: invalid ed25519 public key encoding")
}
