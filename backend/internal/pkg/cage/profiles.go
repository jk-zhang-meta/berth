package cage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jk-zhang-meta/berth/internal/pkg/httpwire"
	utls "github.com/refraction-networking/utls"
)

const (
	PlaneOAuth     = "oauth"
	PlaneInference = "inference"
	PlaneUnified   = "unified"

	ALPNModeNone             = "none"
	ALPNModeHTTP1Only        = "http1_only"
	ALPNModeFollowNegotiated = "follow_negotiated"

	// Pinned uTLS presets (Codex Review Gate: NO floating HelloChrome_Auto).
	PresetClaudeNode24OAuth       = "claude_node24_oauth"
	PresetClaudeNode24Inference   = "claude_node24_inference"
	PresetClaudeNode24CountTokens = "claude_node24_count_tokens"
	PresetCodexChromePinned       = "codex_chrome_pinned"
)

// H2Setting represents one HTTP/2 SETTINGS frame parameter.
type H2Setting struct {
	ID  uint16 `json:"id"`
	Val uint32 `json:"val"`
}

// TLSProfileSpec describes a pinned per-plane uTLS + H2 + HTTP/1.1 header-order profile.
type TLSProfileSpec struct {
	Preset            string      `json:"preset"`
	Provider          string      `json:"provider"`
	Plane             string      `json:"plane"`
	ALPNMode          string      `json:"alpn_mode"`
	EnablePSKCache    bool        `json:"enable_psk_cache"`
	HeaderOrderPreset string      `json:"header_order_preset"`
	H2Settings        []H2Setting `json:"h2_settings,omitempty"`
	H2WindowUpdate    uint32      `json:"h2_window_update,omitempty"`
	H2PseudoOrder     []string    `json:"h2_pseudo_order,omitempty"`
	PinnedSpecVersion string      `json:"pinned_spec_version"`
}

// ProfileHash computes a deterministic 64-hex SHA-256 fingerprint of this profile
// for use as part of the composite CageTransport pool cache key.
func (p *TLSProfileSpec) ProfileHash() string {
	if p == nil {
		return ""
	}
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Node.js 24 / OpenSSL 17-cipher suite list (exact JA3 wire order).
var claudeNode24CipherSuites = []uint16{
	0x1301, // TLS_AES_128_GCM_SHA256
	0x1302, // TLS_AES_256_GCM_SHA384
	0x1303, // TLS_CHACHA20_POLY1305_SHA256
	0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
	0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
	0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
}

var claudeNode24Curves = []utls.CurveID{
	utls.X25519,
	utls.CurveP256,
	utls.CurveP384,
}

var claudeNode24SigAlgs = []utls.SignatureScheme{
	0x0403, // ecdsa_secp256r1_sha256
	0x0804, // rsa_pss_rsae_sha256
	0x0401, // rsa_pkcs1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0805, // rsa_pss_rsae_sha384
	0x0501, // rsa_pkcs1_sha384
	0x0806, // rsa_pss_rsae_sha512
	0x0601, // rsa_pkcs1_sha512
	0x0201, // rsa_pkcs1_sha1
}

// ProfileForPreset returns a fresh copy of the pinned TLSProfileSpec for a preset name.
func ProfileForPreset(preset string) (*TLSProfileSpec, error) {
	switch strings.TrimSpace(preset) {
	case PresetClaudeNode24OAuth:
		return &TLSProfileSpec{
			Preset:            PresetClaudeNode24OAuth,
			Provider:          "anthropic",
			Plane:             PlaneOAuth,
			ALPNMode:          ALPNModeNone,
			EnablePSKCache:    true,
			HeaderOrderPreset: httpwire.PresetClaudeOAuthAxios115,
			PinnedSpecVersion: "node24-openssl-noalpn-psk-v1",
		}, nil

	case PresetClaudeNode24Inference:
		return &TLSProfileSpec{
			Preset:            PresetClaudeNode24Inference,
			Provider:          "anthropic",
			Plane:             PlaneInference,
			ALPNMode:          ALPNModeHTTP1Only,
			EnablePSKCache:    true,
			HeaderOrderPreset: httpwire.PresetClaudeMessagesV2,
			PinnedSpecVersion: "node24-openssl-h1-ocsp-sct-pad-psk-v1",
		}, nil

	case PresetClaudeNode24CountTokens:
		return &TLSProfileSpec{
			Preset:            PresetClaudeNode24CountTokens,
			Provider:          "anthropic",
			Plane:             PlaneInference,
			ALPNMode:          ALPNModeHTTP1Only,
			EnablePSKCache:    true,
			HeaderOrderPreset: httpwire.PresetClaudeCountTokensV2,
			PinnedSpecVersion: "node24-openssl-h1-ocsp-sct-pad-psk-v1",
		}, nil

	case PresetCodexChromePinned:
		return &TLSProfileSpec{
			Preset:            PresetCodexChromePinned,
			Provider:          "openai",
			Plane:             PlaneUnified,
			ALPNMode:          ALPNModeFollowNegotiated,
			EnablePSKCache:    true,
			HeaderOrderPreset: httpwire.PresetCodexCLIRS,
			H2Settings: []H2Setting{
				{ID: 1, Val: 65536},
				{ID: 2, Val: 0},
				{ID: 4, Val: 6291456},
				{ID: 6, Val: 262144},
			},
			H2WindowUpdate:    15663105,
			H2PseudoOrder:     []string{":method", ":authority", ":scheme", ":path"},
			PinnedSpecVersion: "chrome-133-pinned-v1",
		}, nil

	default:
		return nil, fmt.Errorf("cage: unknown pinned uTLS preset %q", preset)
	}
}

// BuildClientHelloSpec constructs a fresh pinned utls.ClientHelloSpec per handshake.
// A fresh spec is built each time because uTLS mutates KeyShare/PSK extensions in-place.
func BuildClientHelloSpec(preset string) (*utls.ClientHelloSpec, error) {
	switch strings.TrimSpace(preset) {
	case PresetClaudeNode24OAuth:
		// 17 ciphers, NO ALPN, NO GREASE/SCT/OCSP, WITH TLS 1.3 PSK (OmitEmptyPsk).
		ciphers := append([]uint16(nil), claudeNode24CipherSuites...)
		return &utls.ClientHelloSpec{
			CipherSuites:       ciphers,
			CompressionMethods: []uint8{0},
			TLSVersMax:         utls.VersionTLS13,
			TLSVersMin:         utls.VersionTLS12,
			Extensions: []utls.TLSExtension{
				&utls.SNIExtension{},
				&utls.ExtendedMasterSecretExtension{},
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
				&utls.SupportedCurvesExtension{Curves: append([]utls.CurveID(nil), claudeNode24Curves...)},
				&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
				&utls.SessionTicketExtension{},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: append([]utls.SignatureScheme(nil), claudeNode24SigAlgs...)},
				&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
				&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
				&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
				&utls.UtlsPreSharedKeyExtension{},
			},
		}, nil

	case PresetClaudeNode24Inference, PresetClaudeNode24CountTokens:
		// 17 ciphers, ALPN ["http/1.1"], StatusRequest (OCSP), SCT, BoringPadding, PSK.
		ciphers := append([]uint16(nil), claudeNode24CipherSuites...)
		return &utls.ClientHelloSpec{
			CipherSuites:       ciphers,
			CompressionMethods: []uint8{0},
			TLSVersMax:         utls.VersionTLS13,
			TLSVersMin:         utls.VersionTLS12,
			Extensions: []utls.TLSExtension{
				&utls.SNIExtension{},
				&utls.ExtendedMasterSecretExtension{},
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
				&utls.SupportedCurvesExtension{Curves: append([]utls.CurveID(nil), claudeNode24Curves...)},
				&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
				&utls.SessionTicketExtension{},
				&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
				&utls.StatusRequestExtension{},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: append([]utls.SignatureScheme(nil), claudeNode24SigAlgs...)},
				&utls.SCTExtension{},
				&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
				&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
				&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
				&utls.UtlsPreSharedKeyExtension{},
			},
		}, nil

	case PresetCodexChromePinned:
		// Strictly pinned Chrome 133 ClientHelloSpec (never floating HelloChrome_Auto).
		spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
		if err != nil {
			return nil, fmt.Errorf("cage: build pinned chrome spec: %w", err)
		}
		return &spec, nil

	default:
		return nil, fmt.Errorf("cage: unknown pinned uTLS preset %q", preset)
	}
}
