package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/cage"
)

const (
	CageBindingModeExclusive    = "exclusive_1to1"
	CageBindingModeSharedCapped = "shared_capped"

	CageEgressPolicyStrictProxyOnly = "strict_proxy_only"

	CageDNSModeProxyDoHIPv4Only = cage.DNSModeProxyDoHIPv4Only
	CageDNSModeSOCKS5hRemote    = cage.DNSModeSOCKS5hRemote

	CageDriftPolicySameIP      = "same_ip"
	CageDriftPolicySameASNCity = "same_asn_city"
	CageDriftPolicySameCountry = "same_country"

	CageGateStateClosed      = "closed"
	CageGateStateChecking    = "checking"
	CageGateStateOpen        = "open"
	CageGateStateQuarantined = "quarantined"
)

var (
	ErrCageNotFound         = errors.New("account cage not found")
	ErrCageProxyRequired    = errors.New("account cage requires a valid proxy_id > 0")
	ErrCageIPv4AnchorNeeded = errors.New("account cage exit anchor requires a valid IPv4 address")
	ErrCageDriftDetected    = errors.New("account cage exit drift detected")
)

// AccountCage mirrors the PostgreSQL `account_cages` row.
type AccountCage struct {
	ID                    int64
	AccountID             int64
	ProxyID               int64
	LandingBindingMode    string
	EgressPolicy          string
	AllowIPv6             bool
	AllowUDP              bool
	DNSMode               string
	DriftPolicy           string
	Timezone              string
	Locale                string
	AcceptLanguage        string
	OAILanguage           string
	TLSOAuthProfileID     *int64
	TLSInferenceProfileID *int64
	ClientOS              string
	ClientOSVersion       string
	ClientArch            string
	ClientRuntime         string
	ClientRuntimeVersion  string
	ClientAppVersion      string
	UserAgentOAuth        string
	UserAgentInference    string
	Originator            string
	HostnameAlias         string
	ConvergenceSeed       []byte
	ClaudeDeviceID        string
	CodexInstallationID   string
	XAIClientIdentifier   string
	ExtraIdentity         map[string]any
	GateState             string
	GateEpoch             int64
	LeaseExpiresAt        *time.Time
	LastVerifiedAt        *time.Time
	LastError             string
	CredentialVersion     int64
	LockedAt              *time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// AccountCageExitAnchor mirrors the PostgreSQL `account_cage_exit_anchors` row.
type AccountCageExitAnchor struct {
	ID              int64
	CageID          int64
	AnchorVersion   int
	IsActive        bool
	ProxyID         int64
	ExitIP          string
	ExitCountryCode string
	ExitRegion      string
	ExitCity        string
	ExitTimezone    string
	ExitASN         string
	ExitISP         string
	ProbeSource     string
	Reason          string
	AnchoredBy      string
	AnchoredAt      time.Time
}

// GeoIdentity captures geo-aligned linguistic and temporal defaults derived from
// a proxy's verified exit country/timezone (never hardcoded zh-CN).
type GeoIdentity struct {
	Timezone       string
	Locale         string
	AcceptLanguage string
	OAILanguage    string
}

// VirtualClientTuple captures persistent virtual OS/arch/runtime/UA identity for a cage.
type VirtualClientTuple struct {
	ClientOS             string
	ClientOSVersion      string
	ClientArch           string
	ClientRuntime        string
	ClientRuntimeVersion string
	ClientAppVersion     string
	UserAgentOAuth       string
	UserAgentInference   string
	Originator           string
	HostnameAlias        string
}

// ProvisionCageInput specifies inputs to create an account's 1:1 AccountCage.
type ProvisionCageInput struct {
	AccountID             int64
	Platform              string
	ProxyID               int64
	LandingBindingMode    string
	DNSMode               string
	DriftPolicy           string
	ExitCountryCode       string
	ExitTimezone          string
	TLSOAuthProfileID     *int64
	TLSInferenceProfileID *int64
	ConvergenceSeed       []byte // optional 32-byte seed; generated via CSPRNG if empty
}

// UpdateCageInput updates mutable non-locked attributes on an existing cage.
type UpdateCageInput struct {
	DriftPolicy           *string
	DNSMode               *string
	Timezone              *string
	Locale                *string
	AcceptLanguage        *string
	OAILanguage           *string
	TLSOAuthProfileID     *int64
	TLSInferenceProfileID *int64
}

var countryGeoDefaults = map[string]GeoIdentity{
	"US": {Timezone: "America/Los_Angeles", Locale: "en_US.UTF-8", AcceptLanguage: "en-US,en;q=0.9", OAILanguage: "en-US"},
	"GB": {Timezone: "Europe/London", Locale: "en_GB.UTF-8", AcceptLanguage: "en-GB,en;q=0.9", OAILanguage: "en-GB"},
	"CA": {Timezone: "America/Toronto", Locale: "en_CA.UTF-8", AcceptLanguage: "en-CA,en;q=0.9", OAILanguage: "en-CA"},
	"AU": {Timezone: "Australia/Sydney", Locale: "en_AU.UTF-8", AcceptLanguage: "en-AU,en;q=0.9", OAILanguage: "en-AU"},
	"NZ": {Timezone: "Pacific/Auckland", Locale: "en_NZ.UTF-8", AcceptLanguage: "en-NZ,en;q=0.9", OAILanguage: "en-NZ"},
	"SG": {Timezone: "Asia/Singapore", Locale: "en_SG.UTF-8", AcceptLanguage: "en-SG,en;q=0.9", OAILanguage: "en-SG"},
	"IE": {Timezone: "Europe/Dublin", Locale: "en_IE.UTF-8", AcceptLanguage: "en-IE,en;q=0.9", OAILanguage: "en-IE"},
	"JP": {Timezone: "Asia/Tokyo", Locale: "ja_JP.UTF-8", AcceptLanguage: "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7", OAILanguage: "ja-JP"},
	"KR": {Timezone: "Asia/Seoul", Locale: "ko_KR.UTF-8", AcceptLanguage: "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7", OAILanguage: "ko-KR"},
	"TW": {Timezone: "Asia/Taipei", Locale: "zh_TW.UTF-8", AcceptLanguage: "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7", OAILanguage: "zh-TW"},
	"HK": {Timezone: "Asia/Hong_Kong", Locale: "en_HK.UTF-8", AcceptLanguage: "en-HK,en;q=0.9,zh-HK;q=0.8", OAILanguage: "en-HK"},
	"DE": {Timezone: "Europe/Berlin", Locale: "de_DE.UTF-8", AcceptLanguage: "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7", OAILanguage: "de-DE"},
	"FR": {Timezone: "Europe/Paris", Locale: "fr_FR.UTF-8", AcceptLanguage: "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", OAILanguage: "fr-FR"},
	"NL": {Timezone: "Europe/Amsterdam", Locale: "nl_NL.UTF-8", AcceptLanguage: "nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7", OAILanguage: "nl-NL"},
	"ES": {Timezone: "Europe/Madrid", Locale: "es_ES.UTF-8", AcceptLanguage: "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7", OAILanguage: "es-ES"},
	"IT": {Timezone: "Europe/Rome", Locale: "it_IT.UTF-8", AcceptLanguage: "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7", OAILanguage: "it-IT"},
	"SE": {Timezone: "Europe/Stockholm", Locale: "sv_SE.UTF-8", AcceptLanguage: "sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7", OAILanguage: "sv-SE"},
	"CH": {Timezone: "Europe/Zurich", Locale: "de_CH.UTF-8", AcceptLanguage: "de-CH,de;q=0.9,en-US;q=0.8,en;q=0.7", OAILanguage: "de-CH"},
	"BR": {Timezone: "America/Sao_Paulo", Locale: "pt_BR.UTF-8", AcceptLanguage: "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7", OAILanguage: "pt-BR"},
	"IN": {Timezone: "Asia/Kolkata", Locale: "en_IN.UTF-8", AcceptLanguage: "en-IN,en;q=0.9", OAILanguage: "en-IN"},
	"PL": {Timezone: "Europe/Warsaw", Locale: "pl_PL.UTF-8", AcceptLanguage: "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7", OAILanguage: "pl-PL"},
}

// DeriveGeoIdentity maps a verified proxy exit country code and IANA timezone
// to consistent timezone, POSIX locale, Accept-Language, and oai-language values.
// Never defaults to zh-CN; falls back to en-US when country is unmapped or empty.
func DeriveGeoIdentity(countryCode, timezone string) GeoIdentity {
	cc := strings.ToUpper(strings.TrimSpace(countryCode))
	tz := strings.TrimSpace(timezone)

	geo, ok := countryGeoDefaults[cc]
	if !ok {
		geo = GeoIdentity{
			Timezone:       "UTC",
			Locale:         "en_US.UTF-8",
			AcceptLanguage: "en-US,en;q=0.9",
			OAILanguage:    "en-US",
		}
	}
	if tz != "" {
		geo.Timezone = tz
	}
	return geo
}

// DeriveOAILanguageFromAccount returns geo-aligned (oai-language, Accept-Language)
// derived from the account's verified proxy exit or extra cage metadata.
// Defaults cleanly to ("en-US", "en-US,en;q=0.9").
func DeriveOAILanguageFromAccount(account *Account) (oaiLang string, acceptLang string) {
	if account != nil {
		if v := strings.TrimSpace(account.GetExtraString("cage_oai_language")); v != "" {
			accept := strings.TrimSpace(account.GetExtraString("cage_accept_language"))
			if accept == "" {
				accept = v + ",en;q=0.9"
			}
			return v, accept
		}
		if account.Proxy != nil {
			cc := strings.TrimSpace(account.Proxy.ExitCountryCode)
			tz := strings.TrimSpace(account.Proxy.ExitTimezone)
			if cc != "" || tz != "" {
				geo := DeriveGeoIdentity(cc, tz)
				return geo.OAILanguage, geo.AcceptLanguage
			}
		}
	}
	return "en-US", "en-US,en;q=0.9"
}

// GenerateConvergenceSeed generates a cryptographically random 32-byte cage root seed.
func GenerateConvergenceSeed() ([]byte, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate cage convergence seed: %w", err)
	}
	return seed, nil
}

// DeriveClaudeDeviceID deterministically derives a 64-lowercase-hex device ID from seed.
func DeriveClaudeDeviceID(seed []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte("claude-device-id:v1:"))
	_, _ = h.Write(seed)
	return hex.EncodeToString(h.Sum(nil))
}

// DeriveCodexInstallationID deterministically derives a canonical RFC 4122 UUIDv4 from seed.
func DeriveCodexInstallationID(seed []byte) string {
	return deriveDeterministicUUIDv4("codex-installation-id:v1:", seed)
}

// DeriveXAIClientIdentifier deterministically derives a canonical RFC 4122 UUIDv4 from seed.
func DeriveXAIClientIdentifier(seed []byte) string {
	return deriveDeterministicUUIDv4("xai-client-identifier:v1:", seed)
}

func deriveDeterministicUUIDv4(domain string, seed []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(seed)
	sum := h.Sum(nil)
	b := make([]byte, 16)
	copy(b, sum[:16])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16],
	)
}

var (
	macHostPrefixes     = []string{"MacBook-Pro", "MacBook-Air", "Mac-Studio", "iMac"}
	winHostPrefixes     = []string{"DESKTOP", "LAPTOP", "WIN"}
	linuxHostPrefixes   = []string{"thinkpad", "xps", "workstation", "devbox"}
	hostnameAlphanumSet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

// DeriveHostnameAlias deterministically produces a realistic personal workstation
// hostname aligned with clientOS. Never contains "berth", "cage", "proxy", or "sub2api".
func DeriveHostnameAlias(seed []byte, clientOS string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("hostname-alias:v1:"))
	_, _ = h.Write(seed)
	sum := h.Sum(nil)

	osLower := strings.ToLower(strings.TrimSpace(clientOS))
	switch {
	case strings.Contains(osLower, "mac") || strings.Contains(osLower, "darwin"):
		prefix := macHostPrefixes[int(sum[0])%len(macHostPrefixes)]
		return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(sum[1:3]))
	case strings.Contains(osLower, "win"):
		prefix := winHostPrefixes[int(sum[0])%len(winHostPrefixes)]
		suffix := make([]byte, 7)
		for i := range suffix {
			suffix[i] = hostnameAlphanumSet[int(sum[i+1])%len(hostnameAlphanumSet)]
		}
		return fmt.Sprintf("%s-%s", prefix, string(suffix))
	default:
		prefix := linuxHostPrefixes[int(sum[0])%len(linuxHostPrefixes)]
		return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(sum[1:3]))
	}
}

// BuildDefaultVirtualClientTuple deterministically picks a realistic virtual OS/arch/runtime/UA
// tuple for platform from seed (never leaking the server's runtime.GOOS/GOARCH).
func BuildDefaultVirtualClientTuple(platform string, seed []byte) VirtualClientTuple {
	h := sha256.New()
	_, _ = h.Write([]byte("virtual-client:v1:"))
	_, _ = h.Write([]byte(strings.ToLower(strings.TrimSpace(platform))))
	_, _ = h.Write(seed)
	sum := h.Sum(nil)

	type osSpec struct {
		osName    string
		osVersion string
		arch      string
		codexOS   string
		codexArch string
	}
	profiles := []osSpec{
		{osName: "MacOS", osVersion: "15.3.1", arch: "arm64", codexOS: "Mac OS 15.3.1", codexArch: "arm64"},
		{osName: "MacOS", osVersion: "14.7.2", arch: "arm64", codexOS: "Mac OS 14.7.2", codexArch: "arm64"},
		{osName: "Windows", osVersion: "10.0.22631", arch: "x64", codexOS: "Windows 11", codexArch: "x86_64"},
		{osName: "Linux", osVersion: "6.8.0", arch: "x64", codexOS: "Ubuntu 24.04", codexArch: "x86_64"},
	}
	chosen := profiles[int(sum[0])%len(profiles)]
	hostAlias := DeriveHostnameAlias(seed, chosen.osName)

	switch strings.ToLower(strings.TrimSpace(platform)) {
	case PlatformOpenAI:
		appVer := "0.114.0"
		ua := fmt.Sprintf("codex_cli_rs/%s (%s; %s)", appVer, chosen.codexOS, chosen.codexArch)
		return VirtualClientTuple{
			ClientOS:             chosen.osName,
			ClientOSVersion:      chosen.osVersion,
			ClientArch:           chosen.arch,
			ClientRuntime:        "rust",
			ClientRuntimeVersion: "1.85.0",
			ClientAppVersion:     appVer,
			UserAgentOAuth:       ua,
			UserAgentInference:   ua,
			Originator:           "codex_cli_rs",
			HostnameAlias:        hostAlias,
		}
	case PlatformGemini:
		appVer := "0.24.0"
		goOS := strings.ToLower(chosen.osName)
		if goOS == "macos" {
			goOS = "darwin"
		}
		ua := fmt.Sprintf("GeminiCLI/%s (%s; %s)", appVer, goOS, chosen.arch)
		return VirtualClientTuple{
			ClientOS:             chosen.osName,
			ClientOSVersion:      chosen.osVersion,
			ClientArch:           chosen.arch,
			ClientRuntime:        "node",
			ClientRuntimeVersion: "v24.11.0",
			ClientAppVersion:     appVer,
			UserAgentOAuth:       ua,
			UserAgentInference:   ua,
			HostnameAlias:        hostAlias,
		}
	case PlatformAntigravity:
		appVer := "2.23.0"
		goOS := strings.ToLower(chosen.osName)
		if goOS == "macos" {
			goOS = "darwin"
		}
		goArch := "amd64"
		if chosen.arch == "arm64" {
			goArch = "arm64"
		}
		ua := fmt.Sprintf("antigravity/hub/%s %s/%s", appVer, goOS, goArch)
		return VirtualClientTuple{
			ClientOS:             chosen.osName,
			ClientOSVersion:      chosen.osVersion,
			ClientArch:           chosen.arch,
			ClientRuntime:        "electron",
			ClientRuntimeVersion: "33.2.0",
			ClientAppVersion:     appVer,
			UserAgentOAuth:       ua,
			UserAgentInference:   ua,
			HostnameAlias:        hostAlias,
		}
	case PlatformGrok:
		appVer := "1.0.13"
		rustOS := strings.ToLower(chosen.osName)
		if rustOS == "macos" {
			rustOS = "macos"
		}
		rustArch := "x86_64"
		if chosen.arch == "arm64" {
			rustArch = "aarch64"
		}
		ua := fmt.Sprintf("grok-pager/%s grok-shell/%s (%s; %s)", appVer, appVer, rustOS, rustArch)
		return VirtualClientTuple{
			ClientOS:             chosen.osName,
			ClientOSVersion:      chosen.osVersion,
			ClientArch:           chosen.arch,
			ClientRuntime:        "rust",
			ClientRuntimeVersion: "1.85.0",
			ClientAppVersion:     appVer,
			UserAgentOAuth:       ua,
			UserAgentInference:   ua,
			HostnameAlias:        hostAlias,
		}
	default: // Anthropic / Claude Code
		appVer := "2.1.220"
		return VirtualClientTuple{
			ClientOS:             chosen.osName,
			ClientOSVersion:      chosen.osVersion,
			ClientArch:           chosen.arch,
			ClientRuntime:        "node",
			ClientRuntimeVersion: "v24.11.0",
			ClientAppVersion:     appVer,
			UserAgentOAuth:       "axios/1.15.2",
			UserAgentInference:   fmt.Sprintf("claude-cli/%s (external, cli)", appVer),
			HostnameAlias:        hostAlias,
		}
	}
}

// CheckExitDrift evaluates whether observed exit probe output violates anchor
// under driftPolicy ("same_ip" | "same_asn_city" | "same_country").
func CheckExitDrift(anchor *AccountCageExitAnchor, observed *ProxyExitInfo, driftPolicy string) (bool, string) {
	if anchor == nil || observed == nil {
		return true, "missing_anchor_or_observation"
	}
	obsIP := strings.TrimSpace(observed.IP)
	addr, err := netip.ParseAddr(obsIP)
	if err != nil || !addr.Unmap().Is4() {
		return true, fmt.Sprintf("non_ipv4_exit_observed:%s", obsIP)
	}
	normObsIP := addr.Unmap().String()
	normAnchorIP := strings.TrimSpace(anchor.ExitIP)
	if anchorAddr, aErr := netip.ParseAddr(normAnchorIP); aErr == nil {
		normAnchorIP = anchorAddr.Unmap().String()
	}

	policy := strings.TrimSpace(driftPolicy)
	if policy == "" {
		policy = CageDriftPolicySameIP
	}

	switch policy {
	case CageDriftPolicySameIP:
		if normObsIP != normAnchorIP {
			return true, fmt.Sprintf("exit_ip_drifted:%s->%s", normAnchorIP, normObsIP)
		}
		return false, ""

	case CageDriftPolicySameASNCity:
		if !strings.EqualFold(strings.TrimSpace(anchor.ExitCountryCode), strings.TrimSpace(observed.CountryCode)) {
			return true, fmt.Sprintf("exit_country_drifted:%s->%s", anchor.ExitCountryCode, observed.CountryCode)
		}
		if !strings.EqualFold(strings.TrimSpace(anchor.ExitCity), strings.TrimSpace(observed.City)) {
			return true, fmt.Sprintf("exit_city_drifted:%s->%s", anchor.ExitCity, observed.City)
		}
		if !strings.EqualFold(strings.TrimSpace(anchor.ExitASN), strings.TrimSpace(observed.ASN)) {
			return true, fmt.Sprintf("exit_asn_drifted:%s->%s", anchor.ExitASN, observed.ASN)
		}
		return false, ""

	case CageDriftPolicySameCountry:
		if !strings.EqualFold(strings.TrimSpace(anchor.ExitCountryCode), strings.TrimSpace(observed.CountryCode)) {
			return true, fmt.Sprintf("exit_country_drifted:%s->%s", anchor.ExitCountryCode, observed.CountryCode)
		}
		return false, ""

	default:
		// Fail closed on unknown drift policy.
		return true, fmt.Sprintf("unknown_drift_policy:%s", policy)
	}
}

// BerthAccountCageService manages persistent 1:1 AccountCages, immutable IPv4
// first-use exit anchors, drift quarantine, and live in-process CageGate instances.
type BerthAccountCageService struct {
	db            *sql.DB
	transportPool *cage.CageTransportPool
	gates         sync.Map // key: cageID (int64) -> *cage.CageGate
}

// NewBerthAccountCageService creates a BerthAccountCageService backed by PostgreSQL.
func NewBerthAccountCageService(db *sql.DB, transportPool *cage.CageTransportPool) *BerthAccountCageService {
	return &BerthAccountCageService{
		db:            db,
		transportPool: transportPool,
	}
}

// LiveGate returns (or initializes) the in-process fail-closed CageGate bound to cageID.
func (s *BerthAccountCageService) LiveGate(cageID int64) *cage.CageGate {
	if existing, ok := s.gates.Load(cageID); ok {
		return existing.(*cage.CageGate)
	}
	var opts []cage.GateOption
	if s.transportPool != nil {
		opts = append(opts, cage.WithEvictionCallback(s.transportPool.EvictCage))
	}
	created := cage.NewCageGate(cageID, opts...)
	actual, _ := s.gates.LoadOrStore(cageID, created)
	return actual.(*cage.CageGate)
}

// ProvisionCage creates a persistent 1:1 AccountCage with deterministic device IDs,
// geo-aligned timezone/locale/languages, and realistic non-Berth hostname alias.
func (s *BerthAccountCageService) ProvisionCage(ctx context.Context, input ProvisionCageInput) (*AccountCage, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("account cage service database is not configured")
	}
	if input.AccountID <= 0 {
		return nil, errors.New("account_id must be > 0")
	}
	if input.ProxyID <= 0 {
		return nil, ErrCageProxyRequired
	}

	seed := input.ConvergenceSeed
	if len(seed) == 0 {
		var err error
		seed, err = GenerateConvergenceSeed()
		if err != nil {
			return nil, err
		}
	}
	if len(seed) != 32 {
		return nil, errors.New("convergence_seed must be exactly 32 bytes")
	}

	bindingMode := strings.TrimSpace(input.LandingBindingMode)
	if bindingMode == "" {
		bindingMode = CageBindingModeExclusive
	}
	if bindingMode != CageBindingModeExclusive && bindingMode != CageBindingModeSharedCapped {
		return nil, fmt.Errorf("invalid landing_binding_mode: %q", bindingMode)
	}

	dnsMode := strings.TrimSpace(input.DNSMode)
	if dnsMode == "" {
		dnsMode = CageDNSModeProxyDoHIPv4Only
	}
	if dnsMode != CageDNSModeProxyDoHIPv4Only && dnsMode != CageDNSModeSOCKS5hRemote {
		return nil, fmt.Errorf("invalid dns_mode: %q", dnsMode)
	}

	driftPolicy := strings.TrimSpace(input.DriftPolicy)
	if driftPolicy == "" {
		driftPolicy = CageDriftPolicySameIP
	}
	if driftPolicy != CageDriftPolicySameIP && driftPolicy != CageDriftPolicySameASNCity && driftPolicy != CageDriftPolicySameCountry {
		return nil, fmt.Errorf("invalid drift_policy: %q", driftPolicy)
	}

	geo := DeriveGeoIdentity(input.ExitCountryCode, input.ExitTimezone)
	tuple := BuildDefaultVirtualClientTuple(input.Platform, seed)
	claudeDevID := DeriveClaudeDeviceID(seed)
	codexInstallID := DeriveCodexInstallationID(seed)
	xaiClientID := DeriveXAIClientIdentifier(seed)

	row := s.db.QueryRowContext(ctx, `
		INSERT INTO account_cages (
			account_id, proxy_id,
			landing_binding_mode, egress_policy, allow_ipv6, allow_udp, dns_mode, drift_policy,
			timezone, locale, accept_language, oai_language,
			tls_oauth_profile_id, tls_inference_profile_id,
			client_os, client_os_version, client_arch, client_runtime, client_runtime_version,
			client_app_version, user_agent_oauth, user_agent_inference, originator, hostname_alias,
			convergence_seed, claude_device_id, codex_installation_id, xai_client_identifier, extra_identity,
			gate_state, gate_epoch, credential_version
		) VALUES (
			$1, $2,
			$3, $4, FALSE, FALSE, $5, $6,
			$7, $8, $9, $10,
			$11, $12,
			$13, $14, $15, $16, $17,
			$18, $19, $20, $21, $22,
			$23, $24, $25, $26, '{}'::jsonb,
			'closed', 1, 1
		)
		RETURNING id, gate_state, gate_epoch, credential_version, created_at, updated_at
	`,
		input.AccountID, input.ProxyID,
		bindingMode, CageEgressPolicyStrictProxyOnly, dnsMode, driftPolicy,
		geo.Timezone, geo.Locale, geo.AcceptLanguage, geo.OAILanguage,
		input.TLSOAuthProfileID, input.TLSInferenceProfileID,
		tuple.ClientOS, tuple.ClientOSVersion, tuple.ClientArch, tuple.ClientRuntime, tuple.ClientRuntimeVersion,
		tuple.ClientAppVersion, tuple.UserAgentOAuth, tuple.UserAgentInference, tuple.Originator, tuple.HostnameAlias,
		seed, claudeDevID, codexInstallID, xaiClientID,
	)

	out := &AccountCage{
		AccountID:             input.AccountID,
		ProxyID:               input.ProxyID,
		LandingBindingMode:    bindingMode,
		EgressPolicy:          CageEgressPolicyStrictProxyOnly,
		AllowIPv6:             false,
		AllowUDP:              false,
		DNSMode:               dnsMode,
		DriftPolicy:           driftPolicy,
		Timezone:              geo.Timezone,
		Locale:                geo.Locale,
		AcceptLanguage:        geo.AcceptLanguage,
		OAILanguage:           geo.OAILanguage,
		TLSOAuthProfileID:     input.TLSOAuthProfileID,
		TLSInferenceProfileID: input.TLSInferenceProfileID,
		ClientOS:              tuple.ClientOS,
		ClientOSVersion:       tuple.ClientOSVersion,
		ClientArch:            tuple.ClientArch,
		ClientRuntime:         tuple.ClientRuntime,
		ClientRuntimeVersion:  tuple.ClientRuntimeVersion,
		ClientAppVersion:      tuple.ClientAppVersion,
		UserAgentOAuth:        tuple.UserAgentOAuth,
		UserAgentInference:    tuple.UserAgentInference,
		Originator:            tuple.Originator,
		HostnameAlias:         tuple.HostnameAlias,
		ConvergenceSeed:       append([]byte(nil), seed...),
		ClaudeDeviceID:        claudeDevID,
		CodexInstallationID:   codexInstallID,
		XAIClientIdentifier:   xaiClientID,
		ExtraIdentity:         map[string]any{},
	}
	if err := row.Scan(&out.ID, &out.GateState, &out.GateEpoch, &out.CredentialVersion, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return nil, fmt.Errorf("insert account_cage: %w", err)
	}
	_ = s.LiveGate(out.ID)
	return out, nil
}

// GetActiveCageByAccountID loads the active AccountCage for accountID.
func (s *BerthAccountCageService) GetActiveCageByAccountID(ctx context.Context, accountID int64) (*AccountCage, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("account cage service database is not configured")
	}
	return s.scanCageRow(s.db.QueryRowContext(ctx, `
		SELECT id, account_id, proxy_id,
		       landing_binding_mode, egress_policy, allow_ipv6, allow_udp, dns_mode, drift_policy,
		       timezone, locale, accept_language, oai_language,
		       tls_oauth_profile_id, tls_inference_profile_id,
		       client_os, client_os_version, client_arch, client_runtime, client_runtime_version,
		       client_app_version, user_agent_oauth, user_agent_inference, originator, hostname_alias,
		       convergence_seed, COALESCE(claude_device_id, ''), COALESCE(codex_installation_id::text, ''), COALESCE(xai_client_identifier::text, ''), extra_identity,
		       gate_state, gate_epoch, lease_expires_at, last_verified_at, COALESCE(last_error, ''),
		       credential_version, locked_at, created_at, updated_at
		  FROM account_cages
		 WHERE account_id = $1 AND deleted_at IS NULL
	`, accountID))
}

// GetActiveCageByID loads the active AccountCage by cage ID.
func (s *BerthAccountCageService) GetActiveCageByID(ctx context.Context, cageID int64) (*AccountCage, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("account cage service database is not configured")
	}
	return s.scanCageRow(s.db.QueryRowContext(ctx, `
		SELECT id, account_id, proxy_id,
		       landing_binding_mode, egress_policy, allow_ipv6, allow_udp, dns_mode, drift_policy,
		       timezone, locale, accept_language, oai_language,
		       tls_oauth_profile_id, tls_inference_profile_id,
		       client_os, client_os_version, client_arch, client_runtime, client_runtime_version,
		       client_app_version, user_agent_oauth, user_agent_inference, originator, hostname_alias,
		       convergence_seed, COALESCE(claude_device_id, ''), COALESCE(codex_installation_id::text, ''), COALESCE(xai_client_identifier::text, ''), extra_identity,
		       gate_state, gate_epoch, lease_expires_at, last_verified_at, COALESCE(last_error, ''),
		       credential_version, locked_at, created_at, updated_at
		  FROM account_cages
		 WHERE id = $1 AND deleted_at IS NULL
	`, cageID))
}

func (s *BerthAccountCageService) scanCageRow(row *sql.Row) (*AccountCage, error) {
	var c AccountCage
	var oauthProfID, inferProfID sql.NullInt64
	var leaseExp, lastVer, lockedAt sql.NullTime
	var extraRaw []byte

	err := row.Scan(
		&c.ID, &c.AccountID, &c.ProxyID,
		&c.LandingBindingMode, &c.EgressPolicy, &c.AllowIPv6, &c.AllowUDP, &c.DNSMode, &c.DriftPolicy,
		&c.Timezone, &c.Locale, &c.AcceptLanguage, &c.OAILanguage,
		&oauthProfID, &inferProfID,
		&c.ClientOS, &c.ClientOSVersion, &c.ClientArch, &c.ClientRuntime, &c.ClientRuntimeVersion,
		&c.ClientAppVersion, &c.UserAgentOAuth, &c.UserAgentInference, &c.Originator, &c.HostnameAlias,
		&c.ConvergenceSeed, &c.ClaudeDeviceID, &c.CodexInstallationID, &c.XAIClientIdentifier, &extraRaw,
		&c.GateState, &c.GateEpoch, &leaseExp, &lastVer, &c.LastError,
		&c.CredentialVersion, &lockedAt, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCageNotFound
	}
	if err != nil {
		return nil, err
	}
	if oauthProfID.Valid {
		v := oauthProfID.Int64
		c.TLSOAuthProfileID = &v
	}
	if inferProfID.Valid {
		v := inferProfID.Int64
		c.TLSInferenceProfileID = &v
	}
	if leaseExp.Valid {
		t := leaseExp.Time
		c.LeaseExpiresAt = &t
	}
	if lastVer.Valid {
		t := lastVer.Time
		c.LastVerifiedAt = &t
	}
	if lockedAt.Valid {
		t := lockedAt.Time
		c.LockedAt = &t
	}
	c.ExtraIdentity = map[string]any{}
	if len(extraRaw) > 0 {
		_ = json.Unmarshal(extraRaw, &c.ExtraIdentity)
	}
	return &c, nil
}

// UpdateCage applies allowed non-proxy policy/geo/profile updates to a cage.
func (s *BerthAccountCageService) UpdateCage(ctx context.Context, cageID int64, input UpdateCageInput) (*AccountCage, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("account cage service database is not configured")
	}
	existing, err := s.GetActiveCageByID(ctx, cageID)
	if err != nil {
		return nil, err
	}
	if input.DriftPolicy != nil {
		p := strings.TrimSpace(*input.DriftPolicy)
		if p != CageDriftPolicySameIP && p != CageDriftPolicySameASNCity && p != CageDriftPolicySameCountry {
			return nil, fmt.Errorf("invalid drift_policy: %q", p)
		}
		existing.DriftPolicy = p
	}
	if input.DNSMode != nil {
		d := strings.TrimSpace(*input.DNSMode)
		if d != CageDNSModeProxyDoHIPv4Only && d != CageDNSModeSOCKS5hRemote {
			return nil, fmt.Errorf("invalid dns_mode: %q", d)
		}
		existing.DNSMode = d
	}
	if input.Timezone != nil && strings.TrimSpace(*input.Timezone) != "" {
		existing.Timezone = strings.TrimSpace(*input.Timezone)
	}
	if input.Locale != nil && strings.TrimSpace(*input.Locale) != "" {
		existing.Locale = strings.TrimSpace(*input.Locale)
	}
	if input.AcceptLanguage != nil && strings.TrimSpace(*input.AcceptLanguage) != "" {
		existing.AcceptLanguage = strings.TrimSpace(*input.AcceptLanguage)
	}
	if input.OAILanguage != nil && strings.TrimSpace(*input.OAILanguage) != "" {
		existing.OAILanguage = strings.TrimSpace(*input.OAILanguage)
	}
	if input.TLSOAuthProfileID != nil {
		existing.TLSOAuthProfileID = input.TLSOAuthProfileID
	}
	if input.TLSInferenceProfileID != nil {
		existing.TLSInferenceProfileID = input.TLSInferenceProfileID
	}

	_, err = s.db.ExecContext(ctx, `
		UPDATE account_cages
		   SET drift_policy = $2,
		       dns_mode = $3,
		       timezone = $4,
		       locale = $5,
		       accept_language = $6,
		       oai_language = $7,
		       tls_oauth_profile_id = $8,
		       tls_inference_profile_id = $9
		 WHERE id = $1 AND deleted_at IS NULL
	`, cageID, existing.DriftPolicy, existing.DNSMode, existing.Timezone, existing.Locale,
		existing.AcceptLanguage, existing.OAILanguage, existing.TLSOAuthProfileID, existing.TLSInferenceProfileID)
	if err != nil {
		return nil, fmt.Errorf("update account_cage: %w", err)
	}
	return existing, nil
}

// AnchorFirstUseExit persists the immutable first-use IPv4 exit anchor, aligns
// cage timezone/locale/accept_language/oai_language to the verified exit, locks
// the cage (`locked_at = NOW()`), and opens the gate with a 90s lease.
func (s *BerthAccountCageService) AnchorFirstUseExit(
	ctx context.Context,
	cageID int64,
	proxyID int64,
	exit *ProxyExitInfo,
	probeSource string,
) (*AccountCageExitAnchor, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("account cage service database is not configured")
	}
	if exit == nil {
		return nil, ErrCageIPv4AnchorNeeded
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(exit.IP))
	if err != nil || !addr.Unmap().Is4() {
		return nil, ErrCageIPv4AnchorNeeded
	}
	ipv4 := addr.Unmap().String()
	geo := DeriveGeoIdentity(exit.CountryCode, exit.Timezone)
	if strings.TrimSpace(probeSource) == "" {
		probeSource = "ipwho.is"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	anchor := &AccountCageExitAnchor{
		CageID:          cageID,
		AnchorVersion:   1,
		IsActive:        true,
		ProxyID:         proxyID,
		ExitIP:          ipv4,
		ExitCountryCode: strings.ToUpper(strings.TrimSpace(exit.CountryCode)),
		ExitRegion:      strings.TrimSpace(exit.Region),
		ExitCity:        strings.TrimSpace(exit.City),
		ExitTimezone:    geo.Timezone,
		ExitASN:         strings.TrimSpace(exit.ASN),
		ExitISP:         strings.TrimSpace(exit.ISP),
		ProbeSource:     strings.TrimSpace(probeSource),
		Reason:          "first_use",
		AnchoredBy:      "system",
	}
	if anchor.ExitCountryCode == "" {
		anchor.ExitCountryCode = "US"
	}

	err = tx.QueryRowContext(ctx, `
		INSERT INTO account_cage_exit_anchors (
			cage_id, anchor_version, is_active, proxy_id,
			exit_ip, exit_country_code, exit_region, exit_city, exit_timezone,
			exit_asn, exit_isp, probe_source, reason, anchored_by
		) VALUES (
			$1, 1, TRUE, $2,
			$3::inet, $4, $5, $6, $7,
			$8, $9, $10, 'first_use', 'system'
		)
		RETURNING id, anchored_at
	`,
		anchor.CageID, anchor.ProxyID,
		anchor.ExitIP, anchor.ExitCountryCode, anchor.ExitRegion, anchor.ExitCity, anchor.ExitTimezone,
		anchor.ExitASN, anchor.ExitISP, anchor.ProbeSource,
	).Scan(&anchor.ID, &anchor.AnchoredAt)
	if err != nil {
		return nil, fmt.Errorf("insert first-use exit anchor: %w", err)
	}

	leaseUntil := time.Now().UTC().Add(cage.DefaultGateLease)
	_, err = tx.ExecContext(ctx, `
		UPDATE account_cages
		   SET timezone = $2,
		       locale = $3,
		       accept_language = $4,
		       oai_language = $5,
		       gate_state = 'open',
		       lease_expires_at = $6,
		       last_verified_at = NOW(),
		       last_error = NULL,
		       locked_at = COALESCE(locked_at, NOW())
		 WHERE id = $1 AND deleted_at IS NULL
	`, cageID, geo.Timezone, geo.Locale, geo.AcceptLanguage, geo.OAILanguage, leaseUntil)
	if err != nil {
		return nil, fmt.Errorf("lock and open account_cage: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	_, _ = s.LiveGate(cageID).Open(cage.DefaultGateLease)
	return anchor, nil
}

// GetActiveExitAnchor loads the active immutable exit anchor for cageID.
func (s *BerthAccountCageService) GetActiveExitAnchor(ctx context.Context, cageID int64) (*AccountCageExitAnchor, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("account cage service database is not configured")
	}
	var a AccountCageExitAnchor
	err := s.db.QueryRowContext(ctx, `
		SELECT id, cage_id, anchor_version, is_active, proxy_id,
		       host(exit_ip), exit_country_code, exit_region, exit_city, exit_timezone,
		       exit_asn, exit_isp, probe_source, reason, anchored_by, anchored_at
		  FROM account_cage_exit_anchors
		 WHERE cage_id = $1 AND is_active = TRUE
	`, cageID).Scan(
		&a.ID, &a.CageID, &a.AnchorVersion, &a.IsActive, &a.ProxyID,
		&a.ExitIP, &a.ExitCountryCode, &a.ExitRegion, &a.ExitCity, &a.ExitTimezone,
		&a.ExitASN, &a.ExitISP, &a.ProbeSource, &a.Reason, &a.AnchoredBy, &a.AnchoredAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCageNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// VerifyExitAndCheckDrift compares an observed proxy exit against the cage's active
// anchor under its configured drift_policy.
//
// On drift: atomically transitions `account_cages` to `gate_state = 'quarantined'`
// and increments `gate_epoch`, AND immediately quarantines the live in-process
// CageGate (killing live sockets + evicting transport pool & TLS session cache!).
//
// On match: renews the 90s lease.
func (s *BerthAccountCageService) VerifyExitAndCheckDrift(
	ctx context.Context,
	cageID int64,
	observed *ProxyExitInfo,
) (drifted bool, reason string, err error) {
	if s == nil || s.db == nil {
		return false, "", errors.New("account cage service database is not configured")
	}
	accountCage, err := s.GetActiveCageByID(ctx, cageID)
	if err != nil {
		return false, "", err
	}
	anchor, err := s.GetActiveExitAnchor(ctx, cageID)
	if err != nil {
		return false, "", err
	}

	drifted, reason = CheckExitDrift(anchor, observed, accountCage.DriftPolicy)
	if drifted {
		_, execErr := s.db.ExecContext(ctx, `
			UPDATE account_cages
			   SET gate_state = 'quarantined',
			       gate_epoch = gate_epoch + 1,
			       lease_expires_at = NULL,
			       last_error = $2
			 WHERE id = $1 AND deleted_at IS NULL
		`, cageID, reason)
		// Always quarantine the live gate immediately even if DB write hits a transient error (fail-closed!).
		s.LiveGate(cageID).Quarantine(reason)
		if execErr != nil {
			return true, reason, fmt.Errorf("quarantine drifted cage: %w", execErr)
		}
		return true, reason, nil
	}

	leaseUntil := time.Now().UTC().Add(cage.DefaultGateLease)
	_, err = s.db.ExecContext(ctx, `
		UPDATE account_cages
		   SET lease_expires_at = $2,
		       last_verified_at = NOW(),
		       last_error = NULL
		 WHERE id = $1 AND deleted_at IS NULL AND gate_state = 'open'
	`, cageID, leaseUntil)
	if err != nil {
		return false, "", fmt.Errorf("renew cage lease: %w", err)
	}
	_ = s.LiveGate(cageID).RenewLease(cage.DefaultGateLease)
	return false, "", nil
}

// isOfficialOpenAIAPIKeyAccount reports whether account is an official OpenAI
// API-key account targeting api.openai.com (or default base URL), where
// `prompt_cache_retention` MUST be preserved (Bug B7).
func isOfficialOpenAIAPIKeyAccount(account *Account) bool {
	if account == nil || !account.IsOpenAIApiKey() {
		return false
	}
	baseURL := strings.TrimSpace(account.GetOpenAIBaseURL())
	if baseURL == "" {
		return true
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(parsed.Hostname()), "api.openai.com")
}

// resolveRequiredProxyURL enforces fail-closed proxy resolution whenever a
// positive proxyID is configured: if proxyRepo is nil, GetByID fails, or the
// proxy is missing/inactive, it returns an explicit error instead of silently
// falling back to proxyURL = "" (Berth host direct IP).
func resolveRequiredProxyURL(ctx context.Context, proxyRepo ProxyRepository, proxyID *int64, preloaded *Proxy) (string, error) {
	if proxyID == nil || *proxyID <= 0 {
		return "", nil
	}
	if preloaded != nil && (preloaded.ID == 0 || preloaded.ID == *proxyID) {
		if preloaded.Status != "" && !preloaded.IsActive() {
			return "", fmt.Errorf("%w: proxy %d is not active (status=%s)", cage.ErrProxyUnavailable, *proxyID, preloaded.Status)
		}
		return preloaded.URL(), nil
	}
	if proxyRepo == nil {
		return "", fmt.Errorf("%w: proxy repository is unavailable for proxy_id=%d", cage.ErrProxyUnavailable, *proxyID)
	}
	proxy, err := proxyRepo.GetByID(ctx, *proxyID)
	if err != nil {
		return "", fmt.Errorf("%w: load proxy %d: %v", cage.ErrProxyUnavailable, *proxyID, err)
	}
	if proxy == nil {
		return "", fmt.Errorf("%w: proxy %d not found", cage.ErrProxyUnavailable, *proxyID)
	}
	if proxy.Status != "" && !proxy.IsActive() {
		return "", fmt.Errorf("%w: proxy %d is not active (status=%s)", cage.ErrProxyUnavailable, *proxyID, proxy.Status)
	}
	return proxy.URL(), nil
}

// waitForRefreshedTokenWithJitter polls tokenCache with exponential jitter
// (50ms -> 500ms, capped at maxWait, default 4s) while a peer worker holds the
// distributed refresh lock. Respects ctx cancellation immediately.
func waitForRefreshedTokenWithJitter(ctx context.Context, tokenCache GeminiTokenCache, cacheKey string, maxWait time.Duration) (string, error) {
	if tokenCache == nil {
		return "", nil
	}
	if maxWait <= 0 {
		maxWait = 4 * time.Second
	}
	deadline := time.Now().Add(maxWait)
	baseWait := 50 * time.Millisecond
	const maxStep = 500 * time.Millisecond

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return "", nil
		}
		jitterFactor := 0.8 + mathrand.Float64()*0.4
		sleepDur := time.Duration(float64(baseWait) * jitterFactor)
		if sleepDur > remaining {
			sleepDur = remaining
		}
		timer := time.NewTimer(sleepDur)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return "", ctx.Err()
		case <-timer.C:
		}

		if token, err := tokenCache.GetAccessToken(ctx, cacheKey); err == nil && strings.TrimSpace(token) != "" {
			return token, nil
		}
		if baseWait < maxStep {
			baseWait *= 2
			if baseWait > maxStep {
				baseWait = maxStep
			}
		}
	}
}
