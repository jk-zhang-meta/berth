package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/cage"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/jk-zhang-meta/berth/internal/pkg/httpwire"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const landingPerAccountPSKCap = 16

type landingPoolKey struct {
	accountID int64
	cageEpoch int64
	preset    string
}

type landingTransportEntry struct {
	preset       string
	profile      *cage.TLSProfileSpec
	headerOrder  []string
	sessionCache utls.ClientSessionCache
	h1Transport  *http.Transport
	h2Transport  *http2.Transport
	h2Mu         sync.Mutex
	h2Conns      map[string]*http2.ClientConn
}

// LandingCageExecutor executes admitted upstream AI provider requests directly from
// a dedicated Landing berth-edge node using Track A's protocol-level Account Cage
// primitives:
//   - IPv4-only SSRF-guarded direct dialing via CompatSSRFGuard (no IPv6 / no private IPs)
//   - Pinned per-platform uTLS fingerprints (claude_node24_inference / oauth / count_tokens,
//     codex_chrome_pinned — never floating HelloChrome_Auto)
//   - Exact HTTP/1.1 wire header ordering via internal/pkg/httpwire
//   - Strictly isolated per-(account_id, cage_epoch) TLS PSK ClientSessionCache & H1/H2 pools
//   - Geo-aligned Accept-Language from SessionLeaseClaims.CohortLocale
type LandingCageExecutor struct {
	guard   *CompatSSRFGuard
	rootCAs *x509.CertPool
	wsTLS   *tls.Config

	mu           sync.Mutex
	entries      map[landingPoolKey]*landingTransportEntry
	accountEpoch map[int64]int64
	pskCaches    map[int64]utls.ClientSessionCache
}

// NewLandingCageExecutor constructs a direct-from-landing protocol-level Account Cage executor.
func NewLandingCageExecutor(guard *CompatSSRFGuard, wsTLS *tls.Config) *LandingCageExecutor {
	if guard == nil {
		guard = NewCompatSSRFGuard(nil, nil, nil)
	}
	var rootCAs *x509.CertPool
	if wsTLS != nil {
		rootCAs = wsTLS.RootCAs
	}
	return &LandingCageExecutor{
		guard:        guard,
		rootCAs:      rootCAs,
		wsTLS:        wsTLS,
		entries:      make(map[landingPoolKey]*landingTransportEntry),
		accountEpoch: make(map[int64]int64),
		pskCaches:    make(map[int64]utls.ClientSessionCache),
	}
}

// SelectLandingPreset resolves the pinned uTLS + httpwire preset for a platform and request path.
func SelectLandingPreset(platform, reqPath string) string {
	p := strings.ToLower(strings.TrimSpace(platform))
	lp := strings.ToLower(strings.TrimSpace(reqPath))
	switch p {
	case "anthropic", "claude":
		if strings.Contains(lp, "/oauth/") || strings.Contains(lp, "/v1/oauth") {
			return cage.PresetClaudeNode24OAuth
		}
		if strings.Contains(lp, "count_tokens") {
			return cage.PresetClaudeNode24CountTokens
		}
		return cage.PresetClaudeNode24Inference
	default:
		return cage.PresetCodexChromePinned
	}
}

// AcceptLanguageForLocale derives a clean geo-aligned Accept-Language header from a POSIX locale.
func AcceptLanguageForLocale(locale string) string {
	l := strings.TrimSpace(locale)
	if idx := strings.IndexAny(l, ".@"); idx >= 0 {
		l = l[:idx]
	}
	l = strings.ReplaceAll(l, "_", "-")
	if l == "" || strings.EqualFold(l, "C") || strings.EqualFold(l, "POSIX") {
		return "en-US,en;q=0.9"
	}
	parts := strings.SplitN(l, "-", 2)
	lang := strings.ToLower(parts[0])
	if len(parts) == 2 && parts[1] != "" {
		tag := lang + "-" + strings.ToUpper(parts[1])
		if lang == "en" {
			return tag + ",en;q=0.9"
		}
		return fmt.Sprintf("%s,%s;q=0.9,en-US;q=0.8,en;q=0.7", tag, lang)
	}
	if lang == "en" {
		return "en-US,en;q=0.9"
	}
	return fmt.Sprintf("%s,en-US;q=0.8,en;q=0.7", lang)
}

// EvictAccount immediately closes pooled connections and wipes the isolated TLS PSK cache for accountID.
func (e *LandingCageExecutor) EvictAccount(accountID int64) {
	e.mu.Lock()
	evicted := e.evictAccountLocked(accountID)
	e.mu.Unlock()
	for _, entry := range evicted {
		entry.closeIdle()
	}
}

func (e *LandingCageExecutor) evictAccountLocked(accountID int64) []*landingTransportEntry {
	var evicted []*landingTransportEntry
	for k, ent := range e.entries {
		if k.accountID == accountID {
			evicted = append(evicted, ent)
			delete(e.entries, k)
		}
	}
	delete(e.pskCaches, accountID)
	return evicted
}

// SessionCacheForAccount exposes the isolated TLS PSK cache for an account (for inspection/tests).
func (e *LandingCageExecutor) SessionCacheForAccount(accountID int64) utls.ClientSessionCache {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.pskCaches[accountID]
}

func (e *LandingCageExecutor) getOrCreateEntry(accountID, cageEpoch int64, preset string) (*landingTransportEntry, error) {
	profile, err := cage.ProfileForPreset(preset)
	if err != nil {
		return nil, err
	}
	key := landingPoolKey{accountID: accountID, cageEpoch: cageEpoch, preset: preset}

	var evicted []*landingTransportEntry
	e.mu.Lock()
	if prevEpoch, seen := e.accountEpoch[accountID]; seen && accountID > 0 && cageEpoch > 0 {
		if cageEpoch < prevEpoch {
			e.mu.Unlock()
			return nil, fmt.Errorf("landing cage: stale cage_epoch %d < current %d for account %d", cageEpoch, prevEpoch, accountID)
		}
		if cageEpoch > prevEpoch {
			// Monotonic CageEpoch bump: atomically wipe old transports AND TLS PSK tickets!
			evicted = e.evictAccountLocked(accountID)
		}
	}
	if accountID > 0 && cageEpoch > e.accountEpoch[accountID] {
		e.accountEpoch[accountID] = cageEpoch
	}
	if existing, ok := e.entries[key]; ok {
		e.mu.Unlock()
		for _, old := range evicted {
			old.closeIdle()
		}
		return existing, nil
	}

	sessCache, ok := e.pskCaches[accountID]
	if !ok {
		sessCache = utls.NewLRUClientSessionCache(landingPerAccountPSKCap)
		e.pskCaches[accountID] = sessCache
	}
	headerOrder := httpwire.PresetHeaderOrder(profile.HeaderOrderPreset)
	ent := &landingTransportEntry{
		preset:       preset,
		profile:      profile,
		headerOrder:  headerOrder,
		sessionCache: sessCache,
		h2Transport:  &http2.Transport{},
		h2Conns:      make(map[string]*http2.ClientConn),
	}
	ent.h1Transport = &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			raw, _, dErr := e.guard.DialValidatedTCP(ctx, addr)
			if dErr != nil {
				return nil, dErr
			}
			return httpwire.NewOrderedRequestConn(raw, headerOrder), nil
		},
		DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			uConn, dErr := e.dialUTLS(ctx, addr, ent)
			if dErr != nil {
				return nil, dErr
			}
			return httpwire.NewOrderedRequestConn(uConn, headerOrder), nil
		},
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     60 * time.Second,
	}
	e.entries[key] = ent
	e.mu.Unlock()

	for _, old := range evicted {
		old.closeIdle()
	}
	return ent, nil
}

func (e *LandingCageExecutor) dialUTLS(ctx context.Context, addr string, ent *landingTransportEntry) (*utls.UConn, error) {
	rawConn, origHost, err := e.guard.DialValidatedTCP(ctx, addr)
	if err != nil {
		return nil, err
	}
	spec, err := cage.BuildClientHelloSpec(ent.preset)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	tlsCfg := &utls.Config{
		ServerName:                         origHost,
		RootCAs:                            e.rootCAs,
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}
	if ent.profile.EnablePSKCache && ent.sessionCache != nil {
		tlsCfg.ClientSessionCache = ent.sessionCache
	}
	uConn := utls.UClient(rawConn, tlsCfg, utls.HelloCustom)
	if err := uConn.ApplyPreset(spec); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("landing cage: apply uTLS preset %q: %w", ent.preset, err)
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("landing cage: uTLS handshake (%s): %w", ent.preset, err)
	}
	return uConn, nil
}

func (ent *landingTransportEntry) closeIdle() {
	if ent.h1Transport != nil {
		ent.h1Transport.CloseIdleConnections()
	}
	ent.h2Mu.Lock()
	conns := make([]*http2.ClientConn, 0, len(ent.h2Conns))
	for k, cc := range ent.h2Conns {
		conns = append(conns, cc)
		delete(ent.h2Conns, k)
	}
	ent.h2Mu.Unlock()
	for _, cc := range conns {
		_ = cc.Close()
	}
}

func (ent *landingTransportEntry) getUsableH2Conn(addr string) *http2.ClientConn {
	ent.h2Mu.Lock()
	defer ent.h2Mu.Unlock()
	cc, ok := ent.h2Conns[addr]
	if !ok {
		return nil
	}
	if !cc.CanTakeNewRequest() {
		delete(ent.h2Conns, addr)
		return nil
	}
	return cc
}

func (ent *landingTransportEntry) storeH2Conn(addr string, cc *http2.ClientConn) {
	ent.h2Mu.Lock()
	if prev, ok := ent.h2Conns[addr]; ok && prev != cc {
		_ = prev.Close()
	}
	ent.h2Conns[addr] = cc
	ent.h2Mu.Unlock()
}

// DoHTTP executes an admitted upstream HTTP/SSE request using pinned uTLS + httpwire + per-account PSK cache.
func (e *LandingCageExecutor) DoHTTP(ctx context.Context, req *http.Request, lease *edgeproto.SessionLeaseClaims) (*http.Response, error) {
	if _, _, _, err := e.guard.ValidateURL(req.URL.String()); err != nil {
		return nil, err
	}
	var accountID, cageEpoch int64
	var platform, locale string
	if lease != nil {
		accountID = lease.AccountID
		cageEpoch = lease.CageEpoch
		platform = lease.Platform
		locale = lease.CohortLocale
	}
	preset := SelectLandingPreset(platform, req.URL.Path)
	ent, err := e.getOrCreateEntry(accountID, cageEpoch, preset)
	if err != nil {
		return nil, err
	}

	outReq := req.Clone(ctx)
	outReq.RequestURI = ""
	if locale != "" && (accountID > 0 || outReq.Header.Get("Accept-Language") == "") {
		outReq.Header.Set("Accept-Language", AcceptLanguageForLocale(locale))
	}

	if !strings.EqualFold(outReq.URL.Scheme, "https") || ent.profile.ALPNMode != cage.ALPNModeFollowNegotiated {
		return ent.h1Transport.RoundTrip(outReq)
	}

	addr := outReq.URL.Host
	if _, _, splitErr := net.SplitHostPort(addr); splitErr != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	if cc := ent.getUsableH2Conn(addr); cc != nil {
		return cc.RoundTrip(outReq)
	}

	uConn, err := e.dialUTLS(ctx, addr, ent)
	if err != nil {
		return nil, err
	}
	if uConn.ConnectionState().NegotiatedProtocol == "h2" {
		cc, h2Err := ent.h2Transport.NewClientConn(uConn)
		if h2Err != nil {
			_ = uConn.Close()
			return nil, fmt.Errorf("landing cage: create http2 conn: %w", h2Err)
		}
		ent.storeH2Conn(addr, cc)
		return cc.RoundTrip(outReq)
	}

	ordered := httpwire.NewOrderedRequestConn(uConn, ent.headerOrder)
	var once sync.Once
	singleH1 := &http.Transport{
		DialTLSContext: func(dctx context.Context, _, dialAddr string) (net.Conn, error) {
			var conn net.Conn
			once.Do(func() { conn = ordered })
			if conn != nil {
				return conn, nil
			}
			nextUConn, dialErr := e.dialUTLS(dctx, dialAddr, ent)
			if dialErr != nil {
				return nil, dialErr
			}
			return httpwire.NewOrderedRequestConn(nextUConn, ent.headerOrder), nil
		},
		ForceAttemptHTTP2: false,
		DisableKeepAlives: true,
	}
	return singleH1.RoundTrip(outReq)
}

// DialWebSocket opens an SSRF-guarded IPv4 WebSocket connection from the Landing node.
func (e *LandingCageExecutor) DialWebSocket(ctx context.Context, targetURL string, headers http.Header, _ *edgeproto.SessionLeaseClaims) (net.Conn, *bufio.Reader, *http.Response, error) {
	return DialRFC6455WebSocket(ctx, e.guard, e.wsTLS, targetURL, headers)
}
