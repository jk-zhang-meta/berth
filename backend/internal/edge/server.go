package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// UpstreamExecutor executes admitted upstream AI provider HTTP/SSE/WS requests on
// Landing/Compat nodes. Designed as a clean seam so Track A's internal/pkg/cage.Transport
// plugs directly into berth-edge without changing any data-plane routing or admission logic.
type UpstreamExecutor interface {
	DoHTTP(ctx context.Context, req *http.Request, lease *edgeproto.SessionLeaseClaims) (*http.Response, error)
	DialWebSocket(ctx context.Context, targetURL string, headers http.Header, lease *edgeproto.SessionLeaseClaims) (net.Conn, *bufio.Reader, *http.Response, error)
}

// SafeUpstreamExecutor is the default fail-closed IPv4 UpstreamExecutor backed by CompatSSRFGuard.
type SafeUpstreamExecutor struct {
	Guard     *CompatSSRFGuard
	Client    *http.Client
	TLSConfig *tls.Config
}

// NewSafeUpstreamExecutor builds an SSRF-guarded UpstreamExecutor.
func NewSafeUpstreamExecutor(guard *CompatSSRFGuard, tlsCfg *tls.Config) *SafeUpstreamExecutor {
	return &SafeUpstreamExecutor{
		Guard:     guard,
		Client:    guard.NewSafeHTTPClient(tlsCfg),
		TLSConfig: tlsCfg,
	}
}

func (e *SafeUpstreamExecutor) DoHTTP(ctx context.Context, req *http.Request, _ *edgeproto.SessionLeaseClaims) (*http.Response, error) {
	if _, _, _, err := e.Guard.ValidateURL(req.URL.String()); err != nil {
		return nil, err
	}
	outReq := req.Clone(ctx)
	outReq.RequestURI = ""
	return e.Client.Do(outReq)
}

func (e *SafeUpstreamExecutor) DialWebSocket(ctx context.Context, targetURL string, headers http.Header, _ *edgeproto.SessionLeaseClaims) (net.Conn, *bufio.Reader, *http.Response, error) {
	return DialRFC6455WebSocket(ctx, e.Guard, e.TLSConfig, targetURL, headers)
}

// ---------- Central Control-Plane Client ----------

// FailoverCandidateDTO carries optional failover candidate descriptors for Central failover requests.
type FailoverCandidateDTO struct {
	AccountID         int64  `json:"account_id"`
	CageID            int64  `json:"cage_id"`
	CageEpoch         int64  `json:"cage_epoch"`
	GrantID           int64  `json:"grant_id"`
	LandingNodeID     int64  `json:"landing_node_id"`
	CohortTimezone    string `json:"cohort_timezone"`
	CohortCountryCode string `json:"cohort_country_code"`
	CohortLocale      string `json:"cohort_locale"`
}

// FailoverResult mirrors Berth Central's /api/v1/internal/edge/failover response.
type FailoverResult struct {
	Action string `json:"action"` // switched | cage_rebind_required
	Code   string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Lease  *struct {
		LeaseID    string               `json:"lease_id"`
		Token      string               `json:"token"`
		RouteChain []edgeproto.RouteHop `json:"route_chain"`
		AccountID  int64                `json:"account_id"`
	} `json:"lease,omitempty"`
	RecommendedCohort json.RawMessage `json:"recommended_cohort,omitempty"`
}

// OAuthTaskDTO mirrors Berth Central's Landing-dispatched OAuth/refresh/probe task.
type OAuthTaskDTO struct {
	TaskID     string            `json:"task_id"`
	NodeID     int64             `json:"node_id"`
	AccountID  int64             `json:"account_id"`
	Kind       string            `json:"kind"`
	TargetURL  string            `json:"target_url"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers,omitempty"`
	BodyBase64 string            `json:"body_base64,omitempty"`
}

// CentralClient speaks Ed25519-authenticated control-plane HTTP with Berth Central.
type CentralClient struct {
	BaseURL    string
	NodeID     int64
	PrivateKey ed25519.PrivateKey
	HTTPClient *http.Client
}

// NewCentralClient builds an Ed25519-authenticated Central control-plane client.
func NewCentralClient(baseURL string, nodeID int64, priv ed25519.PrivateKey, httpClient *http.Client) *CentralClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &CentralClient{
		BaseURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		NodeID:     nodeID,
		PrivateKey: priv,
		HTTPClient: httpClient,
	}
}

func (c *CentralClient) doSignedJSON(ctx context.Context, method, path string, reqBody any) (int, []byte, error) {
	if c == nil || c.BaseURL == "" {
		return 0, nil, errors.New("edge: central client not configured")
	}
	var raw []byte
	var err error
	if reqBody != nil {
		raw, err = json.Marshal(reqBody)
		if err != nil {
			return 0, nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	ts := time.Now().Unix()
	sig, err := edgeproto.SignNodeRequest(c.PrivateKey, c.NodeID, method, path, ts, raw)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set(edgeproto.HeaderNodeID, strconv.FormatInt(c.NodeID, 10))
	req.Header.Set(edgeproto.HeaderNodeTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(edgeproto.HeaderNodeSignature, sig)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	return resp.StatusCode, respBytes, err
}

// Heartbeat reports node health to Berth Central and returns the fresh signed RevocationSnapshot.
func (c *CentralClient) Heartbeat(ctx context.Context, status string) (*edgeproto.RevocationSnapshot, error) {
	code, raw, err := c.doSignedJSON(ctx, http.MethodPost, "/api/v1/internal/edge/heartbeat", map[string]any{"status": status})
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("edge: heartbeat failed with status %d", code)
	}
	var env struct {
		Data struct {
			RevocationSnapshot *edgeproto.RevocationSnapshot `json:"revocation_snapshot"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.Data.RevocationSnapshot == nil {
		return nil, edgeproto.ErrRevocationSnapshotMissing
	}
	return env.Data.RevocationSnapshot, nil
}

// RequestGrantSlice atomically reserves the next disjoint byte slice from Berth Central.
func (c *CentralClient) RequestGrantSlice(ctx context.Context, grantID, wantBytes int64) (string, int64, time.Time, error) {
	code, raw, err := c.doSignedJSON(ctx, http.MethodPost, "/api/v1/internal/edge/grant-slice", map[string]any{
		"grant_id":        grantID,
		"requested_bytes": wantBytes,
	})
	if err != nil {
		return "", 0, time.Time{}, err
	}
	if code != http.StatusOK {
		return "", 0, time.Time{}, edgeproto.ErrGrantSliceExhausted
	}
	var env struct {
		Data struct {
			SliceID      string     `json:"slice_id"`
			GrantedBytes int64      `json:"granted_bytes"`
			ExpiresAt    *time.Time `json:"expires_at"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", 0, time.Time{}, err
	}
	var exp time.Time
	if env.Data.ExpiresAt != nil {
		exp = *env.Data.ExpiresAt
	}
	return env.Data.SliceID, env.Data.GrantedBytes, exp, nil
}

// FlushUsageOutbox delivers a batch of terminal receipts idempotently to Berth Central.
func (c *CentralClient) FlushUsageOutbox(ctx context.Context, batch []edgeproto.UsageReceipt) ([]string, error) {
	code, raw, err := c.doSignedJSON(ctx, http.MethodPost, "/api/v1/internal/edge/usage-outbox", map[string]any{
		"receipts": batch,
	})
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("edge: usage-outbox flush failed status %d", code)
	}
	var env struct {
		Data struct {
			AckedReceiptIDs []string `json:"acked_receipt_ids"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	return env.Data.AckedReceiptIDs, nil
}

// RequestFailover asks Berth Central for same-cohort failover or 409 cage_rebind_required.
func (c *CentralClient) RequestFailover(ctx context.Context, leaseID string, failedAccountID int64, statusCode int, cands []FailoverCandidateDTO) (int, *FailoverResult, error) {
	code, raw, err := c.doSignedJSON(ctx, http.MethodPost, "/api/v1/internal/edge/failover", map[string]any{
		"lease_id":          leaseID,
		"failed_account_id": failedAccountID,
		"status_code":       statusCode,
		"candidates":        cands,
	})
	if err != nil {
		return code, nil, err
	}
	var env struct {
		Data *FailoverResult `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return code, nil, err
	}
	return code, env.Data, nil
}

// PollOAuthTasks retrieves pending OAuth/refresh/probe tasks assigned to this Landing node.
func (c *CentralClient) PollOAuthTasks(ctx context.Context) ([]OAuthTaskDTO, error) {
	code, raw, err := c.doSignedJSON(ctx, http.MethodGet, "/api/v1/internal/edge/oauth-tasks", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("edge: poll oauth tasks status %d", code)
	}
	var env struct {
		Data struct {
			Tasks []OAuthTaskDTO `json:"tasks"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	return env.Data.Tasks, nil
}

// CompleteOAuthTask submits the upstream execution result of a dispatched OAuth/refresh/probe task.
func (c *CentralClient) CompleteOAuthTask(ctx context.Context, taskID string, statusCode int, respBody, errMsg string) error {
	code, _, err := c.doSignedJSON(ctx, http.MethodPost, "/api/v1/internal/edge/oauth-tasks/"+taskID+"/complete", map[string]any{
		"status_code": statusCode,
		"resp_body":   respBody,
		"error":       errMsg,
	})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("edge: complete oauth task status %d", code)
	}
	return nil
}

// ---------- Unified Multi-Role EdgeServer ----------

// EdgeServer runs one or more berth-edge roles (ingress_relay, transit, landing, compat)
// over a single HTTP/2 + HTTP/1.1 (h2c or TLS) listener, sharing one fenced AdmissionGate.
type EdgeServer struct {
	cfg            *Config
	central        *CentralClient
	gate           *AdmissionGate
	outbox         *edgeproto.OutboxWAL
	grantWAL       *edgeproto.GrantWAL
	reverseHub     *ReverseTunnelHub
	upstream       UpstreamExecutor
	ssrfGuard      *CompatSSRFGuard
	h2Client       *http.Client
	failoverLookup func(*edgeproto.SessionLeaseClaims) []FailoverCandidateDTO

	mu  sync.Mutex
	srv *http.Server
}

// EdgeServerOptions configures an EdgeServer cleanly for production or E2E tests.
type EdgeServerOptions struct {
	Config         *Config
	CentralPubKey  ed25519.PublicKey
	CentralClient  *CentralClient
	GrantWAL       *edgeproto.GrantWAL
	OutboxWAL      *edgeproto.OutboxWAL
	ReverseHub     *ReverseTunnelHub
	Upstream       UpstreamExecutor
	SSRFGuard      *CompatSSRFGuard
	FailoverLookup func(*edgeproto.SessionLeaseClaims) []FailoverCandidateDTO
}

// NewEdgeServer initializes an EdgeServer with single-mux HTTP/2 transport and AdmissionGate.
func NewEdgeServer(opts EdgeServerOptions) (*EdgeServer, error) {
	if opts.Config == nil {
		return nil, errors.New("edge: nil config")
	}
	opts.Config.ApplyDefaults()

	guard := opts.SSRFGuard
	if guard == nil {
		guard = NewCompatSSRFGuard(opts.Config.AllowedUpstreamHosts, opts.Config.TestAllowLoopbackHosts, nil)
	}
	upstream := opts.Upstream
	if upstream == nil {
		upstream = NewSafeUpstreamExecutor(guard, nil)
	}

	var refiller SliceRefiller
	if opts.CentralClient != nil {
		refiller = opts.CentralClient.RequestGrantSlice
	}

	var walForGate *edgeproto.GrantWAL
	if opts.Config.HasRole(RoleLanding) || opts.Config.HasRole(RoleCompat) {
		walForGate = opts.GrantWAL
	}
	gate := NewAdmissionGate(opts.CentralPubKey, walForGate, refiller, opts.Config.GrantSliceBytes, opts.Config.GrantLowWatermark)

	// Single-mux HTTP/2 transport supporting both h2c (local/test) and TLS hops.
	h2Tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}

	return &EdgeServer{
		cfg:            opts.Config,
		central:        opts.CentralClient,
		gate:           gate,
		outbox:         opts.OutboxWAL,
		grantWAL:       opts.GrantWAL,
		reverseHub:     opts.ReverseHub,
		upstream:       upstream,
		ssrfGuard:      guard,
		h2Client:       &http.Client{Transport: h2Tr},
		failoverLookup: opts.FailoverLookup,
	}, nil
}

// Gate exposes the node's single fenced AdmissionGate.
func (s *EdgeServer) Gate() *AdmissionGate { return s.gate }

// Outbox exposes the node's durable UsageReceipt outbox WAL.
func (s *EdgeServer) Outbox() *edgeproto.OutboxWAL { return s.outbox }

// Handler returns the unified HTTP/1.1 + h2c HTTP/2 handler for this EdgeServer.
func (s *EdgeServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc(edgeproto.TunnelExecutePath, s.handleTunnelExecute)
	mux.HandleFunc(edgeproto.TunnelWSBridgePath, s.handleTunnelWSBridge)
	mux.HandleFunc("/", s.handleIngressClient)
	return h2c.NewHandler(mux, &http2.Server{
		MaxConcurrentStreams: uint32(s.cfg.MaxConcurrentStreams),
	})
}

// Serve runs the EdgeServer on ln until ctx is cancelled.
func (s *EdgeServer) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}
	s.mu.Lock()
	s.srv = srv
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *EdgeServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":         "ok",
		"node_id":        s.cfg.NodeID,
		"node_name":      s.cfg.NodeName,
		"roles":          s.cfg.Roles,
		"active_streams": s.gate.ActiveStreamCount(),
	})
}

func extractBearerLease(r *http.Request) string {
	if tok := strings.TrimSpace(r.Header.Get(edgeproto.HeaderLease)); tok != "" {
		return tok
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

func newReceiptID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "rcpt-" + hex.EncodeToString(b[:])
}

// ---------- Ingress Relay Client Handling ----------

func (s *EdgeServer) handleIngressClient(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.HasRole(RoleIngressRelay) {
		http.Error(w, "ingress_relay role not enabled on this node", http.StatusNotFound)
		return
	}
	leaseToken := extractBearerLease(r)
	if leaseToken == "" {
		http.Error(w, "missing session lease token", http.StatusUnauthorized)
		return
	}

	admitted, err := s.gate.Admit(r.Context(), leaseToken, 0, nil)
	if err != nil {
		writeAdmissionError(w, err)
		return
	}
	defer admitted.Release()

	targetURL := strings.TrimSpace(r.Header.Get(edgeproto.HeaderUpstreamURL))
	if targetURL == "" {
		base := strings.TrimRight(s.cfg.DefaultUpstreamBaseURL, "/")
		if base == "" {
			http.Error(w, "missing upstream target url", http.StatusBadRequest)
			return
		}
		targetURL = base + r.URL.RequestURI()
	}

	if IsWebSocketUpgrade(r) {
		s.handleIngressWebSocket(w, r, admitted, leaseToken, targetURL)
		return
	}

	s.handleIngressHTTP(w, r, admitted, leaseToken, targetURL)
}

func (s *EdgeServer) handleIngressHTTP(
	w http.ResponseWriter,
	r *http.Request,
	admitted *AdmittedStream,
	leaseToken string,
	targetURL string,
) {
	// Buffer small request bodies so pre-commit failover can cleanly retry on a same-cohort account.
	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(io.LimitReader(r.Body, 16*1024*1024))
		if err != nil {
			http.Error(w, "failed reading request body", http.StatusBadRequest)
			return
		}
	}

	curLeaseToken := leaseToken
	curClaims := admitted.Claims()
	curRoute := curClaims.RouteChain

	for attempt := 0; attempt < 2; attempt++ {
		resp, err := s.dispatchTunnelHTTP(admitted.Context(), curRoute, 0, curLeaseToken, r.Method, targetURL, r.Header, bodyBytes)
		if err != nil {
			http.Error(w, fmt.Sprintf("tunnel dispatch failed: %v", err), http.StatusBadGateway)
			return
		}

		// Pre-commit failover on 429/529 (Codex Blocker #7: strictly BEFORE writing client headers!).
		if attempt == 0 && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 529) && s.central != nil {
			_ = resp.Body.Close()
			var cands []FailoverCandidateDTO
			if s.failoverLookup != nil {
				cands = s.failoverLookup(curClaims)
			}
			foCode, foRes, foErr := s.central.RequestFailover(admitted.Context(), curClaims.LeaseID, curClaims.AccountID, resp.StatusCode, cands)
			if foErr == nil && foRes != nil {
				if foRes.Action == "switched" && foRes.Lease != nil && foRes.Lease.Token != "" {
					curLeaseToken = foRes.Lease.Token
					curRoute = foRes.Lease.RouteChain
					if nextClaims, verr := edgeproto.VerifyLease(s.gate.centralPubKey, curLeaseToken, time.Now()); verr == nil {
						curClaims = nextClaims
					}
					continue
				}
				if foCode == http.StatusConflict || foRes.Action == "cage_rebind_required" {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set(edgeproto.HeaderAction, "cage_rebind_required")
					w.WriteHeader(http.StatusConflict)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"error": map[string]any{
							"code":               "cage_rebind_required",
							"message":            foRes.Message,
							"recommended_cohort": foRes.RecommendedCohort,
						},
					})
					return
				}
			}
			// If failover didn't switch or return 409, return 429/529 transparently.
			http.Error(w, "upstream rate limited", resp.StatusCode)
			return
		}

		defer func() { _ = resp.Body.Close() }()
		copyForwardHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}

		isSSE := strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
		buf := make([]byte, 16*1024)
		for {
			if err := admitted.Context().Err(); err != nil {
				if isSSE {
					_, _ = io.WriteString(w, "event: error\ndata: {\"code\":\"cage_rebind_required\",\"reason\":\"stream_revoked\"}\n\n")
					if flusher != nil {
						flusher.Flush()
					}
				}
				return
			}
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if rerr != nil {
				if isSSE && admitted.Context().Err() != nil {
					_, _ = io.WriteString(w, "event: error\ndata: {\"code\":\"cage_rebind_required\",\"reason\":\"stream_revoked\"}\n\n")
					if flusher != nil {
						flusher.Flush()
					}
				}
				return
			}
		}
	}
}

func (s *EdgeServer) handleIngressWebSocket(
	w http.ResponseWriter,
	r *http.Request,
	admitted *AdmittedStream,
	leaseToken string,
	targetURL string,
) {
	secKey := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if secKey == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	// Open bidirectional full-duplex H2 stream to Landing along route_chain BEFORE hijacking!
	pr, pw := io.Pipe()
	bridgeResp, err := s.dispatchTunnelWSBridge(admitted.Context(), admitted.Claims().RouteChain, 0, leaseToken, targetURL, r.Header, pr)
	if err != nil {
		_ = pw.Close()
		http.Error(w, fmt.Sprintf("ws bridge failed: %v", err), http.StatusBadGateway)
		return
	}
	if bridgeResp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(bridgeResp.Body, 4096))
		_ = bridgeResp.Body.Close()
		_ = pw.Close()
		http.Error(w, string(errBody), bridgeResp.StatusCode)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = bridgeResp.Body.Close()
		_ = pw.Close()
		http.Error(w, "websocket hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, clientRW, err := hj.Hijack()
	if err != nil {
		_ = bridgeResp.Body.Close()
		_ = pw.Close()
		return
	}
	defer func() {
		_ = pw.Close()
		_ = bridgeResp.Body.Close()
		_ = clientConn.Close()
	}()

	// Complete RFC 6455 handshake with client.
	accept := ComputeWebSocketAccept(secKey)
	_, err = fmt.Fprintf(clientRW,
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		accept,
	)
	if err != nil {
		return
	}
	if err := clientRW.Flush(); err != nil {
		return
	}

	var writeMu sync.Mutex
	writeClientFrame := func(op byte, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return WriteRFC6455Frame(clientConn, op, payload, false)
	}

	done := make(chan struct{}, 2)

	// Watch revocation / stale snapshot -> send RFC 6455 close code 4009 immediately!
	go func() {
		<-admitted.Context().Done()
		writeMu.Lock()
		_ = WriteRFC6455Close(clientConn, WSCloseCageRebind, "stream_revoked", false)
		writeMu.Unlock()
		_ = pw.Close()
		_ = clientConn.Close()
	}()

	// Client WS frames -> H2 ws-bridge
	go func() {
		defer func() {
			_ = pw.Close()
			done <- struct{}{}
		}()
		for {
			op, payload, rerr := ReadRFC6455Frame(clientRW, edgeproto.DefaultMaxWSFrameBytes)
			if rerr != nil {
				return
			}
			if werr := edgeproto.WriteWSFrame(pw, op, payload); werr != nil {
				return
			}
			if op == edgeproto.WSOpClose {
				return
			}
		}
	}()

	// H2 ws-bridge -> Client WS frames
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			op, payload, rerr := edgeproto.ReadWSFrame(bridgeResp.Body, edgeproto.DefaultMaxWSFrameBytes)
			if rerr != nil {
				return
			}
			if werr := writeClientFrame(op, payload); werr != nil {
				return
			}
			if op == edgeproto.WSOpClose {
				return
			}
		}
	}()

	<-done
}

// ---------- Tunnel Dispatch Helpers (Direct / 1-Way IPLC / Reverse Tunnel) ----------

func (s *EdgeServer) nextHopDispatch(
	ctx context.Context,
	route []edgeproto.RouteHop,
	curHopIdx int,
	path string,
	leaseToken string,
	method string,
	targetURL string,
	origHeaders http.Header,
	body io.Reader,
) (*http.Response, error) {
	nextIdx := curHopIdx + 1
	if len(route) == 0 {
		return nil, errors.New("edge: empty route chain")
	}
	if nextIdx >= len(route) {
		// Current node IS the final landing hop — execute directly locally via internal dispatch!
		return nil, errors.New("edge: no next hop in route")
	}

	nextHop := route[nextIdx]
	routeHdr, err := edgeproto.EncodeRouteHeader(route)
	if err != nil {
		return nil, err
	}

	reqURL := "http://" + nextHop.Addr + path
	if nextHop.LinkClass == "reverse_tunnel" {
		reqURL = fmt.Sprintf("http://node-%d.edge.internal%s", nextHop.NodeID, path)
	}
	fwdReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, body)
	if err != nil {
		return nil, err
	}
	if path == edgeproto.TunnelWSBridgePath {
		fwdReq.ContentLength = -1
	}
	copyForwardHeaders(fwdReq.Header, origHeaders)
	fwdReq.Header.Set(edgeproto.HeaderRoute, routeHdr)
	fwdReq.Header.Set(edgeproto.HeaderHopIndex, strconv.Itoa(nextIdx))
	fwdReq.Header.Set(edgeproto.HeaderLease, leaseToken)
	fwdReq.Header.Set(edgeproto.HeaderUpstreamMethod, method)
	fwdReq.Header.Set(edgeproto.HeaderUpstreamURL, targetURL)

	if nextHop.LinkClass == "reverse_tunnel" {
		if s.reverseHub == nil {
			return nil, edgeproto.ErrReverseTunnelUnavailable
		}
		return s.reverseHub.RoundTrip(nextHop.NodeID, fwdReq)
	}
	return s.h2Client.Do(fwdReq)
}

func (s *EdgeServer) dispatchTunnelHTTP(
	ctx context.Context,
	route []edgeproto.RouteHop,
	curHopIdx int,
	leaseToken, method, targetURL string,
	origHeaders http.Header,
	bodyBytes []byte,
) (*http.Response, error) {
	// If single-hop (ingress relay IS also landing node), invoke locally over loopback/in-process.
	if len(route) == 1 && route[0].NodeID == s.cfg.NodeID {
		return s.nextHopDispatch(ctx, []edgeproto.RouteHop{route[0], route[0]}, 0, edgeproto.TunnelExecutePath, leaseToken, method, targetURL, origHeaders, bytes.NewReader(bodyBytes))
	}
	return s.nextHopDispatch(ctx, route, curHopIdx, edgeproto.TunnelExecutePath, leaseToken, method, targetURL, origHeaders, bytes.NewReader(bodyBytes))
}

func (s *EdgeServer) dispatchTunnelWSBridge(
	ctx context.Context,
	route []edgeproto.RouteHop,
	curHopIdx int,
	leaseToken, targetURL string,
	origHeaders http.Header,
	body io.Reader,
) (*http.Response, error) {
	if len(route) == 1 && route[0].NodeID == s.cfg.NodeID {
		return s.nextHopDispatch(ctx, []edgeproto.RouteHop{route[0], route[0]}, 0, edgeproto.TunnelWSBridgePath, leaseToken, http.MethodGet, targetURL, origHeaders, body)
	}
	return s.nextHopDispatch(ctx, route, curHopIdx, edgeproto.TunnelWSBridgePath, leaseToken, http.MethodGet, targetURL, origHeaders, body)
}

// ---------- Transit & Landing HTTP / SSE Execution ----------

func (s *EdgeServer) handleTunnelExecute(w http.ResponseWriter, r *http.Request) {
	route, err := edgeproto.DecodeRouteHeader(r.Header.Get(edgeproto.HeaderRoute))
	if err != nil || len(route) == 0 {
		http.Error(w, "invalid X-Berth-Route header", http.StatusBadRequest)
		return
	}
	hopIdx, err := strconv.Atoi(strings.TrimSpace(r.Header.Get(edgeproto.HeaderHopIndex)))
	if err != nil || hopIdx < 0 || hopIdx >= len(route) {
		http.Error(w, "invalid X-Berth-Hop-Index header", http.StatusBadRequest)
		return
	}

	// Transit forwarding hop!
	if hopIdx < len(route)-1 {
		if !s.cfg.HasRole(RoleTransit) && !s.cfg.HasRole(RoleIngressRelay) {
			http.Error(w, "transit role not enabled", http.StatusForbidden)
			return
		}
		resp, err := s.nextHopDispatch(
			r.Context(),
			route,
			hopIdx,
			edgeproto.TunnelExecutePath,
			r.Header.Get(edgeproto.HeaderLease),
			r.Header.Get(edgeproto.HeaderUpstreamMethod),
			r.Header.Get(edgeproto.HeaderUpstreamURL),
			r.Header,
			r.Body,
		)
		if err != nil {
			http.Error(w, fmt.Sprintf("transit hop failed: %v", err), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		copyForwardHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		streamCopyWithFlush(w, resp.Body)
		return
	}

	// Final Landing / Compat execution hop!
	s.handleLandingExecute(w, r)
}

func (s *EdgeServer) handleLandingExecute(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.HasRole(RoleLanding) && !s.cfg.HasRole(RoleCompat) {
		http.Error(w, "landing/compat role not enabled", http.StatusForbidden)
		return
	}

	startTime := time.Now()
	leaseToken := extractBearerLease(r)

	// SINGLE FENCED ADMISSION GATE (Codex Blocker #1.1 & #1.2).
	admitted, err := s.gate.Admit(r.Context(), leaseToken, s.cfg.NodeID, nil)
	if err != nil {
		writeAdmissionError(w, err)
		return
	}
	defer admitted.Release()
	claims := admitted.Claims()

	// Pre-debit request ingress bytes chunk-by-chunk BEFORE sending to upstream!
	var ingressBytes int64
	var reqBuf bytes.Buffer
	if r.Body != nil {
		chunk := make([]byte, min(s.cfg.PreDebitChunkSize, 32*1024))
		for {
			n, rerr := r.Body.Read(chunk)
			if n > 0 {
				if _, derr := admitted.PreDebit(admitted.Context(), int64(n)); derr != nil {
					s.recordReceipt(claims, ingressBytes, 0, http.StatusForbidden, 0, time.Since(startTime))
					writeAdmissionError(w, derr)
					return
				}
				ingressBytes += int64(n)
				_, _ = reqBuf.Write(chunk[:n])
			}
			if errors.Is(rerr, io.EOF) {
				break
			}
			if rerr != nil {
				http.Error(w, "failed reading request stream", http.StatusBadRequest)
				return
			}
		}
	}

	upMethod := strings.TrimSpace(r.Header.Get(edgeproto.HeaderUpstreamMethod))
	if upMethod == "" {
		upMethod = http.MethodPost
	}
	upURL := strings.TrimSpace(r.Header.Get(edgeproto.HeaderUpstreamURL))
	if upURL == "" {
		http.Error(w, "missing X-Berth-Upstream-URL", http.StatusBadRequest)
		return
	}

	upReq, err := http.NewRequestWithContext(admitted.Context(), upMethod, upURL, bytes.NewReader(reqBuf.Bytes()))
	if err != nil {
		http.Error(w, "invalid upstream request", http.StatusBadRequest)
		return
	}
	copyUpstreamHeaders(upReq.Header, r.Header)

	upResp, err := s.upstream.DoHTTP(admitted.Context(), upReq, claims)
	if err != nil {
		statusCode := http.StatusBadGateway
		if errors.Is(err, ErrSSRFAuthorityBlocked) || errors.Is(err, ErrSSRFSchemeBlocked) || errors.Is(err, ErrSSRFPrivateIPBlocked) {
			statusCode = http.StatusForbidden
		}
		s.recordReceipt(claims, ingressBytes, 0, statusCode, 0, time.Since(startTime))
		http.Error(w, fmt.Sprintf("upstream error: %v", err), statusCode)
		return
	}
	defer func() { _ = upResp.Body.Close() }()

	// Stream response while pre-debiting egress chunks BEFORE writing back to caller!
	copyForwardHeaders(w.Header(), upResp.Header)
	w.Header().Set(edgeproto.HeaderAccountID, strconv.FormatInt(claims.AccountID, 10))
	w.Header().Set(edgeproto.HeaderLandingNode, s.cfg.NodeName)
	w.Header().Set(edgeproto.HeaderCageCohort, fmt.Sprintf("%s:%s:%s", claims.Platform, claims.CohortCountryCode, claims.CohortTimezone))
	w.WriteHeader(upResp.StatusCode)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	var egressBytes int64
	var ttftMs int64
	isSSE := strings.Contains(strings.ToLower(upResp.Header.Get("Content-Type")), "text/event-stream")
	buf := make([]byte, min(s.cfg.PreDebitChunkSize, 32*1024))
	for {
		if err := admitted.Context().Err(); err != nil {
			if isSSE {
				_, _ = io.WriteString(w, "event: error\ndata: {\"code\":\"cage_rebind_required\",\"reason\":\"stream_revoked\"}\n\n")
				if flusher != nil {
					flusher.Flush()
				}
			}
			break
		}
		n, rerr := upResp.Body.Read(buf)
		if n > 0 {
			if ttftMs == 0 {
				ttftMs = time.Since(startTime).Milliseconds()
			}
			// Pre-debit up to n bytes BEFORE forwarding to stop at the exact last admitted byte!
			allowed, _, derr := admitted.PreDebitUpTo(admitted.Context(), int64(n))
			if allowed > 0 {
				if _, werr := w.Write(buf[:allowed]); werr != nil {
					break
				}
				egressBytes += allowed
				if flusher != nil {
					flusher.Flush()
				}
			}
			if derr != nil || allowed < int64(n) {
				// Exact byte-cap cutoff reached — fail closed immediately!
				if isSSE {
					_, _ = io.WriteString(w, "event: error\ndata: {\"code\":\"landing_grant_exhausted\"}\n\n")
					if flusher != nil {
						flusher.Flush()
					}
				}
				break
			}
		}
		if rerr != nil {
			break
		}
	}

	// DURABLY PERSIST TERMINAL RECEIPT TO OUTBOX WAL BEFORE COMPLETING (Codex Blocker #1.1).
	s.recordReceipt(claims, ingressBytes, egressBytes, upResp.StatusCode, ttftMs, time.Since(startTime))
}

// ---------- Transit & Landing Full-Duplex WebSocket Bridge ----------

func (s *EdgeServer) handleTunnelWSBridge(w http.ResponseWriter, r *http.Request) {
	route, err := edgeproto.DecodeRouteHeader(r.Header.Get(edgeproto.HeaderRoute))
	if err != nil || len(route) == 0 {
		http.Error(w, "invalid X-Berth-Route header", http.StatusBadRequest)
		return
	}
	hopIdx, err := strconv.Atoi(strings.TrimSpace(r.Header.Get(edgeproto.HeaderHopIndex)))
	if err != nil || hopIdx < 0 || hopIdx >= len(route) {
		http.Error(w, "invalid X-Berth-Hop-Index header", http.StatusBadRequest)
		return
	}

	// Transit hop: forward full-duplex H2 stream opaquely!
	if hopIdx < len(route)-1 {
		if !s.cfg.HasRole(RoleTransit) && !s.cfg.HasRole(RoleIngressRelay) {
			http.Error(w, "transit role not enabled", http.StatusForbidden)
			return
		}
		resp, err := s.nextHopDispatch(
			r.Context(),
			route,
			hopIdx,
			edgeproto.TunnelWSBridgePath,
			r.Header.Get(edgeproto.HeaderLease),
			http.MethodGet,
			r.Header.Get(edgeproto.HeaderUpstreamURL),
			r.Header,
			r.Body,
		)
		if err != nil {
			http.Error(w, fmt.Sprintf("transit ws hop failed: %v", err), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		streamCopyWithFlush(w, resp.Body)
		return
	}

	// Final Landing / Compat WS hop — passes through the SAME single AdmissionGate!
	if !s.cfg.HasRole(RoleLanding) && !s.cfg.HasRole(RoleCompat) {
		http.Error(w, "landing/compat role not enabled", http.StatusForbidden)
		return
	}

	startTime := time.Now()
	leaseToken := extractBearerLease(r)
	var upConnMu sync.Mutex
	var upConn net.Conn

	admitted, err := s.gate.Admit(r.Context(), leaseToken, s.cfg.NodeID, func(reason error) {
		upConnMu.Lock()
		c := upConn
		upConnMu.Unlock()
		if c != nil {
			_ = WriteRFC6455Close(c, WSCloseCageRebind, "stream_revoked", true)
			_ = c.Close()
		}
	})
	if err != nil {
		writeAdmissionError(w, err)
		return
	}
	defer admitted.Release()
	claims := admitted.Claims()

	upURL := strings.TrimSpace(r.Header.Get(edgeproto.HeaderUpstreamURL))
	if upURL == "" {
		http.Error(w, "missing X-Berth-Upstream-URL", http.StatusBadRequest)
		return
	}

	upHeaders := http.Header{}
	copyUpstreamHeaders(upHeaders, r.Header)
	conn, br, _, err := s.upstream.DialWebSocket(admitted.Context(), upURL, upHeaders, claims)
	if err != nil {
		statusCode := http.StatusBadGateway
		if errors.Is(err, ErrSSRFAuthorityBlocked) || errors.Is(err, ErrSSRFSchemeBlocked) || errors.Is(err, ErrSSRFPrivateIPBlocked) {
			statusCode = http.StatusForbidden
		}
		s.recordReceipt(claims, 0, 0, statusCode, 0, time.Since(startTime))
		http.Error(w, fmt.Sprintf("upstream ws error: %v", err), statusCode)
		return
	}
	upConnMu.Lock()
	upConn = conn
	upConnMu.Unlock()
	defer func() { _ = conn.Close() }()

	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}

	var ingressBytes, egressBytes int64
	var bytesMu sync.Mutex
	var writeRespMu sync.Mutex

	sendClose4009 := func(reason string) {
		payload := make([]byte, 2+len(reason))
		binary.BigEndian.PutUint16(payload[:2], WSCloseCageRebind)
		copy(payload[2:], reason)
		writeRespMu.Lock()
		_ = edgeproto.WriteWSFrame(w, edgeproto.WSOpClose, payload)
		writeRespMu.Unlock()
	}

	done := make(chan struct{}, 2)

	// Inbound H2 bridge -> Upstream WS (pre-debiting ingress frames!)
	go func() {
		defer func() {
			_ = conn.Close()
			done <- struct{}{}
		}()
		for {
			op, payload, rerr := edgeproto.ReadWSFrame(r.Body, edgeproto.DefaultMaxWSFrameBytes)
			if rerr != nil {
				return
			}
			if len(payload) > 0 {
				if _, derr := admitted.PreDebit(admitted.Context(), int64(len(payload))); derr != nil {
					sendClose4009("landing_grant_exhausted")
					return
				}
				bytesMu.Lock()
				ingressBytes += int64(len(payload))
				bytesMu.Unlock()
			}
			if werr := WriteRFC6455Frame(conn, op, payload, true); werr != nil {
				return
			}
			if op == edgeproto.WSOpClose {
				return
			}
		}
	}()

	// Upstream WS -> Outbound H2 bridge (pre-debiting egress frames!)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			op, payload, rerr := ReadRFC6455Frame(br, edgeproto.DefaultMaxWSFrameBytes)
			if rerr != nil {
				if admitted.Context().Err() != nil {
					sendClose4009("stream_revoked")
				}
				return
			}
			if len(payload) > 0 && op != edgeproto.WSOpClose {
				if _, derr := admitted.PreDebit(admitted.Context(), int64(len(payload))); derr != nil {
					sendClose4009("landing_grant_exhausted")
					return
				}
				bytesMu.Lock()
				egressBytes += int64(len(payload))
				bytesMu.Unlock()
			}
			writeRespMu.Lock()
			werr := edgeproto.WriteWSFrame(w, op, payload)
			writeRespMu.Unlock()
			if werr != nil || op == edgeproto.WSOpClose {
				return
			}
		}
	}()

	select {
	case <-admitted.Context().Done():
		sendClose4009("stream_revoked")
		_ = conn.Close()
	case <-done:
	}

	bytesMu.Lock()
	inB, outB := ingressBytes, egressBytes
	bytesMu.Unlock()
	s.recordReceipt(claims, inB, outB, http.StatusSwitchingProtocols, 0, time.Since(startTime))
}

// ExecutePendingOAuthTasks polls Berth Central for OAuth/refresh/probe tasks and
// executes them locally from this Landing node so Central NEVER contacts AI providers.
func (s *EdgeServer) ExecutePendingOAuthTasks(ctx context.Context) (int, error) {
	if s.central == nil || (!s.cfg.HasRole(RoleLanding) && !s.cfg.HasRole(RoleCompat)) {
		return 0, nil
	}
	tasks, err := s.central.PollOAuthTasks(ctx)
	if err != nil {
		return 0, err
	}
	executed := 0
	for _, task := range tasks {
		if err := s.ssrfGuard.ValidateOAuthDiscoveryURL(task.TargetURL); err != nil {
			_ = s.central.CompleteOAuthTask(ctx, task.TaskID, http.StatusForbidden, "", err.Error())
			continue
		}
		var body []byte
		if task.BodyBase64 != "" {
			body, _ = base64.StdEncoding.DecodeString(task.BodyBase64)
		}
		method := task.Method
		if method == "" {
			method = http.MethodPost
		}
		req, err := http.NewRequestWithContext(ctx, method, task.TargetURL, bytes.NewReader(body))
		if err != nil {
			_ = s.central.CompleteOAuthTask(ctx, task.TaskID, 0, "", err.Error())
			continue
		}
		for k, v := range task.Headers {
			req.Header.Set(k, v)
		}
		resp, err := s.upstream.DoHTTP(ctx, req, nil)
		if err != nil {
			_ = s.central.CompleteOAuthTask(ctx, task.TaskID, 0, "", err.Error())
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		_ = resp.Body.Close()
		_ = s.central.CompleteOAuthTask(ctx, task.TaskID, resp.StatusCode, string(respBody), "")
		executed++
	}
	return executed, nil
}

func (s *EdgeServer) recordReceipt(claims *edgeproto.SessionLeaseClaims, inB, outB int64, statusCode int, ttftMs int64, dur time.Duration) {
	if s.outbox == nil || claims == nil {
		return
	}
	_ = s.outbox.Append(edgeproto.UsageReceipt{
		ReceiptID:     newReceiptID(),
		NodeID:        s.cfg.NodeID,
		LeaseID:       claims.LeaseID,
		GrantID:       claims.GrantID,
		UserID:        claims.UserID,
		APIKeyID:      claims.APIKeyID,
		AccountID:     claims.AccountID,
		WorkSessionID: claims.WorkSessionID,
		Platform:      claims.Platform,
		IngressBytes:  inB,
		EgressBytes:   outB,
		TotalBytes:    inB + outB,
		RequestCount:  1,
		StatusCode:    statusCode,
		TTFTMs:        ttftMs,
		DurationMs:    dur.Milliseconds(),
		CreatedAtUnix: time.Now().Unix(),
	})
}

func writeAdmissionError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case errors.Is(err, edgeproto.ErrGrantSliceExhausted), errors.Is(err, edgeproto.ErrGrantWALExpired), errors.Is(err, edgeproto.ErrGrantWALRevoked):
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "landing_grant_exhausted", "message": err.Error()}})
	case errors.Is(err, ErrGrantConcurrencyLimit), errors.Is(err, ErrGrantRPMLimit):
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "landing_grant_rate_limited", "message": err.Error()}})
	case errors.Is(err, edgeproto.ErrLeaseRevoked), errors.Is(err, edgeproto.ErrGrantRevoked), errors.Is(err, edgeproto.ErrAPIKeyRevoked), errors.Is(err, edgeproto.ErrCageEpochStale), errors.Is(err, ErrLandingNodeMismatch):
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "lease_revoked", "message": err.Error()}})
	case errors.Is(err, edgeproto.ErrRevocationSnapshotMissing), errors.Is(err, edgeproto.ErrRevocationSnapshotStale), errors.Is(err, edgeproto.ErrRevocationSnapshotBehind):
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "revocation_snapshot_stale", "message": err.Error()}})
	default:
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "lease_unauthorized", "message": err.Error()}})
	}
}

func copyForwardHeaders(dst, src http.Header) {
	for k, vals := range src {
		lk := strings.ToLower(k)
		if lk == "connection" || lk == "keep-alive" || lk == "proxy-authenticate" ||
			lk == "proxy-authorization" || lk == "te" || lk == "trailers" ||
			lk == "transfer-encoding" || lk == "upgrade" || lk == "content-length" {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func copyUpstreamHeaders(dst, src http.Header) {
	for k, vals := range src {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-berth-") || lk == "authorization" ||
			lk == "host" || lk == "connection" || lk == "transfer-encoding" ||
			lk == "content-length" || lk == "upgrade" {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func streamCopyWithFlush(w http.ResponseWriter, src io.Reader) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 16*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}
