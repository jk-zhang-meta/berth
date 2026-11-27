package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jk-zhang-meta/berth/internal/pkg/proxyutil"
)

const (
	edgeInternalHostSuffix  = ".edge.internal"
	maxEdgeOAuthRequestBody = 4 * 1024 * 1024
	defaultEdgeOAuthTimeout = 35 * time.Second
)

var (
	defaultEdgeLeaseMu  sync.RWMutex
	defaultEdgeLeaseSvc *BerthEdgeLeaseService
)

// RegisterDefaultEdgeLeaseService wires the active BerthEdgeLeaseService so OAuth
// and token-refresh HTTP clients bound to `*.edge.internal` Landing grant proxies
// automatically dispatch upstream HTTP calls through the bound Landing node's
// `berth-edge` daemon instead of dialing the virtual hostname from Central.
func RegisterDefaultEdgeLeaseService(svc *BerthEdgeLeaseService) {
	defaultEdgeLeaseMu.Lock()
	defaultEdgeLeaseSvc = svc
	defaultEdgeLeaseMu.Unlock()
	if svc != nil {
		proxyutil.RegisterEdgeRoundTripperFactory(NewEdgeLandingRoundTripper)
	} else {
		proxyutil.RegisterEdgeRoundTripperFactory(nil)
	}
}

func getDefaultEdgeLeaseService() *BerthEdgeLeaseService {
	defaultEdgeLeaseMu.RLock()
	svc := defaultEdgeLeaseSvc
	defaultEdgeLeaseMu.RUnlock()
	return svc
}

// EdgeInternalProxyHost returns the canonical, rename-safe virtual proxy host
// for a Berth Edge Landing node (`node-<id>.edge.internal`). Using the numeric
// node ID ensures proxies.host remains RFC-3986 / DNS-safe regardless of
// Unicode characters, spaces, parentheses, or future node renames in the UI.
func EdgeInternalProxyHost(nodeID int64) string {
	return fmt.Sprintf("node-%d%s", nodeID, edgeInternalHostSuffix)
}

// IsReservedEdgeInternalHost reports whether host targets Berth's reserved
// internal virtual landing namespace (`edge.internal` or `*.edge.internal`).
// User-supplied external proxy creation/updates MUST reject reserved hosts.
func IsReservedEdgeInternalHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return false
	}
	return h == strings.TrimPrefix(edgeInternalHostSuffix, ".") || strings.HasSuffix(h, edgeInternalHostSuffix)
}

// ParseEdgeInternalNodeID parses a canonical `node-<id>` selector into a positive node ID.
func ParseEdgeInternalNodeID(selector string) (int64, bool) {
	s := strings.ToLower(strings.TrimSpace(selector))
	if !strings.HasPrefix(s, "node-") {
		return 0, false
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(s, "node-"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// TruncateUTF8Bytes truncates s so its UTF-8 byte length is <= maxBytes without
// splitting a multi-byte rune. This aligns SQL inserts with Ent's byte-length MaxLen checks.
func TruncateUTF8Bytes(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	n := maxBytes
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func formatEdgeLandingProxyName(nodeName string, userID int64) string {
	const prefix = "edge-landing-"
	suffix := fmt.Sprintf("-u%d", userID)
	budget := 100 - len(prefix) - len(suffix)
	if budget < 0 {
		return TruncateUTF8Bytes(prefix+suffix, 100)
	}
	return prefix + TruncateUTF8Bytes(strings.TrimSpace(nodeName), budget) + suffix
}

func findEdgeLandingNode(nodes []EdgeNode, selector string) *EdgeNode {
	trimmed := strings.TrimSpace(selector)
	if trimmed == "" {
		return nil
	}
	if id, ok := ParseEdgeInternalNodeID(trimmed); ok {
		for i := range nodes {
			if nodes[i].ID == id {
				return &nodes[i]
			}
		}
		return nil
	}
	for i := range nodes {
		if strings.EqualFold(strings.TrimSpace(nodes[i].Name), trimmed) {
			return &nodes[i]
		}
	}
	if unescaped, err := url.PathUnescape(trimmed); err == nil && unescaped != trimmed {
		for i := range nodes {
			if strings.EqualFold(strings.TrimSpace(nodes[i].Name), strings.TrimSpace(unescaped)) {
				return &nodes[i]
			}
		}
	}
	return nil
}

// ParseEdgeInternalNodeName returns the edge node selector (`node-<id>` or legacy
// `<node-name>`) if proxyURL points to a Berth virtual `edge_landing_grant` host
// (`*.edge.internal`).
func ParseEdgeInternalNodeName(proxyURL string) (string, bool) {
	raw := strings.TrimSpace(proxyURL)
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if !strings.HasSuffix(host, edgeInternalHostSuffix) {
		return "", false
	}
	nodeName := strings.TrimSuffix(host, edgeInternalHostSuffix)
	if nodeName == "" {
		return "", false
	}
	return nodeName, true
}

// NewEdgeLandingRoundTripper returns an http.RoundTripper that executes requests
// through the bound Berth Edge Landing node when proxyURL targets `*.edge.internal`.
// Returns nil for ordinary external proxies or direct URLs.
func NewEdgeLandingRoundTripper(proxyURL string) http.RoundTripper {
	return NewEdgeLandingRoundTripperForAccount(proxyURL, 0)
}

// NewEdgeLandingRoundTripperForAccount is identical to NewEdgeLandingRoundTripper but
// carries the authoritative accountID so the Landing node binds isolated per-account
// TLS session resumption (and disables resumption when accountID <= 0).
func NewEdgeLandingRoundTripperForAccount(proxyURL string, accountID int64) http.RoundTripper {
	nodeName, ok := ParseEdgeInternalNodeName(proxyURL)
	if !ok {
		return nil
	}
	return &edgeLandingRoundTripper{nodeName: nodeName, accountID: accountID}
}

type edgeLandingRoundTripper struct {
	nodeName  string
	accountID int64
}

func (rt *edgeLandingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	svc := getDefaultEdgeLeaseService()
	if svc == nil {
		return nil, fmt.Errorf("edge landing proxy %q unavailable: BerthEdgeLeaseService not registered", rt.nodeName)
	}
	return svc.ExecuteOAuthTaskSyncForAccount(req.Context(), rt.nodeName, rt.accountID, req)
}

// WaitPendingOAuthTasks returns any pending OAuth tasks for nodeID immediately, or
// waits up to maxWait until a new task is enqueued for nodeID (long-poll wakeup).
func (s *BerthEdgeLeaseService) WaitPendingOAuthTasks(ctx context.Context, nodeID int64, maxWait time.Duration) []EdgeOAuthTask {
	if tasks := s.ListPendingOAuthTasks(nodeID); len(tasks) > 0 || maxWait <= 0 {
		return tasks
	}

	s.mu.Lock()
	if s.oauthNotifyByNode == nil {
		s.oauthNotifyByNode = make(map[int64]chan struct{})
	}
	ch, ok := s.oauthNotifyByNode[nodeID]
	if !ok {
		ch = make(chan struct{})
		s.oauthNotifyByNode[nodeID] = ch
	}
	s.mu.Unlock()

	if tasks := s.ListPendingOAuthTasks(nodeID); len(tasks) > 0 {
		return tasks
	}

	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	select {
	case <-ch:
		return s.ListPendingOAuthTasks(nodeID)
	case <-timer.C:
		return s.ListPendingOAuthTasks(nodeID)
	case <-ctx.Done():
		return nil
	}
}

func (s *BerthEdgeLeaseService) notifyNodeOAuthLocked(nodeID int64) {
	if s.oauthNotifyByNode == nil {
		return
	}
	if ch, ok := s.oauthNotifyByNode[nodeID]; ok {
		close(ch)
		delete(s.oauthNotifyByNode, nodeID)
	}
}

// ExecuteOAuthTaskSync dispatches an outbound OAuth/refresh HTTP request strictly to
// the Landing node named nodeName and waits synchronously for its completion.
func (s *BerthEdgeLeaseService) ExecuteOAuthTaskSync(ctx context.Context, nodeName string, req *http.Request) (*http.Response, error) {
	return s.ExecuteOAuthTaskSyncForAccount(ctx, nodeName, 0, req)
}

// ExecuteOAuthTaskSyncForAccount dispatches a single-hop outbound HTTP request through
// the Landing node named nodeName, carrying accountID for isolated TLS session resumption
// (or disabled resumption when accountID <= 0) and returning exact status/headers/bytes
// without internal redirect following so the Go caller enforces its own redirect policy.
func (s *BerthEdgeLeaseService) ExecuteOAuthTaskSyncForAccount(ctx context.Context, nodeName string, accountID int64, req *http.Request) (*http.Response, error) {
	if s == nil || s.zones == nil {
		return nil, errors.New("edge landing OAuth dispatch unavailable")
	}
	if req == nil || req.URL == nil || strings.TrimSpace(req.URL.Host) == "" {
		return nil, errors.New("edge landing OAuth request missing target URL")
	}
	nodes, err := s.zones.ListNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("lookup edge landing node %q: %w", nodeName, err)
	}
	targetNode := findEdgeLandingNode(nodes, nodeName)
	if targetNode == nil {
		return nil, fmt.Errorf("edge landing node %q not found", nodeName)
	}
	if targetNode.Status != EdgeNodeStatusActive && targetNode.Status != EdgeNodeStatusDraining {
		return nil, fmt.Errorf("edge landing node %q is %s (must be active)", nodeName, targetNode.Status)
	}
	if !targetNode.HasRole(EdgeRoleLanding) && !targetNode.HasRole(EdgeRoleCompat) {
		return nil, fmt.Errorf("edge landing node %q does not have landing role", nodeName)
	}
	if accountID > 0 {
		if authVerifier, ok := s.store.(edgeLandingOAuthAuthVerifier); ok {
			if err := authVerifier.VerifyAccountEdgeLandingAuthorization(ctx, accountID, targetNode.ID); err != nil {
				return nil, fmt.Errorf("edge landing OAuth authorization denied for account %d on node %d: %w", accountID, targetNode.ID, err)
			}
		}
	}

	var bodyBytes []byte
	if req.Body != nil {
		var rErr error
		bodyBytes, rErr = io.ReadAll(io.LimitReader(req.Body, maxEdgeOAuthRequestBody+1))
		_ = req.Body.Close()
		if rErr != nil {
			return nil, fmt.Errorf("read OAuth request body: %w", rErr)
		}
		if len(bodyBytes) > maxEdgeOAuthRequestBody {
			return nil, fmt.Errorf("OAuth request body exceeds %d bytes", maxEdgeOAuthRequestBody)
		}
	}

	headers := make(map[string]string, len(req.Header))
	for k, vals := range req.Header {
		if len(vals) == 0 {
			continue
		}
		lk := strings.ToLower(k)
		if lk == "host" || lk == "content-length" || lk == "connection" || lk == "accept-encoding" {
			continue
		}
		if lk == "cookie" {
			headers[k] = strings.Join(vals, "; ")
		} else {
			headers[k] = strings.Join(vals, ", ")
		}
	}

	task := s.EnqueueOAuthTask(EdgeOAuthTask{
		NodeID:          targetNode.ID,
		AccountID:       accountID,
		Kind:            "oauth_exchange",
		TargetURL:       req.URL.String(),
		Method:          req.Method,
		Headers:         headers,
		BodyBase64:      base64.StdEncoding.EncodeToString(bodyBytes),
		FollowRedirects: false,
	})
	if task.Status == "failed" {
		return nil, fmt.Errorf("edge landing node %q rejected OAuth task: %s", nodeName, task.Error)
	}

	s.mu.Lock()
	var waitCh chan struct{}
	if t, ok := s.oauthTaskIndex[task.TaskID]; ok && (t.Status == "pending" || t.Status == "claimed") {
		if s.oauthWaiters == nil {
			s.oauthWaiters = make(map[string]chan struct{})
		}
		var exists bool
		waitCh, exists = s.oauthWaiters[task.TaskID]
		if !exists {
			waitCh = make(chan struct{})
			s.oauthWaiters[task.TaskID] = waitCh
		}
	}
	s.mu.Unlock()

	if waitCh != nil {
		waitCtx := ctx
		var cancel context.CancelFunc
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			waitCtx, cancel = context.WithTimeout(ctx, defaultEdgeOAuthTimeout)
			defer cancel()
		}

		select {
		case <-waitCh:
		case <-waitCtx.Done():
			s.CancelOAuthTask(targetNode.ID, task.TaskID, "timed out waiting for edge landing node")
			return nil, fmt.Errorf("edge landing node %q timed out executing OAuth task %s: %w", nodeName, task.TaskID, waitCtx.Err())
		}
	}

	snap, _ := s.ConsumeOAuthTask(task.TaskID)

	if snap.Status == "failed" || snap.Error != "" {
		return nil, fmt.Errorf("edge landing node %q OAuth request failed: %s", nodeName, snap.Error)
	}
	if snap.StatusCode <= 0 {
		return nil, fmt.Errorf("edge landing node %q returned invalid HTTP status %d", nodeName, snap.StatusCode)
	}

	var respBytes []byte
	if snap.RespBodyBase64 != "" {
		decoded, decErr := base64.StdEncoding.DecodeString(snap.RespBodyBase64)
		if decErr != nil {
			return nil, fmt.Errorf("edge landing node %q returned invalid base64 response body: %w", nodeName, decErr)
		}
		respBytes = decoded
	} else {
		respBytes = []byte(snap.RespBody)
	}

	respHeader := make(http.Header, len(snap.RespHeaders)+1)
	for k, vals := range snap.RespHeaders {
		for _, v := range vals {
			respHeader.Add(k, v)
		}
	}
	if respHeader.Get("Content-Type") == "" {
		trimmedBody := bytes.TrimSpace(respBytes)
		if len(trimmedBody) > 0 && (trimmedBody[0] == '{' || trimmedBody[0] == '[') {
			respHeader.Set("Content-Type", "application/json")
		} else if bytes.HasPrefix(trimmedBody, []byte("event:")) || bytes.HasPrefix(trimmedBody, []byte("data:")) {
			respHeader.Set("Content-Type", "text/event-stream")
		} else {
			respHeader.Set("Content-Type", "text/plain; charset=utf-8")
		}
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", snap.StatusCode, http.StatusText(snap.StatusCode)),
		StatusCode:    snap.StatusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        respHeader,
		Body:          io.NopCloser(bytes.NewReader(respBytes)),
		ContentLength: int64(len(respBytes)),
		Request:       req,
	}, nil
}

// ProbeEdgeLandingNode verifies a live Berth Edge Landing node backing a virtual
// `*.edge.internal` proxy: requires a fresh heartbeat, a non-empty observed exit IP,
// and a live Central <-> Landing health_probe round-trip to measure real latency.
func ProbeEdgeLandingNode(ctx context.Context, nodeName string) (*ProxyExitInfo, int64, error) {
	svc := getDefaultEdgeLeaseService()
	if svc == nil || svc.zones == nil {
		return nil, 0, fmt.Errorf("edge landing proxy %q unavailable: BerthEdgeLeaseService not registered", nodeName)
	}
	nodes, err := svc.zones.ListNodes(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("lookup edge landing node %q: %w", nodeName, err)
	}
	n := findEdgeLandingNode(nodes, nodeName)
	if n == nil {
		return nil, 0, fmt.Errorf("edge landing node %q not found", nodeName)
	}
	if n.Status != EdgeNodeStatusActive && n.Status != EdgeNodeStatusDraining {
		return nil, 0, fmt.Errorf("edge landing node %q is %s", nodeName, n.Status)
	}
	if n.LastHeartbeatAt == nil {
		return nil, 0, fmt.Errorf("edge landing node %q has not reported a heartbeat yet", nodeName)
	}
	if time.Since(*n.LastHeartbeatAt) > 5*time.Minute {
		return nil, 0, fmt.Errorf("edge landing node %q heartbeat stale (%s ago)", nodeName, time.Since(*n.LastHeartbeatAt).Round(time.Second))
	}
	exitIP := strings.TrimSpace(n.ExitIP)
	if exitIP == "" {
		return nil, 0, fmt.Errorf("edge landing node %q has no observed exit IP", nodeName)
	}

	// Live Central <-> Landing round-trip health_probe proves the node's OAuth worker is responsive now.
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	start := time.Now()
	task := svc.EnqueueOAuthTask(EdgeOAuthTask{
		NodeID:    n.ID,
		Kind:      "health_probe",
		TargetURL: "",
		Method:    http.MethodGet,
	})
	if task.Status == "failed" {
		return nil, 0, fmt.Errorf("edge landing node %q probe enqueue failed: %s", nodeName, task.Error)
	}
	svc.mu.Lock()
	var waitCh chan struct{}
	if t, ok := svc.oauthTaskIndex[task.TaskID]; ok && (t.Status == "pending" || t.Status == "claimed") {
		waitCh = svc.oauthWaiters[task.TaskID]
	}
	svc.mu.Unlock()
	if waitCh != nil {
		select {
		case <-waitCh:
		case <-probeCtx.Done():
			svc.CancelOAuthTask(n.ID, task.TaskID, "timed out waiting for edge landing health probe")
			return nil, 0, fmt.Errorf("edge landing node %q did not respond to live probe: %w", nodeName, probeCtx.Err())
		}
	}
	snap, _ := svc.ConsumeOAuthTask(task.TaskID)
	if snap.Status == "failed" || snap.Error != "" || snap.StatusCode < 200 || snap.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("edge landing node %q live probe failed (status=%d): %s", nodeName, snap.StatusCode, snap.Error)
	}
	latencyMs := time.Since(start).Milliseconds()
	if latencyMs < 1 {
		latencyMs = 1
	}
	return &ProxyExitInfo{
		IP:          exitIP,
		CountryCode: strings.ToUpper(strings.TrimSpace(n.ExitCountryCode)),
		Timezone:    strings.TrimSpace(n.ExitTimezone),
		ASN:         strings.TrimSpace(n.ExitASNClass),
		ISP:         TruncateUTF8Bytes("Berth Edge Landing ("+n.Name+")", 255),
	}, latencyMs, nil
}

// CancelPendingOAuthTasksForNode cancels all queued (not yet completed) OAuth tasks
// targeting nodeID (used when a landing grant or node authorization is revoked).
func (s *BerthEdgeLeaseService) CancelPendingOAuthTasksForNode(nodeID int64, reason string) int {
	if s == nil || nodeID <= 0 {
		return 0
	}
	s.mu.Lock()
	var ids []string
	for _, t := range s.oauthTasksByNode[nodeID] {
		if t.Status == "pending" || t.Status == "claimed" {
			ids = append(ids, t.TaskID)
		}
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.CancelOAuthTask(nodeID, id, reason)
	}
	return len(ids)
}

type edgeLandingOAuthAuthVerifier interface {
	VerifyAccountEdgeLandingAuthorization(ctx context.Context, accountID, targetNodeID int64) error
}
