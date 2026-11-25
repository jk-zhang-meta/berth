package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jk-zhang-meta/berth/internal/config"
	"github.com/jk-zhang-meta/berth/internal/pkg/httpclient"
	"github.com/jk-zhang-meta/berth/internal/service"
)

func NewProxyExitInfoProber(cfg *config.Config) service.ProxyExitInfoProber {
	insecure := false
	allowPrivate := false
	validateResolvedIP := true
	maxResponseBytes := defaultProxyProbeResponseMaxBytes
	if cfg != nil {
		insecure = cfg.Security.ProxyProbe.InsecureSkipVerify
		allowPrivate = cfg.Security.URLAllowlist.AllowPrivateHosts
		validateResolvedIP = cfg.Security.URLAllowlist.Enabled
		if cfg.Gateway.ProxyProbeResponseReadMaxBytes > 0 {
			maxResponseBytes = cfg.Gateway.ProxyProbeResponseReadMaxBytes
		}
	}
	if insecure {
		log.Printf("[ProxyProbe] Warning: insecure_skip_verify is not allowed and will cause probe failure.")
	}
	// 构建探测 URL 列表：配置存在时覆盖内置默认列表。
	var configuredTargets []configuredProbeTarget
	if cfg != nil && len(cfg.Security.ProxyProbe.URLs) > 0 {
		configuredTargets = make([]configuredProbeTarget, 0, len(cfg.Security.ProxyProbe.URLs))
		for _, u := range cfg.Security.ProxyProbe.URLs {
			configuredTargets = append(configuredTargets, configuredProbeTarget{
				url:    u.URL,
				parser: u.Parser,
			})
		}
	}

	return &proxyProbeService{
		insecureSkipVerify:  insecure,
		allowPrivateHosts:   allowPrivate,
		validateResolvedIP:  validateResolvedIP,
		maxResponseBytes:    maxResponseBytes,
		configuredProbeURLs: configuredTargets,
	}
}

const (
	defaultProxyProbeTimeout          = 10 * time.Second
	defaultProxyProbeResponseMaxBytes = int64(1024 * 1024)
)

// probeURLs 按优先级排列的内置 HTTPS IPv4-only 出口探测 URL 列表（替代明文 ip-api?lang=zh-CN 与双栈 api64.ipify.org）。
var probeURLs = []struct {
	url    string
	parser string
}{
	{"https://ipwho.is/", "ipwho"},
	{"https://api.ip.sb/geoip", "ipsb"},
}

type configuredProbeTarget struct {
	url    string
	parser string
}

type proxyProbeService struct {
	insecureSkipVerify  bool
	allowPrivateHosts   bool
	validateResolvedIP  bool
	maxResponseBytes    int64
	configuredProbeURLs []configuredProbeTarget
}

func (s *proxyProbeService) ProbeProxy(ctx context.Context, proxyURL string) (*service.ProxyExitInfo, int64, error) {
	client, err := httpclient.GetClient(httpclient.Options{
		ProxyURL:           proxyURL,
		Timeout:            defaultProxyProbeTimeout,
		InsecureSkipVerify: s.insecureSkipVerify,
		ValidateResolvedIP: s.validateResolvedIP,
		AllowPrivateHosts:  s.allowPrivateHosts,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create proxy client: %w", err)
	}

	var lastErr error
	if len(s.configuredProbeURLs) > 0 {
		for _, probe := range s.configuredProbeURLs {
			exitInfo, latencyMs, err := s.probeWithURL(ctx, client, probe.url, probe.parser)
			if err == nil {
				return exitInfo, latencyMs, nil
			}
			lastErr = err
		}
		return nil, 0, fmt.Errorf("all probe URLs failed, last error: %w", lastErr)
	}

	for _, probe := range probeURLs {
		exitInfo, latencyMs, err := s.probeWithURL(ctx, client, probe.url, probe.parser)
		if err == nil {
			return exitInfo, latencyMs, nil
		}
		lastErr = err
	}

	return nil, 0, fmt.Errorf("all probe URLs failed, last error: %w", lastErr)
}

func (s *proxyProbeService) probeWithURL(ctx context.Context, client *http.Client, url string, parser string) (*service.ProxyExitInfo, int64, error) {
	startTime := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("proxy connection failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	latencyMs := time.Since(startTime).Milliseconds()

	if resp.StatusCode != http.StatusOK {
		return nil, latencyMs, fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}

	maxResponseBytes := s.maxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = defaultProxyProbeResponseMaxBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, latencyMs, fmt.Errorf("failed to read response: %w", err)
	}
	if int64(len(body)) > maxResponseBytes {
		return nil, latencyMs, fmt.Errorf("proxy probe response exceeds limit: %d", maxResponseBytes)
	}

	switch parser {
	case "ipwho":
		return s.parseIPWho(body, latencyMs)
	case "ipsb":
		return s.parseIPSB(body, latencyMs)
	case "ip-api":
		return s.parseIPAPI(body, latencyMs)
	case "ipify":
		return s.parseIPify(body, latencyMs)
	case "chatgpt-trace":
		return s.parseChatGPTTrace(body, latencyMs)
	default:
		return nil, latencyMs, fmt.Errorf("unknown parser: %s", parser)
	}
}

func (s *proxyProbeService) parseIPWho(body []byte, latencyMs int64) (*service.ProxyExitInfo, int64, error) {
	var resp struct {
		Success     bool   `json:"success"`
		Message     string `json:"message"`
		IP          string `json:"ip"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
		Timezone struct {
			ID     string `json:"id"`
			Offset *int   `json:"offset"`
		} `json:"timezone"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, latencyMs, fmt.Errorf("failed to parse ipwho.is response: %w", err)
	}
	if !resp.Success {
		msg := strings.TrimSpace(resp.Message)
		if msg == "" {
			msg = "ipwho.is probe failed"
		}
		return nil, latencyMs, fmt.Errorf("ipwho.is request failed: %s", msg)
	}
	ipStr := strings.TrimSpace(resp.IP)
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || !addr.Unmap().Is4() {
		return nil, latencyMs, fmt.Errorf("ipwho.is returned non-IPv4 exit address %q", ipStr)
	}
	asn := ""
	if resp.Connection.ASN > 0 {
		asn = "AS" + strconv.Itoa(resp.Connection.ASN)
		if org := strings.TrimSpace(resp.Connection.Org); org != "" {
			asn += " " + org
		}
	}
	isp := strings.TrimSpace(resp.Connection.ISP)
	if isp == "" {
		isp = strings.TrimSpace(resp.Connection.Org)
	}
	return &service.ProxyExitInfo{
		IP:               addr.Unmap().String(),
		City:             strings.TrimSpace(resp.City),
		Region:           strings.TrimSpace(resp.Region),
		Country:          strings.TrimSpace(resp.Country),
		CountryCode:      strings.ToUpper(strings.TrimSpace(resp.CountryCode)),
		Timezone:         strings.TrimSpace(resp.Timezone.ID),
		UTCOffsetSeconds: resp.Timezone.Offset,
		ASN:              asn,
		ISP:              isp,
	}, latencyMs, nil
}

func (s *proxyProbeService) parseIPSB(body []byte, latencyMs int64) (*service.ProxyExitInfo, int64, error) {
	var resp struct {
		IP           string `json:"ip"`
		Country      string `json:"country"`
		CountryCode  string `json:"country_code"`
		Region       string `json:"region"`
		City         string `json:"city"`
		Timezone     string `json:"timezone"`
		Offset       *int   `json:"offset"`
		ASN          int    `json:"asn"`
		ASNOrg       string `json:"asn_organization"`
		Organization string `json:"organization"`
		ISP          string `json:"isp"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, latencyMs, fmt.Errorf("failed to parse api.ip.sb response: %w", err)
	}
	ipStr := strings.TrimSpace(resp.IP)
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || !addr.Unmap().Is4() {
		return nil, latencyMs, fmt.Errorf("api.ip.sb returned non-IPv4 exit address %q", ipStr)
	}
	asn := ""
	if resp.ASN > 0 {
		asn = "AS" + strconv.Itoa(resp.ASN)
		org := strings.TrimSpace(resp.ASNOrg)
		if org == "" {
			org = strings.TrimSpace(resp.Organization)
		}
		if org != "" {
			asn += " " + org
		}
	}
	isp := strings.TrimSpace(resp.ISP)
	if isp == "" {
		isp = strings.TrimSpace(resp.Organization)
	}
	return &service.ProxyExitInfo{
		IP:               addr.Unmap().String(),
		City:             strings.TrimSpace(resp.City),
		Region:           strings.TrimSpace(resp.Region),
		Country:          strings.TrimSpace(resp.Country),
		CountryCode:      strings.ToUpper(strings.TrimSpace(resp.CountryCode)),
		Timezone:         strings.TrimSpace(resp.Timezone),
		UTCOffsetSeconds: resp.Offset,
		ASN:              asn,
		ISP:              isp,
	}, latencyMs, nil
}

func (s *proxyProbeService) parseIPAPI(body []byte, latencyMs int64) (*service.ProxyExitInfo, int64, error) {
	var ipInfo struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		Query       string `json:"query"`
		City        string `json:"city"`
		Region      string `json:"region"`
		RegionName  string `json:"regionName"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		Timezone    string `json:"timezone"`
		ASN         string `json:"as"`
		ISP         string `json:"isp"`
		Offset      *int   `json:"offset"`
	}

	if err := json.Unmarshal(body, &ipInfo); err != nil {
		preview := string(body)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		return nil, latencyMs, fmt.Errorf("failed to parse response: %w (body: %s)", err, preview)
	}
	if strings.ToLower(ipInfo.Status) != "success" {
		if ipInfo.Message == "" {
			ipInfo.Message = "ip-api request failed"
		}
		return nil, latencyMs, fmt.Errorf("ip-api request failed: %s", ipInfo.Message)
	}

	region := ipInfo.RegionName
	if region == "" {
		region = ipInfo.Region
	}
	return &service.ProxyExitInfo{
		IP:               ipInfo.Query,
		City:             ipInfo.City,
		Region:           region,
		Country:          ipInfo.Country,
		CountryCode:      ipInfo.CountryCode,
		Timezone:         ipInfo.Timezone,
		UTCOffsetSeconds: ipInfo.Offset,
		ASN:              ipInfo.ASN,
		ISP:              ipInfo.ISP,
	}, latencyMs, nil
}

func (s *proxyProbeService) parseIPify(body []byte, latencyMs int64) (*service.ProxyExitInfo, int64, error) {
	var result struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, latencyMs, fmt.Errorf("failed to parse ipify response: %w", err)
	}
	if result.IP == "" {
		return nil, latencyMs, fmt.Errorf("ipify: no IP found in response")
	}
	return &service.ProxyExitInfo{
		IP: result.IP,
	}, latencyMs, nil
}

// parseChatGPTTrace 解析 Cloudflare trace 端点（如 chatgpt.com/cdn-cgi/trace）的纯文本响应。
// 响应按行给出键值对，其中 ip= 为出口 IP，loc= 为国家代码。
func (s *proxyProbeService) parseChatGPTTrace(body []byte, latencyMs int64) (*service.ProxyExitInfo, int64, error) {
	var ip, loc, timezone string
	for _, line := range strings.Split(string(body), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "ip":
			ip = strings.TrimSpace(value)
		case "loc":
			loc = strings.TrimSpace(value)
		case "tz":
			timezone = strings.TrimSpace(value)
		}
	}
	if ip == "" {
		preview := string(body)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		return nil, latencyMs, fmt.Errorf("chatgpt-trace: no ip= found in response (body: %s)", preview)
	}
	info := &service.ProxyExitInfo{
		IP: ip,
	}
	if loc != "" {
		info.CountryCode = loc
	}
	if timezone != "" {
		info.Timezone = timezone
	}
	return info, latencyMs, nil
}
