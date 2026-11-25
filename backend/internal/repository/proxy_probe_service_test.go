package repository

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ProxyProbeServiceSuite struct {
	suite.Suite
	ctx      context.Context
	proxySrv *httptest.Server
	prober   *proxyProbeService
}

func (s *ProxyProbeServiceSuite) SetupTest() {
	s.ctx = context.Background()
	s.prober = &proxyProbeService{
		allowPrivateHosts: true,
	}
}

func (s *ProxyProbeServiceSuite) TearDownTest() {
	if s.proxySrv != nil {
		s.proxySrv.Close()
		s.proxySrv = nil
	}
}

func (s *ProxyProbeServiceSuite) setupProxyServer(handler http.HandlerFunc) {
	s.proxySrv = newLocalTestServer(s.T(), handler)
}

func (s *ProxyProbeServiceSuite) TestProbeProxy_InvalidProxyURL() {
	_, _, err := s.prober.ProbeProxy(s.ctx, "://bad")
	require.Error(s.T(), err)
	require.ErrorContains(s.T(), err, "failed to create proxy client")
}

func (s *ProxyProbeServiceSuite) TestProbeProxy_UnsupportedProxyScheme() {
	_, _, err := s.prober.ProbeProxy(s.ctx, "ftp://127.0.0.1:1")
	require.Error(s.T(), err)
	require.ErrorContains(s.T(), err, "failed to create proxy client")
}

func (s *ProxyProbeServiceSuite) TestProbeProxy_Success_IPWho() {
	s.prober.configuredProbeURLs = []configuredProbeTarget{
		{url: "http://ipwho.is/", parser: "ipwho"},
	}
	s.setupProxyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(s.T(), "en-US,en;q=0.9", r.Header.Get("Accept-Language"))
		if strings.Contains(r.RequestURI, "ipwho.is") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"success":true,"ip":"1.2.3.4","city":"Los Angeles","region":"California","country":"United States","country_code":"US","connection":{"asn":7922,"org":"Comcast","isp":"Comcast Cable"},"timezone":{"id":"America/Los_Angeles","offset":-28800}}`)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	info, latencyMs, err := s.prober.ProbeProxy(s.ctx, s.proxySrv.URL)
	require.NoError(s.T(), err, "ProbeProxy")
	require.GreaterOrEqual(s.T(), latencyMs, int64(0), "unexpected latency")
	require.Equal(s.T(), "1.2.3.4", info.IP)
	require.Equal(s.T(), "Los Angeles", info.City)
	require.Equal(s.T(), "California", info.Region)
	require.Equal(s.T(), "United States", info.Country)
	require.Equal(s.T(), "US", info.CountryCode)
	require.Equal(s.T(), "America/Los_Angeles", info.Timezone)
	require.Equal(s.T(), "AS7922 Comcast", info.ASN)
}

func (s *ProxyProbeServiceSuite) TestProbeProxy_Success_IPSBFallback() {
	s.prober.configuredProbeURLs = []configuredProbeTarget{
		{url: "http://ipwho.is/", parser: "ipwho"},
		{url: "http://api.ip.sb/geoip", parser: "ipsb"},
	}
	s.setupProxyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "ipwho.is") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if strings.Contains(r.RequestURI, "api.ip.sb") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ip":"5.6.7.8","city":"Tokyo","region":"Tokyo","country":"Japan","country_code":"JP","timezone":"Asia/Tokyo","offset":32400,"asn":2516,"asn_organization":"KDDI","isp":"KDDI"}`)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	info, latencyMs, err := s.prober.ProbeProxy(s.ctx, s.proxySrv.URL)
	require.NoError(s.T(), err, "ProbeProxy should fallback to api.ip.sb")
	require.GreaterOrEqual(s.T(), latencyMs, int64(0), "unexpected latency")
	require.Equal(s.T(), "5.6.7.8", info.IP)
	require.Equal(s.T(), "JP", info.CountryCode)
	require.Equal(s.T(), "Asia/Tokyo", info.Timezone)
}

func (s *ProxyProbeServiceSuite) TestProbeProxy_RejectsIPv6FromIPWhoAndIPSB() {
	_, _, err := s.prober.parseIPWho([]byte(`{"success":true,"ip":"2606:4700:4700::1111"}`), 10)
	require.Error(s.T(), err)
	require.ErrorContains(s.T(), err, "non-IPv4")

	_, _, err = s.prober.parseIPSB([]byte(`{"ip":"2606:4700:4700::1111"}`), 10)
	require.Error(s.T(), err)
	require.ErrorContains(s.T(), err, "non-IPv4")
}

func (s *ProxyProbeServiceSuite) TestDefaultProbeURLsUseHTTPSIPv4Providers() {
	require.Len(s.T(), probeURLs, 2)
	require.Equal(s.T(), "https://ipwho.is/", probeURLs[0].url)
	require.Equal(s.T(), "https://api.ip.sb/geoip", probeURLs[1].url)
}

func (s *ProxyProbeServiceSuite) TestProbeProxy_AllFailed() {
	s.prober.configuredProbeURLs = []configuredProbeTarget{
		{url: "http://ipwho.is/", parser: "ipwho"},
		{url: "http://api.ip.sb/geoip", parser: "ipsb"},
	}
	s.setupProxyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	_, _, err := s.prober.ProbeProxy(s.ctx, s.proxySrv.URL)
	require.Error(s.T(), err)
	require.ErrorContains(s.T(), err, "all probe URLs failed")
}

func (s *ProxyProbeServiceSuite) TestProbeProxy_InvalidJSON() {
	s.prober.configuredProbeURLs = []configuredProbeTarget{
		{url: "http://ipwho.is/", parser: "ipwho"},
		{url: "http://api.ip.sb/geoip", parser: "ipsb"},
	}
	s.setupProxyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "not-json")
	}))

	_, _, err := s.prober.ProbeProxy(s.ctx, s.proxySrv.URL)
	require.Error(s.T(), err)
	require.ErrorContains(s.T(), err, "all probe URLs failed")
}

func (s *ProxyProbeServiceSuite) TestProbeProxy_ProxyServerClosed() {
	s.setupProxyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	s.proxySrv.Close()

	_, _, err := s.prober.ProbeProxy(s.ctx, s.proxySrv.URL)
	require.Error(s.T(), err, "expected error when proxy server is closed")
}

func (s *ProxyProbeServiceSuite) TestParseIPAPI_Success() {
	body := []byte(`{"status":"success","query":"1.2.3.4","city":"Beijing","regionName":"Beijing","country":"China","countryCode":"CN","timezone":"Asia/Shanghai","offset":28800,"as":"AS4134 CHINANET","isp":"China Telecom"}`)
	info, latencyMs, err := s.prober.parseIPAPI(body, 100)
	require.NoError(s.T(), err)
	require.Equal(s.T(), int64(100), latencyMs)
	require.Equal(s.T(), "1.2.3.4", info.IP)
	require.Equal(s.T(), "Beijing", info.City)
	require.Equal(s.T(), "Beijing", info.Region)
	require.Equal(s.T(), "China", info.Country)
	require.Equal(s.T(), "CN", info.CountryCode)
	require.Equal(s.T(), "Asia/Shanghai", info.Timezone)
	require.NotNil(s.T(), info.UTCOffsetSeconds)
	require.Equal(s.T(), 28800, *info.UTCOffsetSeconds)
	require.Equal(s.T(), "AS4134 CHINANET", info.ASN)
	require.Equal(s.T(), "China Telecom", info.ISP)
}

func (s *ProxyProbeServiceSuite) TestParseIPAPI_Failure() {
	body := []byte(`{"status":"fail","message":"rate limited"}`)
	_, _, err := s.prober.parseIPAPI(body, 100)
	require.Error(s.T(), err)
	require.ErrorContains(s.T(), err, "rate limited")
}

func (s *ProxyProbeServiceSuite) TestParseIPify_Success() {
	body := []byte(`{"ip": "2001:db8::1"}`)
	info, latencyMs, err := s.prober.parseIPify(body, 50)
	require.NoError(s.T(), err)
	require.Equal(s.T(), int64(50), latencyMs)
	require.Equal(s.T(), "2001:db8::1", info.IP)
}

func (s *ProxyProbeServiceSuite) TestParseIPify_NoIP() {
	body := []byte(`{"ip": ""}`)
	_, _, err := s.prober.parseIPify(body, 50)
	require.Error(s.T(), err)
	require.ErrorContains(s.T(), err, "no IP found")
}

func (s *ProxyProbeServiceSuite) TestParseChatGPTTrace_Success() {
	body := []byte("fl=abc\nh=chatgpt.com\nip=203.0.113.5\nts=1700000000\nloc=US\ntz=UTC\n")
	info, latencyMs, err := s.prober.parseChatGPTTrace(body, 320)
	require.NoError(s.T(), err)
	require.Equal(s.T(), int64(320), latencyMs)
	require.Equal(s.T(), "203.0.113.5", info.IP)
	require.Equal(s.T(), "US", info.CountryCode)
	require.Equal(s.T(), "UTC", info.Timezone)
}

func (s *ProxyProbeServiceSuite) TestParseChatGPTTrace_NoIP() {
	body := []byte("fl=abc\nh=chatgpt.com\nloc=US\n")
	_, _, err := s.prober.parseChatGPTTrace(body, 100)
	require.Error(s.T(), err)
	require.ErrorContains(s.T(), err, "chatgpt-trace: no ip= found")
}

func TestProxyProbeServiceSuite(t *testing.T) {
	suite.Run(t, new(ProxyProbeServiceSuite))
}
