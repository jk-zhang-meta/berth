package repository

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jk-zhang-meta/berth/internal/pkg/tlsfingerprint"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

type rentalHTTPChecker struct{ denied, proxyDenied atomic.Bool }

func (c *rentalHTTPChecker) CheckRentalProxy(_ context.Context, id int64) (bool, bool, error) {
	return id == 991133, !c.proxyDenied.Load(), nil
}
func (c *rentalHTTPChecker) CheckAccountProxy(_ context.Context, id int64) (bool, bool, error) {
	return id == 991122, !c.denied.Load(), nil
}

func TestHTTPUpstreamRentalRevocationBlocksCachedClientAndTLSWithoutDirectFallback(t *testing.T) {
	checker := &rentalHTTPChecker{}
	require.NoError(t, service.SetProxyRentalChecker(checker))
	var upstreamCalls, proxyCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	proxyAuth := make(chan string, 2)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalls.Add(1)
		proxyAuth <- r.Header.Get("Proxy-Authorization")
		if strings.Contains(r.RequestURI, "berth-rental-") {
			t.Error("internal rental fragment was sent to the proxy")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()
	parsed, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	port, err := strconv.Atoi(parsed.Port())
	require.NoError(t, err)
	leasedProxy := &service.Proxy{ID: 991133, Protocol: parsed.Scheme, Host: parsed.Hostname(), Port: port, Username: "renter", Password: "secret"}
	cachedLeaseURL := leasedProxy.URL()
	require.Contains(t, cachedLeaseURL, "#berth-rental-991133")
	client := NewHTTPUpstream(nil)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target.URL, nil)
	require.NoError(t, err)
	response, err := client.Do(req, cachedLeaseURL, 991122, 1)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("renter:secret")), <-proxyAuth)
	checker.denied.Store(true)
	_, err = client.Do(req, proxy.URL, 991122, 1)
	require.ErrorIs(t, err, service.ErrProxyRentalUnavailable)
	_, err = client.DoWithTLS(req, proxy.URL, 991122, 1, &tlsfingerprint.Profile{Name: "test"})
	require.ErrorIs(t, err, service.ErrProxyRentalUnavailable)
	tlsRequest, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://must-not-dial.invalid/", nil)
	require.NoError(t, err)
	_, err = client.DoWithTLS(tlsRequest, proxy.URL, 991122, 1, &tlsfingerprint.Profile{Name: "test"})
	require.ErrorIs(t, err, service.ErrProxyRentalUnavailable)
	// Rebinding the account does not authorize the proxy retained by a retry.
	checker.denied.Store(false)
	checker.proxyDenied.Store(true)
	_, err = client.Do(req, cachedLeaseURL, 991122, 1)
	require.ErrorIs(t, err, service.ErrProxyRentalUnavailable)
	_, err = client.DoWithTLS(tlsRequest, cachedLeaseURL, 991122, 1, &tlsfingerprint.Profile{Name: "test"})
	require.ErrorIs(t, err, service.ErrProxyRentalUnavailable)
	require.Equal(t, int64(1), proxyCalls.Load())
	require.Zero(t, upstreamCalls.Load())
	// The owner's original proxy shares credentials but has no lease marker.
	leasedProxy.ID = 991134
	sourceURL := leasedProxy.URL()
	require.NotContains(t, sourceURL, "berth-rental-")
	response, err = client.Do(req, sourceURL, 991122, 1)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, int64(2), proxyCalls.Load())
	require.Zero(t, upstreamCalls.Load())
}
