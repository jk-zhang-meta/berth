package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jk-zhang-meta/berth/internal/pkg/proxyurl"
	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type proxyRentalCheckFunc struct {
	proxy   func(context.Context, int64) (bool, bool, error)
	account func(context.Context, int64) (bool, bool, error)
}

func (f proxyRentalCheckFunc) CheckRentalProxy(ctx context.Context, id int64) (bool, bool, error) {
	return f.proxy(ctx, id)
}
func (f proxyRentalCheckFunc) CheckAccountProxy(ctx context.Context, id int64) (bool, bool, error) {
	return f.account(ctx, id)
}

func useTestProxyRentalChecker(t *testing.T, checker ProxyRentalChecker) {
	t.Helper()
	previous := proxyRentalChecker.Swap(&proxyRentalCheckerHolder{checker: checker})
	t.Cleanup(func() { proxyRentalChecker.Store(previous) })
}

func TestRentalProxyCachedSnapshotRechecksLeaseWithoutSweep(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	active := true
	check := func(ctx context.Context, id int64) (bool, bool, error) {
		if id != 90001 {
			return false, false, nil
		}
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.WithinDuration(t, time.Now().Add(2*time.Second), deadline, time.Second)
		return true, active && time.Now().Before(expires), nil
	}
	useTestProxyRentalChecker(t, proxyRentalCheckFunc{proxy: check, account: check})
	original := Proxy{ID: 90001, Name: "arbitrary mutable name", Protocol: "http", Host: "127.0.0.1", Port: 18080, Username: "private", Password: "secret"}
	raw, err := json.Marshal(original)
	require.NoError(t, err)
	var cached Proxy
	require.NoError(t, json.Unmarshal(raw, &cached))
	require.Contains(t, cached.URL(), "127.0.0.1:18080")
	// A previously deserialized account cannot retain access after natural expiry.
	expires = time.Now().Add(-time.Second)
	require.Equal(t, deniedRentalProxyURL, cached.URL())
	// Nor after early revocation while the expiration timestamp is still future.
	expires = time.Now().Add(time.Hour)
	active = false
	require.Equal(t, deniedRentalProxyURL, cached.URL())
	_, err = url.Parse(cached.URL())
	require.Error(t, err)
	_, _, err = proxyurl.Parse(cached.URL())
	require.Error(t, err)
	require.True(t, ProxyNeedsRentalRedaction(cached.ID))
	original.ID = 90002
	require.Contains(t, original.URL(), "127.0.0.1:18080")
	require.False(t, ProxyNeedsRentalRedaction(original.ID))
}

func TestRentalAccountChecksCurrentAssignmentOnEachRequest(t *testing.T) {
	allowed := true
	calls := 0
	useTestProxyRentalChecker(t, proxyRentalCheckFunc{
		proxy: func(context.Context, int64) (bool, bool, error) { return false, true, nil },
		account: func(_ context.Context, id int64) (bool, bool, error) {
			require.Equal(t, int64(90003), id)
			calls++
			return true, allowed, nil
		},
	})
	require.NoError(t, CheckAccountProxyRental(context.Background(), 90003))
	allowed = false
	require.ErrorIs(t, CheckAccountProxyRental(context.Background(), 90003), ErrProxyRentalUnavailable)
	require.Equal(t, 2, calls)
}

func TestRentalProxyQueryFailureNeverFallsBackToDirect(t *testing.T) {
	check := func(context.Context, int64) (bool, bool, error) {
		return false, false, errors.New("database unavailable")
	}
	useTestProxyRentalChecker(t, proxyRentalCheckFunc{proxy: check, account: check})
	p := Proxy{ID: 90004, Protocol: "socks5", Host: "127.0.0.1", Port: 1080}
	require.Equal(t, deniedRentalProxyURL, p.URL())
	require.Error(t, CheckAccountProxyRental(context.Background(), 90004))
	require.True(t, ProxyNeedsRentalRedaction(p.ID))
}

func TestRentalProxyRevocationBlocksNewTurnOnExistingWebSocket(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var denied atomic.Bool
	check := func(context.Context, int64) (bool, bool, error) { return true, !denied.Load(), nil }
	useTestProxyRentalChecker(t, proxyRentalCheckFunc{proxy: check, account: check})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upstream := newStagedPassthroughConn()
	upstream.Send(`{"type":"response.completed","response":{"id":"first","model":"gpt-5.1","usage":{"input_tokens":1,"output_tokens":1}}}`)
	server, serverErr := startPassthroughLifecycleServer(t, ctx, newPassthroughLifecycleService(passthroughLifecycleConfig(), upstream), passthroughLifecycleAccount())
	defer server.Close()
	client := dialPassthroughLifecycleClient(t, server)
	defer func() { _ = client.CloseNow() }()
	requirePassthroughUpstreamWrite(t, upstream, 3*time.Second)
	_, err := readPassthroughLifecycleFrame(t, client, 3*time.Second)
	require.NoError(t, err)
	denied.Store(true)
	require.NoError(t, client.Write(ctx, coderws.MessageText, []byte(`{"type":"response.create","model":"gpt-5.1","input":"second turn"}`)))
	select {
	case err := <-serverErr:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("revoked lease did not reject the next websocket turn")
	}
	select {
	case <-upstream.writes:
		t.Fatal("revoked websocket turn reached the reused upstream connection")
	default:
	}
}

func TestRentalProxySnapshotStillDeniedAfterAccountAssignmentChanges(t *testing.T) {
	useTestProxyRentalChecker(t, proxyRentalCheckFunc{
		account: func(context.Context, int64) (bool, bool, error) { return false, true, nil },
		proxy:   func(context.Context, int64) (bool, bool, error) { return true, false, nil },
	})
	require.ErrorIs(t, checkAccountSnapshotProxyRental(context.Background(), &Account{ID: 90005, Proxy: &Proxy{ID: 90006}}), ErrProxyRentalUnavailable)
}

func TestRentalProxyURLMarkerPreservesTransportAddressAndCredentials(t *testing.T) {
	check := func(context.Context, int64) (bool, bool, error) { return true, true, nil }
	useTestProxyRentalChecker(t, proxyRentalCheckFunc{proxy: check, account: check})
	for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			p := &Proxy{ID: 90007, Protocol: scheme, Host: "proxy.internal", Port: 12345, Username: "user@name", Password: "password#with%chars"}
			raw := p.URL()
			_, parsed, err := proxyurl.Parse(raw)
			require.NoError(t, err)
			require.NotNil(t, parsed, "rental marker must never select direct transport")
			require.Equal(t, "proxy.internal:12345", parsed.Host)
			require.Equal(t, p.Username, parsed.User.Username())
			password, present := parsed.User.Password()
			require.True(t, present)
			require.Equal(t, p.Password, password)
			require.Equal(t, "berth-rental-90007", parsed.Fragment)
			require.NoError(t, CheckProxyRentalURL(context.Background(), raw))
		})
	}
	require.Error(t, CheckProxyRentalURL(context.Background(), "http://proxy.internal:12345/#berth-rental-invalid"))
}
