package proxyutil

import (
	"net/http"
	"sync"
)

// EdgeRoundTripperFactory returns an http.RoundTripper that routes requests
// bound to a Berth virtual `*.edge.internal` Landing proxy through the
// corresponding edge node, or nil for ordinary proxies.
type EdgeRoundTripperFactory func(proxyURL string) http.RoundTripper

var (
	edgeRTMu      sync.RWMutex
	edgeRTFactory EdgeRoundTripperFactory
)

// RegisterEdgeRoundTripperFactory registers the active Berth Edge Landing
// RoundTripper factory so low-level HTTP clients inside internal/pkg can route
// `*.edge.internal` proxies without importing internal/service.
func RegisterEdgeRoundTripperFactory(fn EdgeRoundTripperFactory) {
	edgeRTMu.Lock()
	edgeRTFactory = fn
	edgeRTMu.Unlock()
}

// NewEdgeRoundTripper returns a Berth Edge Landing RoundTripper if proxyURL
// targets a virtual `*.edge.internal` Landing proxy and a factory is registered.
func NewEdgeRoundTripper(proxyURL string) http.RoundTripper {
	edgeRTMu.RLock()
	fn := edgeRTFactory
	edgeRTMu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn(proxyURL)
}
