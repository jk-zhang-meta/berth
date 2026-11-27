//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestAdminProxyUpdate_EdgeLandingRenamePreservesVirtualTransport(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	mock.ExpectQuery(`SELECT COALESCE\(source_type, ''\), edge_node_id`).
		WithArgs(int64(56)).
		WillReturnRows(sqlmock.NewRows([]string{"source_type", "edge_node_id"}).
			AddRow(ProxySourceTypeEdgeLandingGrant, int64(9)))

	repo := &updatingProxyRepoStub{
		proxyRepoStub: &proxyRepoStub{},
		proxy: &Proxy{
			ID:           56,
			Name:         "edge-landing-houston(host)-u1",
			Protocol:     "https",
			Host:         "houston(host).edge.internal",
			Port:         443,
			Status:       StatusActive,
			FallbackMode: FallbackModeNone,
		},
	}
	prober := &recordingProxyExitProber{}
	svc := &adminServiceImpl{
		proxyRepo:   repo,
		proxyProber: prober,
		marketplace: &MarketplaceService{db: db},
	}

	tamperedUser, tamperedPass := "evil", "secret"
	got, err := svc.UpdateProxy(context.Background(), 56, &UpdateProxyInput{
		Name:     "Houston (母机 7600X)",
		Protocol: "socks5",
		Host:     "tampered.example.com",
		Port:     1080,
		Username: &tamperedUser,
		Password: &tamperedPass,
	})
	require.NoError(t, err)
	require.Equal(t, "Houston (母机 7600X)", got.Name)
	require.Equal(t, "https", got.Protocol)
	require.Equal(t, "node-9.edge.internal", got.Host)
	require.Equal(t, 443, got.Port)
	require.Empty(t, got.Username)
	require.Empty(t, got.Password)
	require.Equal(t, 1, repo.updateCalls)
	require.Empty(t, prober.url, "managed landing proxy rename must not fail on external proxy probe")
	require.NoError(t, mock.ExpectationsWereMet())
}
