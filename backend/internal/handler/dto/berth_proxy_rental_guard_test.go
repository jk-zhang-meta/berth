package dto

import (
	"context"
	"testing"

	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

type dtoRentalChecker struct{}

func (dtoRentalChecker) CheckRentalProxy(_ context.Context, id int64) (bool, bool, error) {
	return id == 991144, true, nil
}
func (dtoRentalChecker) CheckAccountProxy(context.Context, int64) (bool, bool, error) {
	return false, true, nil
}

func TestRentalProxyDTOHidesConnectionCredentialsButPreservesAdminView(t *testing.T) {
	require.NoError(t, service.SetProxyRentalChecker(dtoRentalChecker{}))
	backup := int64(50)
	proxy := &service.Proxy{ID: 991144, Name: "Rental proxy", Host: "private.internal", Port: 8080, Username: "private-user", Password: "private-password", FallbackMode: service.FallbackModeProxy, BackupProxyID: &backup}
	user := ProxyFromService(proxy)
	require.Empty(t, user.Host)
	require.Zero(t, user.Port)
	require.Empty(t, user.Username)
	require.Nil(t, user.BackupProxyID)
	require.Equal(t, service.FallbackModeNone, user.FallbackMode)
	admin := ProxyFromServiceAdmin(proxy)
	require.Equal(t, proxy.Host, admin.Host)
	require.Equal(t, proxy.Port, admin.Port)
	require.Equal(t, proxy.Username, admin.Username)
	require.Equal(t, proxy.Password, admin.Password)
	require.Equal(t, proxy.BackupProxyID, admin.BackupProxyID)
	proxy.ID = 991145
	require.Equal(t, proxy.Host, ProxyFromService(proxy).Host)
}
