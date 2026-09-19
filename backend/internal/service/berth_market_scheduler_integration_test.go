//go:build integration

package service

import (
	"context"
	"testing"

	"github.com/jk-zhang-meta/berth/internal/config"
	"github.com/stretchr/testify/require"
)

type berthMarketHotCache struct {
	SchedulerCache
	accounts []*Account
}

func (c *berthMarketHotCache) GetSnapshot(context.Context, SchedulerBucket) ([]*Account, bool, error) {
	return c.accounts, true, nil
}

func TestBerthMarketSchedulerHotSnapshotChecksCurrentOwnership(t *testing.T) {
	db := marketplaceTestDB(t)
	ctx := context.Background()
	_, err := db.Exec("UPDATE account_stewards SET user_id=4 WHERE account_id=12")
	require.NoError(t, err)
	m := NewMarketplaceService(db)
	privateGroup, err := m.EnsureAccountGroup(ctx, 11, 1)
	require.NoError(t, err)
	adminGroup, err := m.EnsureAccountGroup(ctx, 12, 4)
	require.NoError(t, err)
	// Simulates a pre-upgrade Redis snapshot with no ownership/group metadata.
	cache := &berthMarketHotCache{accounts: []*Account{{ID: 11}, {ID: 12}}}
	s := &SchedulerSnapshotService{cache: cache}
	s.SetMarketplace(m)
	accounts, _, err := s.ListSchedulableAccounts(ctx, nil, PlatformOpenAI, false)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	require.Equal(t, int64(12), accounts[0].ID)
	require.Len(t, cache.accounts, 2, "must not mutate shared cache objects")
	// A new private claim after startup is rejected without rebuilding Redis.
	_, err = db.Exec("UPDATE account_stewards SET user_id=1 WHERE account_id=12")
	require.NoError(t, err)
	s.cfg = &config.Config{RunMode: config.RunModeSimple}
	accounts, _, err = s.ListSchedulableAccounts(ctx, nil, PlatformOpenAI, false)
	require.NoError(t, err)
	require.Empty(t, accounts)
	_, err = db.Exec("UPDATE account_stewards SET user_id=4 WHERE account_id=12")
	require.NoError(t, err)
	gw := &GatewayService{}
	gw.SetMarketplace(m)
	require.False(t, gw.isAccountInGroup(ctx, &Account{ID: 11}, nil))
	require.True(t, gw.isAccountInGroup(ctx, &Account{ID: 12, AccountGroups: []AccountGroup{{GroupID: adminGroup}}}, nil))
	require.True(t, gw.isAccountInGroup(ctx, &Account{ID: 11, AccountGroups: []AccountGroup{{GroupID: privateGroup}}}, &privateGroup))
	_, err = db.Exec("INSERT INTO groups(id,name,platform) VALUES(100,'public assigned','openai'); INSERT INTO account_groups(account_id,group_id) VALUES(12,100)")
	require.NoError(t, err)
	require.False(t, gw.isAccountInGroup(ctx, &Account{ID: 12}, nil), "real public binding must still exclude legacy nil group")
	// Database failures must not return the stale permissive snapshot.
	require.NoError(t, db.Close())
	_, _, err = s.ListSchedulableAccounts(ctx, nil, PlatformOpenAI, false)
	require.Error(t, err)
	require.False(t, gw.isAccountInGroup(ctx, &Account{ID: 12}, nil))
}
