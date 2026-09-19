//go:build unit

package repository

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

func TestBerthMarketplaceUsageAtomicRevenue(t *testing.T) {
	for _, bps := range []int{0, 2500, 10000} {
		t.Run(fmt.Sprint(bps), func(t *testing.T) {
			db, _ := berthPrivateAccountsDB(t)
			ctx := context.Background()
			_, err := db.Exec("TRUNCATE usage_billing_dedup,usage_billing_dedup_archive")
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO accounts(id,name,platform,type,status) VALUES(11,'fixture','openai','oauth','active');
 INSERT INTO groups(id,name,platform) VALUES(11,'fixture','openai');
 INSERT INTO api_keys(id,user_id,key,name,group_id) VALUES(11,2,'fixture-only-key','fixture',11);`)
			require.NoError(t, err)
			repo := &usageBillingRepository{db: db}
			makeCmd := func(id string, amount float64) *service.UsageBillingCommand {
				return &service.UsageBillingCommand{RequestID: id, APIKeyID: 11, UserID: 2, AccountID: 11, BalanceCost: amount, MarketplaceUsage: &service.MarketplaceUsageSnapshot{GroupID: 11, AccountID: 11, SellerID: 1, CommissionBPS: bps, AdmittedAt: time.Now()}}
			}
			var wg sync.WaitGroup
			errs := make(chan error, 8)
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); _, err := repo.Apply(ctx, makeCmd("same", 8)); errs <- err }()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				require.NoError(t, err)
			}
			var gross, net, fee float64
			var count int
			require.NoError(t, db.QueryRow("SELECT count(*),sum(gross_amount),sum(seller_amount),sum(platform_amount) FROM berth_marketplace_usage_revenue").Scan(&count, &gross, &net, &fee))
			require.Equal(t, 1, count)
			require.Equal(t, 8.0, gross)
			require.Equal(t, gross, net+fee)
			require.Equal(t, 8*float64(bps)/10000, fee)
			balance := func(id int64) float64 {
				var n float64
				require.NoError(t, db.QueryRow("SELECT balance FROM users WHERE id=$1", id).Scan(&n))
				return n
			}
			require.Equal(t, 92.0, balance(2))
			require.Equal(t, 100+net, balance(1))
			// Debited debt is recorded but cannot become spendable seller funds.
			_, err = db.Exec("UPDATE users SET balance=2 WHERE id=2")
			require.NoError(t, err)
			before := balance(1)
			result, err := repo.Apply(ctx, makeCmd("debt", 8))
			require.NoError(t, err)
			require.True(t, result.BalanceOverdrafted)
			require.Equal(t, -6.0, balance(2))
			require.Equal(t, before+2*(1-float64(bps)/10000), balance(1))
			market := service.NewMarketplaceService(db)
			_, err = market.SettleUsageReceivables(ctx)
			require.NoError(t, err)
			require.Equal(t, before+2*(1-float64(bps)/10000), balance(1))
			_, err = db.Exec("UPDATE users SET balance=0 WHERE id=2")
			require.NoError(t, err)
			_, err = market.SettleUsageReceivables(ctx)
			require.NoError(t, err)
			require.Equal(t, before+8*(1-float64(bps)/10000), balance(1))
			_, err = market.SettleUsageReceivables(ctx)
			require.NoError(t, err)
			require.Equal(t, before+8*(1-float64(bps)/10000), balance(1))
			// An impossible seller FK must roll back the buyer debit and dedup claim.
			bad := makeCmd("bad", 1)
			bad.MarketplaceUsage.SellerID = 999
			beforeBuyer := balance(2)
			_, err = repo.Apply(ctx, bad)
			require.Error(t, err)
			require.Equal(t, beforeBuyer, balance(2))
			require.NoError(t, db.QueryRow("SELECT count(*) FROM usage_billing_dedup WHERE request_id='bad'").Scan(&count))
			require.Zero(t, count)
		})
	}
}
