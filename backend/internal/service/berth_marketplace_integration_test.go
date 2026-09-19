//go:build integration

package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func marketplaceTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("BERTH_MARKETPLACE_TEST_DSN")
	if dsn == "" {
		t.Skip("requires an isolated PostgreSQL database via BERTH_MARKETPLACE_TEST_DSN")
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	var name string
	require.NoError(t, db.QueryRow("SELECT current_database()").Scan(&name))
	require.True(t, strings.HasPrefix(name, "berth_marketplace_test_"), "refusing to mutate a non-test database")
	_, err = db.Exec(`TRUNCATE berth_marketplace_ledger,berth_marketplace_orders,berth_marketplace_listings,berth_account_groups,
 account_stewards,proxy_stewards,account_groups,accounts,proxies,groups,users RESTART IDENTITY CASCADE`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO users(id,email,password_hash,role,status,balance) VALUES
 (1,'seller@fixture.invalid','x','user','active',100),(2,'buyer@fixture.invalid','x','user','active',100),
 (3,'other@fixture.invalid','x','user','active',100),(4,'admin@fixture.invalid','x','admin','active',100);
 INSERT INTO accounts(id,name,platform,type,status) VALUES(11,'private account','openai','oauth','active'),(12,'second account','openai','oauth','active');
 INSERT INTO account_stewards(account_id,user_id) VALUES(11,1),(12,1);`)
	require.NoError(t, err)
	_, err = db.Exec("UPDATE berth_marketplace_settings SET rent_commission_bps=0,usage_commission_bps=0 WHERE id=1")
	require.NoError(t, err)
	return db
}
func marketplaceOffer(resourceType string, id int64) MarketplacePublishInput {
	return MarketplacePublishInput{ResourceType: resourceType, ResourceID: id, Title: "Fixture offer", Description: "Public description", DurationHours: 2, PriceCents: 1000, Capacity: 1}
}
func marketplaceBalance(t *testing.T, db *sql.DB, id int64) string {
	t.Helper()
	var s string
	require.NoError(t, db.QueryRow("SELECT balance::text FROM users WHERE id=$1", id).Scan(&s))
	return s
}

func TestMarketplaceSQLPrivateGroupAndFinancialLifecycle(t *testing.T) {
	db := marketplaceTestDB(t)
	ctx := context.Background()
	s := NewMarketplaceService(db)
	_, err := db.Exec("INSERT INTO groups(id,name,platform) VALUES(100,'existing admin pool','openai'); INSERT INTO account_groups(account_id,group_id) VALUES(11,100)")
	require.NoError(t, err)
	group, err := s.EnsureAccountGroup(ctx, 11, 1)
	require.NoError(t, err)
	replayGroup, err := s.EnsureAccountGroup(ctx, 11, 1)
	require.NoError(t, err)
	require.Equal(t, group, replayGroup)
	var bindings int
	require.NoError(t, db.QueryRow("SELECT count(*) FROM account_groups WHERE account_id=11").Scan(&bindings))
	require.Equal(t, 2, bindings)
	_, err = s.EnsureAccountGroup(ctx, 11, 2)
	require.ErrorIs(t, err, ErrMarketplaceForbidden)
	_, err = s.Publish(ctx, 2, false, marketplaceOffer("account", 11))
	require.ErrorIs(t, err, ErrMarketplaceForbidden)
	listing, err := s.Publish(ctx, 1, false, marketplaceOffer("account", 11))
	require.NoError(t, err)
	second, err := s.Publish(ctx, 1, false, marketplaceOffer("account", 12))
	require.NoError(t, err)
	var invalidations atomic.Int32
	s.OnBalanceChanged = func(context.Context, int64) { invalidations.Add(1) }
	order, err := s.Checkout(ctx, 2, listing.ID, "purchase-one")
	require.NoError(t, err)
	require.Equal(t, group, *order.GroupID)
	require.Equal(t, "90.00000000", marketplaceBalance(t, db, 2))
	require.Equal(t, "100.00000000", marketplaceBalance(t, db, 1))
	again, err := s.Checkout(ctx, 2, listing.ID, "purchase-one")
	require.NoError(t, err)
	require.Equal(t, order.ID, again.ID)
	_, err = s.Checkout(ctx, 2, second.ID, "purchase-one")
	require.ErrorIs(t, err, ErrMarketplaceIdempotency)
	_, err = s.Checkout(ctx, 3, listing.ID, "purchase-two")
	require.ErrorIs(t, err, ErrMarketplaceCapacity)
	_, err = s.Checkout(ctx, 1, listing.ID, "self-purchase")
	require.ErrorIs(t, err, ErrMarketplaceForbidden)
	managed, allowed, err := s.GroupAccess(ctx, 2, group)
	require.NoError(t, err)
	require.True(t, managed)
	require.True(t, allowed)
	_, allowed, err = s.GroupAccess(ctx, 3, group)
	require.NoError(t, err)
	require.False(t, allowed)
	_, err = s.Terminate(ctx, 3, false, order.ID)
	require.ErrorIs(t, err, ErrMarketplaceForbidden)
	_, err = db.Exec("UPDATE berth_marketplace_orders SET starts_at=clock_timestamp()-interval '1 hour',expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1", order.ID)
	require.NoError(t, err)
	done, err := s.Terminate(ctx, 2, false, order.ID)
	require.NoError(t, err)
	require.Equal(t, "terminated", done.Status)
	require.Equal(t, int64(500), done.SellerEarnedCents)
	require.Equal(t, int64(500), done.RefundCents)
	again, err = s.Terminate(ctx, 1, false, order.ID)
	require.NoError(t, err)
	require.Equal(t, done.SellerEarnedCents, again.SellerEarnedCents)
	require.Equal(t, "95.00000000", marketplaceBalance(t, db, 2))
	require.Equal(t, "105.00000000", marketplaceBalance(t, db, 1))
	_, allowed, err = s.GroupAccess(ctx, 2, group)
	require.NoError(t, err)
	require.False(t, allowed)
	var ledgerCount int
	var ledgerSum int64
	require.NoError(t, db.QueryRow("SELECT count(*),sum(amount_cents) FROM berth_marketplace_ledger WHERE order_id=$1", order.ID).Scan(&ledgerCount, &ledgerSum))
	require.Equal(t, 3, ledgerCount)
	require.Zero(t, ledgerSum)
	_, err = db.Exec("UPDATE berth_marketplace_ledger SET amount_cents=0 WHERE order_id=$1", order.ID)
	require.Error(t, err)
	require.Positive(t, invalidations.Load())
	// Terms change without modifying the sold order snapshot.
	changed := marketplaceOffer("account", 11)
	changed.PriceCents = 2000
	_, err = s.Publish(ctx, 1, false, changed)
	require.NoError(t, err)
	orders, err := s.Orders(ctx, 2, false)
	require.NoError(t, err)
	require.Equal(t, int64(1000), orders[0].PriceCents)
	_, err = s.Checkout(ctx, 3, listing.ID, "after-termination")
	require.NoError(t, err)
}

func TestMarketplaceSQLConcurrentCapacityAndIdempotency(t *testing.T) {
	db := marketplaceTestDB(t)
	ctx := context.Background()
	s := NewMarketplaceService(db)
	listing, err := s.Publish(ctx, 1, false, marketplaceOffer("account", 11))
	require.NoError(t, err)
	var wg sync.WaitGroup
	var success atomic.Int32
	var soldOut atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Checkout(ctx, 2, listing.ID, fmt.Sprintf("concurrent-%d", i))
			if err == nil {
				success.Add(1)
			} else if errors.Is(err, ErrMarketplaceCapacity) {
				soldOut.Add(1)
			} else {
				t.Errorf("checkout: %v", err)
			}
		}(i)
	}
	wg.Wait()
	require.Equal(t, int32(1), success.Load())
	require.Equal(t, int32(11), soldOut.Load())
	require.Equal(t, "90.00000000", marketplaceBalance(t, db, 2))
	listing2, err := s.Publish(ctx, 1, false, marketplaceOffer("account", 12))
	require.NoError(t, err)
	var ids sync.Map
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, err := s.Checkout(ctx, 3, listing2.ID, "same-key")
			if err != nil {
				t.Errorf("replay: %v", err)
				return
			}
			ids.Store(o.ID, true)
		}()
	}
	wg.Wait()
	count := 0
	ids.Range(func(any, any) bool { count++; return true })
	require.Equal(t, 1, count)
	require.Equal(t, "90.00000000", marketplaceBalance(t, db, 3))
}

func TestMarketplaceSQLProxySnapshotAndExpiry(t *testing.T) {
	db := marketplaceTestDB(t)
	ctx := context.Background()
	s := NewMarketplaceService(db)
	_, err := db.Exec(`INSERT INTO proxies(id,name,protocol,host,port,username,password,status,exit_ip,exit_country,exit_country_code,exit_region,exit_city,exit_timezone,exit_utc_offset_seconds,exit_asn,exit_isp,exit_checked_at)
 VALUES(21,'source proxy','http','127.0.0.1',8080,'private-user','private-password','active','8.8.8.8','United States','US','California','Mountain View','America/Los_Angeles',-25200,'AS15169 Google','Google LLC',clock_timestamp()),
 (22,'unverified proxy','http','127.0.0.1',8081,NULL,NULL,'active',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
 INSERT INTO proxy_stewards(proxy_id,user_id) VALUES(21,1),(22,1)`)
	require.NoError(t, err)
	_, err = s.Publish(ctx, 1, false, marketplaceOffer("proxy", 22))
	require.ErrorIs(t, err, ErrMarketplaceUnavailable)
	listing, err := s.Publish(ctx, 1, false, marketplaceOffer("proxy", 21))
	require.NoError(t, err)
	order, err := s.Checkout(ctx, 2, listing.ID, "proxy-purchase")
	require.NoError(t, err)
	require.NotNil(t, order.RentalProxyID)
	require.NotEqual(t, int64(21), *order.RentalProxyID)
	allowed, err := s.CanUseRentalProxy(ctx, 2, *order.RentalProxyID)
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = s.CanUseRentalProxy(ctx, 3, *order.RentalProxyID)
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = s.CanUseRentalProxy(ctx, 2, 21)
	require.NoError(t, err)
	require.False(t, allowed)
	rental, allowed, err := s.CheckRentalProxy(ctx, *order.RentalProxyID)
	require.NoError(t, err)
	require.True(t, rental)
	require.True(t, allowed)
	_, err = db.Exec("UPDATE accounts SET proxy_id=$1 WHERE id=12", *order.RentalProxyID)
	require.NoError(t, err)
	rental, allowed, err = s.CheckAccountProxy(ctx, 12)
	require.NoError(t, err)
	require.True(t, rental)
	require.True(t, allowed)
	var claims int
	require.NoError(t, db.QueryRow("SELECT count(*) FROM proxy_stewards WHERE proxy_id=$1", *order.RentalProxyID).Scan(&claims))
	require.Zero(t, claims)
	_, err = db.Exec("UPDATE proxies SET password='changed',deleted_at=clock_timestamp() WHERE id=21")
	require.NoError(t, err)
	var password, exitIP, exitTimezone, exitASN string
	require.NoError(t, db.QueryRow("SELECT password,exit_ip,exit_timezone,exit_asn FROM proxies WHERE id=$1", *order.RentalProxyID).Scan(&password, &exitIP, &exitTimezone, &exitASN))
	require.Equal(t, "private-password", password)
	require.Equal(t, "8.8.8.8", exitIP)
	require.Equal(t, "America/Los_Angeles", exitTimezone)
	require.Equal(t, "AS15169 Google", exitASN)
	_, err = db.Exec("UPDATE berth_marketplace_orders SET starts_at=clock_timestamp()-interval '3 hours',expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1", order.ID)
	require.NoError(t, err)
	allowed, err = s.CanUseRentalProxy(ctx, 2, *order.RentalProxyID)
	require.NoError(t, err)
	require.False(t, allowed)
	rental, allowed, err = s.CheckRentalProxy(ctx, *order.RentalProxyID)
	require.NoError(t, err)
	require.True(t, rental)
	require.False(t, allowed)
	rental, allowed, err = s.CheckAccountProxy(ctx, 12)
	require.NoError(t, err)
	require.True(t, rental)
	require.False(t, allowed)
	count, err := s.SettleDue(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	count, err = s.SettleDue(ctx)
	require.NoError(t, err)
	require.Zero(t, count)
	require.Equal(t, "110.00000000", marketplaceBalance(t, db, 1))
	require.Equal(t, "90.00000000", marketplaceBalance(t, db, 2))
}

func TestMarketplaceSQLSourceExpiryAndModeration(t *testing.T) {
	db := marketplaceTestDB(t)
	ctx := context.Background()
	s := NewMarketplaceService(db)
	listing, err := s.Publish(ctx, 1, false, marketplaceOffer("account", 11))
	require.NoError(t, err)
	_, err = db.Exec("UPDATE accounts SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=11")
	require.NoError(t, err)
	_, err = s.Checkout(ctx, 2, listing.ID, "too-long")
	require.ErrorIs(t, err, ErrMarketplaceUnavailable)
	require.Equal(t, "100.00000000", marketplaceBalance(t, db, 2))
	_, err = db.Exec("UPDATE accounts SET expires_at=NULL WHERE id=11")
	require.NoError(t, err)
	_, err = s.SetListingStatus(ctx, 3, false, listing.ID, "paused")
	require.ErrorIs(t, err, ErrMarketplaceNotFound)
	paused, err := s.SetListingStatus(ctx, 4, true, listing.ID, "paused")
	require.NoError(t, err)
	require.Equal(t, "paused", paused.Status)
	_, err = s.Checkout(ctx, 2, listing.ID, "paused")
	require.ErrorIs(t, err, ErrMarketplaceUnavailable)
	_, err = s.SetListingStatus(ctx, 1, false, listing.ID, "active")
	require.Error(t, err)
	_, err = s.Publish(ctx, 1, false, marketplaceOffer("account", 11))
	require.ErrorIs(t, err, ErrMarketplaceForbidden)
	_, err = s.Publish(ctx, 4, true, marketplaceOffer("account", 11))
	require.ErrorIs(t, err, ErrMarketplaceForbidden)
	_, err = s.SetListingStatus(ctx, 1, false, listing.ID, "paused")
	require.NoError(t, err)
	_, err = s.SetListingStatus(ctx, 1, false, listing.ID, "active")
	require.Error(t, err)
	_, err = s.SetListingStatus(ctx, 4, true, listing.ID, "active")
	require.NoError(t, err)
	order, err := s.Checkout(ctx, 2, listing.ID, "allowed")
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Terminate(ctx, 4, true, order.ID)
			if err != nil {
				t.Errorf("settle: %v", err)
			}
		}()
	}
	wg.Wait()
	var count int
	var sum int64
	require.NoError(t, db.QueryRow("SELECT count(*),sum(amount_cents) FROM berth_marketplace_ledger WHERE order_id=$1", order.ID).Scan(&count, &sum))
	require.Equal(t, 3, count)
	require.Zero(t, sum)
	require.Equal(t, "100.00000000", marketplaceBalance(t, db, 2))
	require.Equal(t, "100.00000000", marketplaceBalance(t, db, 1))
}

func TestMarketplaceSQLUnschedulableAccountCannotSell(t *testing.T) {
	db := marketplaceTestDB(t)
	ctx := context.Background()
	s := NewMarketplaceService(db)
	listing, err := s.Publish(ctx, 1, false, marketplaceOffer("account", 11))
	require.NoError(t, err)
	_, err = db.Exec("UPDATE accounts SET schedulable=false WHERE id=11")
	require.NoError(t, err)
	_, err = s.Checkout(ctx, 2, listing.ID, "paused-account")
	require.ErrorIs(t, err, ErrMarketplaceUnavailable)
	_, err = s.Publish(ctx, 1, false, marketplaceOffer("account", 11))
	require.ErrorIs(t, err, ErrMarketplaceUnavailable)
	for _, admin := range []bool{false, true} {
		options, err := s.ResourceOptions(ctx, 1, admin)
		require.NoError(t, err)
		for _, option := range options {
			require.False(t, option.ResourceType == "account" && option.ID == 11)
		}
	}
	require.Equal(t, "100.00000000", marketplaceBalance(t, db, 2))
	var count int
	require.NoError(t, db.QueryRow("SELECT count(*) FROM berth_marketplace_orders").Scan(&count))
	require.Zero(t, count)
	require.NoError(t, db.QueryRow("SELECT count(*) FROM berth_marketplace_ledger").Scan(&count))
	require.Zero(t, count)
}

func TestMarketplaceSQLInsufficientFundsRollsBack(t *testing.T) {
	db := marketplaceTestDB(t)
	ctx := context.Background()
	s := NewMarketplaceService(db)
	listing, err := s.Publish(ctx, 1, false, marketplaceOffer("account", 11))
	require.NoError(t, err)
	_, err = db.Exec("UPDATE users SET frozen_balance=95 WHERE id=2")
	require.NoError(t, err)
	_, err = s.Checkout(ctx, 2, listing.ID, "too-expensive")
	require.ErrorIs(t, err, ErrMarketplaceInsufficientBalance)
	var count int
	require.NoError(t, db.QueryRow("SELECT count(*) FROM berth_marketplace_orders").Scan(&count))
	require.Zero(t, count)
	require.Equal(t, "100.00000000", marketplaceBalance(t, db, 2))
}
