//go:build unit

package repository

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/jk-zhang-meta/berth/ent"
	_ "github.com/jk-zhang-meta/berth/ent/runtime"
	"github.com/jk-zhang-meta/berth/internal/service"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func berthPrivateAccountsDB(t *testing.T) (*sql.DB, *accountRepository) {
	t.Helper()
	dsn := os.Getenv("BERTH_MARKETPLACE_TEST_DSN")
	if dsn == "" {
		t.Skip("requires isolated BERTH_MARKETPLACE_TEST_DSN")
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	var name string
	require.NoError(t, db.QueryRow("SELECT current_database()").Scan(&name))
	require.True(t, strings.HasPrefix(name, "berth_marketplace_test_"))
	_, err = db.Exec(`TRUNCATE berth_marketplace_ledger,berth_marketplace_orders,berth_marketplace_listings,berth_account_groups,
 account_stewards,proxy_stewards,account_groups,accounts,proxies,groups,users RESTART IDENTITY CASCADE;
 INSERT INTO users(id,email,password_hash,role,status,balance) VALUES
 (1,'owner@fixture.invalid','x','user','active',100),(2,'other@fixture.invalid','x','user','active',100),(3,'admin@fixture.invalid','x','admin','active',100);`)
	require.NoError(t, err)
	client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	return db, newAccountRepositoryWithSQL(client, db, nil)
}

func TestBerthPrivateAccountCreationAndLegacyPoolIsolation(t *testing.T) {
	db, repo := berthPrivateAccountsDB(t)
	ctx := context.Background()
	market := service.NewMarketplaceService(db)
	create := func(name string, owner int64) *service.Account {
		a := &service.Account{Name: name, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Schedulable: true, Concurrency: 2, PrivateOwnerUserID: owner}
		require.NoError(t, repo.Create(ctx, a))
		return a
	}
	ownerAccount := create("owner-private", 1)
	otherAccount := create("other-private", 2)
	adminAccount := create("legacy-admin", 3)
	legacyAccount := create("legacy-unowned", 0)
	var owner int64
	require.NoError(t, db.QueryRow("SELECT user_id FROM account_stewards WHERE account_id=$1", ownerAccount.ID).Scan(&owner))
	require.Equal(t, int64(1), owner)
	checkPublic := func() {
		candidates, err := repo.ListSchedulableUngroupedByPlatform(ctx, service.PlatformOpenAI)
		require.NoError(t, err)
		ids := []int64{}
		for _, a := range candidates {
			ids = append(ids, a.ID)
		}
		require.ElementsMatch(t, []int64{adminAccount.ID, legacyAccount.ID}, ids)
		candidates, err = repo.ListSchedulableUngroupedByPlatforms(ctx, []string{service.PlatformOpenAI})
		require.NoError(t, err)
		ids = nil
		for _, a := range candidates {
			ids = append(ids, a.ID)
		}
		require.ElementsMatch(t, []int64{adminAccount.ID, legacyAccount.ID}, ids)
		candidates, err = repo.ListModelAvailabilityCandidates(ctx, nil, []string{service.PlatformOpenAI}, false)
		require.NoError(t, err)
		ids = nil
		for _, a := range candidates {
			ids = append(ids, a.ID)
		}
		require.ElementsMatch(t, []int64{adminAccount.ID, legacyAccount.ID}, ids)
	}
	checkPublic() // No private groups yet: ownership in the create transaction already isolates.
	checkSimple := func() {
		candidates, err := repo.ListSchedulableByPlatform(ctx, service.PlatformOpenAI)
		require.NoError(t, err)
		ids := []int64{}
		for _, a := range candidates {
			ids = append(ids, a.ID)
		}
		require.ElementsMatch(t, []int64{adminAccount.ID, legacyAccount.ID}, ids)
		candidates, err = repo.ListSchedulableByPlatforms(ctx, []string{service.PlatformOpenAI})
		require.NoError(t, err)
		ids = nil
		for _, a := range candidates {
			ids = append(ids, a.ID)
		}
		require.ElementsMatch(t, []int64{adminAccount.ID, legacyAccount.ID}, ids)
		candidates, err = repo.ListModelAvailabilityCandidates(ctx, nil, []string{service.PlatformOpenAI}, true)
		require.NoError(t, err)
		ids = nil
		for _, a := range candidates {
			ids = append(ids, a.ID)
		}
		require.ElementsMatch(t, []int64{adminAccount.ID, legacyAccount.ID}, ids)
	}
	checkSimple()
	ownerGroup, err := market.EnsureAccountGroup(ctx, ownerAccount.ID, 1)
	require.NoError(t, err)
	_, err = market.EnsureAccountGroup(ctx, otherAccount.ID, 2)
	require.NoError(t, err)
	_, err = market.EnsureAccountGroup(ctx, adminAccount.ID, 3)
	require.NoError(t, err)
	checkPublic() // An admin's private mapping must not remove its preexisting public-pool behavior.
	checkSimple()
	candidates, err := repo.ListSchedulableByGroupIDAndPlatform(ctx, ownerGroup, service.PlatformOpenAI)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, ownerAccount.ID, candidates[0].ID)
}

func TestBerthPrivateAccountCreateRollsBackOnStewardFailure(t *testing.T) {
	db, repo := berthPrivateAccountsDB(t)
	ctx := context.Background()
	// Controlled failure inside the real PostgreSQL transaction, after account INSERT.
	_, err := db.Exec(`CREATE FUNCTION berth_test_reject_steward() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test ownership failure'; END; $$;
 CREATE TRIGGER berth_test_reject_steward BEFORE INSERT ON account_stewards FOR EACH ROW EXECUTE FUNCTION berth_test_reject_steward();`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec("DROP TRIGGER IF EXISTS berth_test_reject_steward ON account_stewards; DROP FUNCTION IF EXISTS berth_test_reject_steward()")
		require.NoError(t, err)
	})
	account := &service.Account{Name: "must-not-persist", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Schedulable: true, PrivateOwnerUserID: 1}
	require.Error(t, repo.Create(ctx, account))
	var count int
	require.NoError(t, db.QueryRow("SELECT count(*) FROM accounts WHERE name='must-not-persist'").Scan(&count))
	require.Zero(t, count)
}
