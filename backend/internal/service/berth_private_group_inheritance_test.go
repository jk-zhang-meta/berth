//go:build unit

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func privateGroupInheritanceService(t *testing.T, repo *duplicateAccountRepoStub) (*adminServiceImpl, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	svc := &adminServiceImpl{accountRepo: repo, accountDuplicateRepo: repo}
	svc.SetMarketplace(NewMarketplaceService(db))
	return svc, mock
}

func expectInheritedGroup(mock sqlmock.Sqlmock, groupID int64, managed bool) {
	mock.ExpectQuery("SELECT EXISTS\\(SELECT 1 FROM berth_account_groups WHERE group_id=\\$2\\)").WithArgs(int64(0), groupID).
		WillReturnRows(sqlmock.NewRows([]string{"managed", "allowed"}).AddRow(managed, false))
}

func TestPrivateGroupInheritanceDuplicateDoesNotShareSourceLease(t *testing.T) {
	repo := newDuplicateAccountRepoStub()
	svc, mock := privateGroupInheritanceService(t, repo)
	source := &Account{Name: "leased A", Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{"api_key": "private A"}, GroupIDs: []int64{101, 7}, AccountGroups: []AccountGroup{{GroupID: 101, Priority: 3}, {GroupID: 7, Priority: 42}}}
	require.NoError(t, repo.Create(context.Background(), source))
	expectInheritedGroup(mock, 101, true)
	expectInheritedGroup(mock, 7, false)
	duplicate, err := svc.DuplicateAccount(context.Background(), source.ID, "admin:1", "")
	require.NoError(t, err)
	require.Equal(t, []int64{7}, duplicate.GroupIDs)
	require.Equal(t, []AccountGroup{{AccountID: duplicate.ID, GroupID: 7, Priority: 42}}, duplicate.AccountGroups)
	require.False(t, duplicate.Schedulable)
	require.Equal(t, []int64{101, 7}, source.GroupIDs, "source lease bindings must remain untouched")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPrivateGroupInheritanceShadowDoesNotShareSourceLease(t *testing.T) {
	for _, ordinaryGroup := range []bool{false, true} {
		t.Run(map[bool]string{false: "private only", true: "preserves admin group"}[ordinaryGroup], func(t *testing.T) {
			repo := newDuplicateAccountRepoStub()
			svc, mock := privateGroupInheritanceService(t, repo)
			parent := &Account{Name: "leased A", Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{"refresh_token": "private A"}, GroupIDs: []int64{101}}
			if ordinaryGroup {
				parent.GroupIDs = append(parent.GroupIDs, 7)
			}
			require.NoError(t, repo.Create(context.Background(), parent))
			expectInheritedGroup(mock, 101, true)
			if ordinaryGroup {
				expectInheritedGroup(mock, 7, false)
			}
			shadow, err := svc.CreateShadow(context.Background(), parent.ID, ShadowOptions{PrivateOwnerUserID: 5, SkipDefaultGroupBind: true})
			require.NoError(t, err)
			require.NotContains(t, shadow.GroupIDs, int64(101))
			require.NotContains(t, repo.groupsOf[shadow.ID], int64(101))
			require.Equal(t, int64(5), shadow.PrivateOwnerUserID)
			if ordinaryGroup {
				require.Equal(t, []int64{7}, shadow.GroupIDs)
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestPrivateGroupInheritanceLookupFailureDoesNotCreateDuplicate(t *testing.T) {
	repo := newDuplicateAccountRepoStub()
	svc, mock := privateGroupInheritanceService(t, repo)
	source := &Account{Name: "leased A", Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{"api_key": "private A"}, GroupIDs: []int64{101}}
	require.NoError(t, repo.Create(context.Background(), source))
	mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(0), int64(101)).WillReturnError(errors.New("database unavailable"))
	_, err := svc.DuplicateAccount(context.Background(), source.ID, "admin:1", "")
	require.Error(t, err)
	require.Len(t, repo.accounts, 1)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPrivateGroupInheritancePrivateOnlyDuplicateStaysUnscheduled(t *testing.T) {
	repo := newDuplicateAccountRepoStub()
	svc, mock := privateGroupInheritanceService(t, repo)
	source := &Account{Name: "leased A", Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{"api_key": "private A"}, GroupIDs: []int64{101}, Schedulable: true}
	require.NoError(t, repo.Create(context.Background(), source))
	expectInheritedGroup(mock, 101, true)
	duplicate, err := svc.DuplicateAccount(context.Background(), source.ID, "admin:1", "")
	require.NoError(t, err)
	require.Empty(t, duplicate.GroupIDs)
	require.Empty(t, repo.accountGroupsOf[duplicate.ID])
	require.False(t, duplicate.Schedulable, "no ungrouped live routing before caller claims the duplicate")
	require.NoError(t, mock.ExpectationsWereMet())
}
