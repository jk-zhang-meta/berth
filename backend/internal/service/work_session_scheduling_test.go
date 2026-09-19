//go:build unit

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

type hardRPMStub struct {
	reserved bool
	err      error
	calls    int
}

func (s *hardRPMStub) ReserveRPM(_ context.Context, _ int64, _ int) (int, bool, error) {
	s.calls++
	return s.calls, s.reserved, s.err
}

func (s *hardRPMStub) GetRPM(_ context.Context, _ int64) (int, error) { return 0, nil }
func (s *hardRPMStub) GetRPMBatch(_ context.Context, _ []int64) (map[int64]int, error) {
	return map[int64]int{}, nil
}

func TestAcquireAccountCapacityRPMFullReleasesConcurrency(t *testing.T) {
	cache := &stubConcurrencyCacheForTest{acquireResult: true}
	rpm := &hardRPMStub{reserved: false}
	svc := NewConcurrencyService(cache)
	svc.SetRPMCache(rpm)

	result, err := svc.AcquireAccountCapacity(context.Background(), 42, 2, 10)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.Acquired)
	require.True(t, result.BlockedByRPM())
	require.Equal(t, 1, rpm.calls)
	require.Equal(t, []int64{42}, cache.releasedAccountIDs)
}

func TestAcquireAccountCapacityRPMErrorFailsClosedAndReleases(t *testing.T) {
	cache := &stubConcurrencyCacheForTest{acquireResult: true}
	rpm := &hardRPMStub{err: errors.New("redis unavailable")}
	svc := NewConcurrencyService(cache)
	svc.SetRPMCache(rpm)

	result, err := svc.AcquireAccountCapacity(context.Background(), 7, 1, 3)
	require.ErrorContains(t, err, "redis unavailable")
	require.Nil(t, result)
	require.Equal(t, []int64{7}, cache.releasedAccountIDs)
}

func TestApplyWorkSessionQueuePriority(t *testing.T) {
	ctx := withWorkSessionPref(context.Background(), &WorkSessionPref{
		QueueAccountIDs: []int64{30, 10},
	})
	accounts := []Account{
		{ID: 10, Priority: 50},
		{ID: 20, Priority: 1},
		{ID: 30, Priority: 90},
	}

	applyWorkSessionQueuePriority(ctx, accounts)

	require.Equal(t, -999999, accounts[0].Priority)
	require.Equal(t, 1, accounts[1].Priority)
	require.Equal(t, -1000000, accounts[2].Priority)
}

func TestApplyWorkSessionAssignedAccountPriorityWithoutQueue(t *testing.T) {
	ctx := withWorkSessionPref(context.Background(), &WorkSessionPref{AssignedAccountID: 20})
	accounts := []Account{{ID: 10, Priority: 1}, {ID: 20, Priority: 99}}

	applyWorkSessionQueuePriority(ctx, accounts)

	require.Equal(t, 1, accounts[0].Priority)
	require.Equal(t, -1000000, accounts[1].Priority)
}

func TestPrioritizeOpenAIWorkSessionAccountsUsesExplicitQueueOrder(t *testing.T) {
	ctx := withWorkSessionPref(context.Background(), &WorkSessionPref{QueueAccountIDs: []int64{30, 10}})
	order := []openAIAccountCandidateScore{
		{account: &Account{ID: 20}},
		{account: &Account{ID: 10}},
		{account: &Account{ID: 30}},
	}

	order = prioritizeOpenAIWorkSessionAccounts(ctx, order)

	require.Equal(t, int64(30), order[0].account.ID)
	require.Equal(t, int64(10), order[1].account.ID)
	require.Equal(t, int64(20), order[2].account.ID)
}

func TestWorkSessionReconcileStaleEndsOnlyUsersExpiredLiveSessions(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	store := NewWorkSessionStore(db)

	mock.ExpectExec("UPDATE work_sessions").
		WithArgs(sqlmock.AnyArg(), int64(9)).
		WillReturnResult(sqlmock.NewResult(0, 2))

	require.NoError(t, store.reconcileStale(context.Background(), 9))
	require.NoError(t, mock.ExpectationsWereMet())
}
