//go:build unit

package service

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

type memoryWALStore struct {
	mu          sync.Mutex
	nextID      int64
	cageID      int64
	credVersion int64
	credentials map[string]any
	entries     []*OAuthRefreshJournalEntry
	commitCtxOk bool
	quarantined bool
}

func newMemoryWALStore(cageID, credVer int64) *memoryWALStore {
	return &memoryWALStore{
		nextID:      1,
		cageID:      cageID,
		credVersion: credVer,
		credentials: map[string]any{"refresh_token": "rt-old"},
	}
}

func (s *memoryWALStore) LoadActiveCageForAccount(context.Context, int64) (int64, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cageID, s.credVersion, nil
}

func (s *memoryWALStore) FindLatestByTokenFingerprint(_ context.Context, platform, fp string) (*OAuthRefreshJournalEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.entries) - 1; i >= 0; i-- {
		if s.entries[i].Platform == platform && s.entries[i].TokenFingerprint == fp {
			cp := *s.entries[i]
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *memoryWALStore) InsertPending(_ context.Context, entry *OAuthRefreshJournalEntry) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.entries {
		if existing.Platform == entry.Platform && existing.TokenFingerprint == entry.TokenFingerprint &&
			(existing.Stage == RefreshJournalStagePending || existing.Stage == RefreshJournalStageUnknownQuarantined) {
			return 0, ErrRefreshInFlight
		}
	}
	cp := *entry
	cp.ID = s.nextID
	s.nextID++
	s.entries = append(s.entries, &cp)
	return cp.ID, nil
}

func (s *memoryWALStore) MarkPreSendAborted(_ context.Context, journalID int64, errClass, errDetail string, retryAfter *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.ID == journalID && e.Stage == RefreshJournalStagePending {
			e.Stage = RefreshJournalStagePreSendAborted
			e.ErrorClass = errClass
			e.ErrorDetail = errDetail
			e.RetryAfterUntil = retryAfter
			return nil
		}
	}
	return nil
}

func (s *memoryWALStore) MarkUnknownQuarantined(_ context.Context, journalID, _ int64, errClass, errDetail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.ID == journalID && e.Stage == RefreshJournalStagePending {
			e.Stage = RefreshJournalStageUnknownQuarantined
			e.ErrorClass = errClass
			e.ErrorDetail = errDetail
			s.quarantined = true
			return nil
		}
	}
	return nil
}

func (s *memoryWALStore) CommitRefreshTx(ctx context.Context, in CommitRefreshTxInput) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() == nil {
		s.commitCtxOk = true
	}
	if s.credVersion != in.BaseCredentialVersion {
		return 0, false, nil
	}
	s.credVersion++
	s.credentials = shallowCopyMap(in.NewCredentials)
	for _, e := range s.entries {
		if e.ID == in.JournalID && e.Stage == RefreshJournalStagePending {
			e.Stage = RefreshJournalStageCommitted
			v := s.credVersion
			e.NewCredentialVersion = &v
			e.NewTokenFingerprint = in.NewTokenFingerprint
		}
	}
	return s.credVersion, true, nil
}

func TestBerthOAuthRefreshWAL_PreConnectAbortsAndAllowsSafeRetry(t *testing.T) {
	store := newMemoryWALStore(11, 1)
	wal := NewBerthOAuthRefreshWAL(store, nil)

	req := WALRefreshRequest{
		AccountID:    100,
		Platform:     PlatformOpenAI,
		ClientID:     "app_1",
		RefreshToken: "rt-1",
	}

	// 1. Pre-connect dial failure transitions to pre_send_aborted.
	_, err := wal.ExecuteRefresh(context.Background(), req, func(_ context.Context, tracker *RefreshTraceTracker) (map[string]any, error) {
		// Simulate TCP dial failing before connect completes.
		tracker.connectAttempted.Store(true)
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	})
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrRefreshOutcomeUnknownQuarantined))
	require.Len(t, store.entries, 1)
	require.Equal(t, RefreshJournalStagePreSendAborted, store.entries[0].Stage)
	require.False(t, store.quarantined)

	// 2. Subsequent retry with same refresh_token succeeds and commits CAS v1 -> v2.
	res, err := wal.ExecuteRefresh(context.Background(), req, func(_ context.Context, tracker *RefreshTraceTracker) (map[string]any, error) {
		tracker.MarkConnected()
		return map[string]any{"access_token": "at-2", "refresh_token": "rt-2"}, nil
	})
	require.NoError(t, err)
	require.True(t, res.Committed)
	require.Equal(t, int64(2), res.NewCredentialVersion)
	require.Equal(t, RefreshJournalStageCommitted, store.entries[1].Stage)
	require.Equal(t, "rt-2", store.credentials["refresh_token"])

	// 3. Late caller presenting the old refresh_token follows the committed receipt without hitting upstream!
	upstreamCalls := 0
	lateRes, err := wal.ExecuteRefresh(context.Background(), req, func(_ context.Context, _ *RefreshTraceTracker) (map[string]any, error) {
		upstreamCalls++
		return nil, errors.New("must not call upstream")
	})
	require.NoError(t, err)
	require.True(t, lateRes.AlreadyCommitted)
	require.Equal(t, 0, upstreamCalls)
}

func TestBerthOAuthRefreshWAL_PostConnectAmbiguousErrorQuarantinesAndBlocksOldRT(t *testing.T) {
	store := newMemoryWALStore(12, 3)
	wal := NewBerthOAuthRefreshWAL(store, nil)

	req := WALRefreshRequest{
		AccountID:    200,
		Platform:     PlatformAnthropic,
		ClientID:     "claude-client",
		RefreshToken: "rt-single-use",
	}

	// Post-connect EOF (upstream may have already rotated RT).
	_, err := wal.ExecuteRefresh(context.Background(), req, func(_ context.Context, tracker *RefreshTraceTracker) (map[string]any, error) {
		tracker.MarkConnected()
		return nil, io.ErrUnexpectedEOF
	})
	require.ErrorIs(t, err, ErrRefreshOutcomeUnknownQuarantined)
	require.True(t, store.quarantined)
	require.Equal(t, RefreshJournalStageUnknownQuarantined, store.entries[0].Stage)

	// A retry with the old refresh_token MUST be blocked and NEVER hit upstream.
	upstreamCalls := 0
	_, err = wal.ExecuteRefresh(context.Background(), req, func(_ context.Context, _ *RefreshTraceTracker) (map[string]any, error) {
		upstreamCalls++
		return map[string]any{"access_token": "bad"}, nil
	})
	require.ErrorIs(t, err, ErrRefreshOutcomeUnknownQuarantined)
	require.Equal(t, 0, upstreamCalls)
}

func TestBerthOAuthRefreshWAL_CommitsRotatedTokenEvenWhenCallerContextCancels(t *testing.T) {
	store := newMemoryWALStore(13, 5)
	wal := NewBerthOAuthRefreshWAL(store, nil)

	ctx, cancel := context.WithCancel(context.Background())
	req := WALRefreshRequest{
		AccountID:    300,
		Platform:     PlatformOpenAI,
		ClientID:     "app_1",
		RefreshToken: "rt-rotate-cancel",
	}

	res, err := wal.ExecuteRefresh(ctx, req, func(_ context.Context, tracker *RefreshTraceTracker) (map[string]any, error) {
		tracker.MarkConnected()
		// Caller cancels right as the upstream rotated response arrives!
		cancel()
		return map[string]any{"access_token": "at-fresh", "refresh_token": "rt-fresh"}, nil
	})
	require.NoError(t, err)
	require.True(t, res.Committed)
	require.True(t, store.commitCtxOk, "commit tx must run under detached WithoutCancel 10s context")
	require.Equal(t, int64(6), res.NewCredentialVersion)
	require.Equal(t, "rt-fresh", store.credentials["refresh_token"])
}

func TestBerthOAuthRefreshWAL_SingleflightDeduplicatesConcurrentCallers(t *testing.T) {
	store := newMemoryWALStore(14, 1)
	wal := NewBerthOAuthRefreshWAL(store, nil)

	var upstreamCalls atomic.Int32
	req := WALRefreshRequest{
		AccountID:    400,
		Platform:     PlatformOpenAI,
		ClientID:     "app_1",
		RefreshToken: "rt-concurrent",
	}

	const workers = 12
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = wal.ExecuteRefresh(context.Background(), req, func(_ context.Context, tracker *RefreshTraceTracker) (map[string]any, error) {
				upstreamCalls.Add(1)
				tracker.MarkConnected()
				time.Sleep(25 * time.Millisecond)
				return map[string]any{"access_token": "at-shared", "refresh_token": "rt-shared"}, nil
			})
		}(i)
	}
	wg.Wait()

	for _, e := range errs {
		require.NoError(t, e)
	}
	require.Equal(t, int32(1), upstreamCalls.Load(), "singleflight must allow only 1 upstream refresh call")
}

func TestPostgresOAuthRefreshWALStore_SingleTxCommit(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	store := NewPostgresOAuthRefreshWALStore(db)
	mock.ExpectBegin()
	mock.ExpectQuery(`UPDATE account_cages\s+SET credential_version = credential_version \+ 1`).
		WithArgs(int64(7), int64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"credential_version"}).AddRow(int64(2)))
	mock.ExpectExec(`UPDATE accounts\s+SET credentials`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE oauth_refresh_journal\s+SET stage = 'committed'`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	newVer, applied, err := store.CommitRefreshTx(context.Background(), CommitRefreshTxInput{
		JournalID:             55,
		AccountID:             10,
		CageID:                7,
		BaseCredentialVersion: 1,
		NewCredentials:        map[string]any{"access_token": "new", "refresh_token": "new-rt"},
		NewTokenFingerprint:   ComputeRefreshTokenFingerprint("cid", "new-rt"),
	})
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, int64(2), newVer)
	require.NoError(t, mock.ExpectationsWereMet())
}
