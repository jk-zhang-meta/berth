//go:build unit

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jk-zhang-meta/berth/internal/config"
	"github.com/stretchr/testify/require"
)

func TestDefaultOpenAIAccountScheduler_BerthStickyCapacity(t *testing.T) {
	cacheErr := errors.New("capacity cache unavailable")
	for _, tc := range []struct {
		name        string
		disable     bool
		acquired    bool
		acquireErr  error
		rpmErr      error
		wantEscape  bool
		wantWait    bool
		wantErr     bool
		wantRelease bool
	}{
		{name: "default RPM denial spills", acquired: true, wantEscape: true, wantRelease: true},
		{name: "explicit disable keeps RPM wait", disable: true, acquired: true, wantWait: true, wantRelease: true},
		{name: "explicit disable keeps concurrency wait", disable: true, wantWait: true},
		{name: "explicit disable propagates acquisition error", disable: true, acquireErr: cacheErr, wantErr: true},
		{name: "explicit disable propagates RPM error and releases", disable: true, acquired: true, rpmErr: cacheErr, wantErr: true, wantRelease: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := Account{
				ID: 42, Platform: PlatformOpenAI, Type: AccountTypeAPIKey,
				Status: StatusActive, Schedulable: true, Concurrency: 2,
				Extra: map[string]any{"base_rpm": 7},
			}
			cache := &stubConcurrencyCacheForTest{acquireResult: tc.acquired, acquireErr: tc.acquireErr}
			rpm := &hardRPMStub{err: tc.rpmErr}
			concurrency := NewConcurrencyService(cache)
			concurrency.SetRPMCache(rpm)
			cfg := &config.Config{}
			cfg.Gateway.Scheduling.StickySessionWaitTimeout = 17 * time.Second
			cfg.Gateway.Scheduling.StickySessionMaxWaiting = 3
			// Berth's capacity spill remains active with soft escape disabled.
			cfg.Gateway.OpenAIScheduler.StickyEscapeEnabled = false
			scheduler := &defaultOpenAIAccountScheduler{
				service: &OpenAIGatewayService{
					accountRepo: schedulerTestOpenAIAccountRepo{accounts: []Account{account}},
					cache:       &schedulerTestGatewayCache{sessionBindings: map[string]int64{"openai:capacity": account.ID}},
					cfg:         cfg, concurrencyService: concurrency,
				},
				stats: newOpenAIAccountRuntimeStats(),
			}
			selection, escaped, err := scheduler.selectBySessionHash(context.Background(), OpenAIAccountScheduleRequest{
				Platform: PlatformOpenAI, SessionHash: "capacity", RequestedModel: "gpt-5.1",
				DisableStickyEscape: tc.disable,
			})
			require.Equal(t, tc.wantEscape, escaped)
			if tc.wantErr {
				require.ErrorIs(t, err, cacheErr)
			} else {
				require.NoError(t, err)
			}
			if tc.wantWait {
				require.NotNil(t, selection)
				require.False(t, selection.Acquired)
				require.Nil(t, selection.ReleaseFunc)
				require.NotNil(t, selection.WaitPlan)
				require.Equal(t, account.ID, selection.WaitPlan.AccountID)
				require.Equal(t, account.Concurrency, selection.WaitPlan.MaxConcurrency)
				require.Equal(t, account.GetBaseRPM(), selection.WaitPlan.MaxRPM)
				require.Equal(t, 17*time.Second, selection.WaitPlan.Timeout)
				require.Equal(t, 3, selection.WaitPlan.MaxWaiting)
			} else {
				require.Nil(t, selection)
			}
			if tc.wantRelease {
				require.Equal(t, 1, rpm.calls)
				require.Equal(t, []int64{account.ID}, cache.releasedAccountIDs)
			} else {
				require.Zero(t, rpm.calls)
				require.Empty(t, cache.releasedAccountIDs)
			}
		})
	}
}
