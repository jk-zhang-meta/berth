package handler

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

func TestRentalAccountWebSocketCyberFailureUsesSecondTurnSnapshot(t *testing.T) {
	for _, mode := range []string{service.OpenAIWSIngressModePassthrough, service.OpenAIWSIngressModeCtxPool} {
		t.Run(mode, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer func() { _ = db.Close() }()
			expectSnapshot := func(rate float64, commission int) {
				mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(1701), int64(4201)).WillReturnRows(sqlmock.NewRows([]string{"managed", "allowed"}).AddRow(true, true))
				mock.ExpectQuery("SELECT m.group_id").WithArgs(int64(4201)).WillReturnRows(sqlmock.NewRows([]string{"group", "account", "seller", "commission", "rate", "time"}).AddRow(4201, 9901, 5, commission, rate, time.Now()))
			}
			expectSnapshot(1, 100)
			if mode == service.OpenAIWSIngressModeCtxPool {
				expectSnapshot(1, 100)
			}
			result := runOpenAIResponsesWebSocketUsageLogCase(t, openAIResponsesWSUsageLogCase{
				marketplace:               service.NewMarketplaceService(db),
				marketplaceUsage:          &service.MarketplaceUsageSnapshot{GroupID: 4201, AccountID: 9901, SellerID: 5, RateMultiplier: 1, CommissionBPS: 100},
				ingressMode:               mode,
				firstPayload:              `{"type":"response.create","model":"gpt-5.1","stream":false}`,
				secondPayload:             `{"type":"response.create","model":"gpt-5.1","stream":false}`,
				secondCyberFailure:        true,
				afterFirstUpstreamRequest: func(*service.ChannelService) error { expectSnapshot(2.5, 2500); expectSnapshot(2.5, 2500); return nil },
			})
			require.Len(t, result.logs, 2)
			cyberLogs := 0
			for _, log := range result.logs {
				if log.InputTokens == 9 {
					cyberLogs++
					require.Equal(t, 2.5, log.RateMultiplier)
					require.Equal(t, 2, log.OutputTokens)
				} else {
					require.Equal(t, 2, log.InputTokens)
					require.Equal(t, 1.0, log.RateMultiplier)
				}
			}
			require.Equal(t, 1, cyberLogs, "the failed turn records its consumed tokens exactly once")
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestRentalAccountWebSocketLeaseEndsBeforeSecondTurn(t *testing.T) {
	for _, mode := range []string{service.OpenAIWSIngressModePassthrough, service.OpenAIWSIngressModeCtxPool} {
		t.Run(mode, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer func() { _ = db.Close() }()
			checks := 1
			if mode == service.OpenAIWSIngressModeCtxPool {
				checks = 2
			}
			for i := 0; i < checks; i++ {
				mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(1701), int64(4201)).WillReturnRows(sqlmock.NewRows([]string{"managed", "allowed"}).AddRow(true, true))
			}
			result := runOpenAIResponsesWebSocketUsageLogCase(t, openAIResponsesWSUsageLogCase{
				marketplace:             service.NewMarketplaceService(db),
				ingressMode:             mode,
				firstPayload:            `{"type":"response.create","model":"gpt-5.1","stream":false}`,
				secondPayload:           `{"type":"response.create","model":"gpt-5.1","stream":false}`,
				secondTurnCloseExpected: true,
				afterFirstUpstreamRequest: func(*service.ChannelService) error {
					mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(1701), int64(4201)).WillReturnRows(sqlmock.NewRows([]string{"managed", "allowed"}).AddRow(true, false))
					return nil
				},
			})
			require.Len(t, result.upstreamPayloads, 1, "expired account lease must never forward the second turn, even without a rental proxy")
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestRentalAccountWebSocketExpiredBeforeFirstDispatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(1701), int64(4201)).WillReturnRows(sqlmock.NewRows([]string{"managed", "allowed"}).AddRow(true, false))
	var upstreamCalled atomic.Bool
	runOpenAIResponsesWebSocketUsageLogCase(t, openAIResponsesWSUsageLogCase{
		marketplace:               service.NewMarketplaceService(db),
		ingressMode:               service.OpenAIWSIngressModePassthrough,
		firstPayload:              `{"type":"response.create","model":"gpt-5.1","stream":false}`,
		firstFrameCloseExpected:   true,
		afterFirstUpstreamRequest: func(*service.ChannelService) error { upstreamCalled.Store(true); return nil },
	})
	require.False(t, upstreamCalled.Load(), "passthrough first-frame dispatch must recheck the captured lease")
	require.NoError(t, mock.ExpectationsWereMet())
}
