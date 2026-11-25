//go:build unit

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/config"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyAuthPrepaidMarketplaceQuotaZeroBalanceAdmission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	groupID := int64(90)

	cases := []struct {
		name       string
		balance    float64
		rentalMode string
		orderID    int64
		sellerID   int64
		wantStatus int
	}{
		{
			name:       "prepaid quota buyer with $0 balance is admitted",
			balance:    0,
			rentalMode: service.MarketplaceRentalModeQuota,
			orderID:    77,
			sellerID:   1,
			wantStatus: http.StatusOK,
		},
		{
			name:       "prepaid hybrid buyer with $0 balance is admitted",
			balance:    0,
			rentalMode: service.MarketplaceRentalModeHybrid,
			orderID:    78,
			sellerID:   1,
			wantStatus: http.StatusOK,
		},
		{
			name:       "prepaid quota buyer with negative debt balance is blocked",
			balance:    -0.01,
			rentalMode: service.MarketplaceRentalModeQuota,
			orderID:    77,
			sellerID:   1,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "duration buyer with $0 balance is blocked",
			balance:    0,
			rentalMode: service.MarketplaceRentalModeDuration,
			orderID:    79,
			sellerID:   1,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "owner self-use with $0 balance is blocked",
			balance:    0,
			rentalMode: service.MarketplaceRentalModeQuota,
			orderID:    77,
			sellerID:   2, // same as buyer user ID 2
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer func() { _ = db.Close() }()

			// 1. GroupAccess: managed=true, allowed=true
			mock.ExpectQuery("SELECT EXISTS\\(SELECT 1 FROM berth_account_groups WHERE group_id=\\$2\\)").
				WithArgs(int64(2), groupID).
				WillReturnRows(sqlmock.NewRows([]string{"managed", "allowed"}).AddRow(true, true))
			// 2. usageSnapshotForUser: returns active order metadata including rental_mode & order_id
			mock.ExpectQuery("SELECT m.group_id,m.account_id,m.owner_user_id").
				WithArgs(groupID, int64(2)).
				WillReturnRows(sqlmock.NewRows([]string{
					"group_id", "account_id", "owner_user_id", "usage_commission_bps",
					"rate_multiplier", "admitted_at", "order_id", "rental_mode",
				}).AddRow(groupID, int64(11), tc.sellerID, 0, 1.0, time.Now(), tc.orderID, tc.rentalMode))

			user := &service.User{
				ID:            2,
				Role:          service.RoleUser,
				Status:        service.StatusActive,
				Balance:       tc.balance,
				Concurrency:   2,
				AllowedGroups: []int64{groupID},
			}
			key := &service.APIKey{
				ID:      33,
				UserID:  user.ID,
				GroupID: &groupID,
				Key:     "sk-quota-test",
				Status:  service.StatusActive,
				User:    user,
				Group: &service.Group{
					ID:               groupID,
					Name:             "Berth account 11",
					Platform:         service.PlatformOpenAI,
					Status:           service.StatusActive,
					IsExclusive:      true,
					SubscriptionType: service.SubscriptionTypeStandard,
					Hydrated:         true,
				},
			}
			repo := &stubApiKeyRepo{
				getByKey: func(context.Context, string) (*service.APIKey, error) {
					clone := *key
					return &clone, nil
				},
			}
			cfg := &config.Config{RunMode: config.RunModeStandard}
			svc := service.NewAPIKeyService(repo, nil, nil, nil, nil, nil, cfg)
			svc.SetMarketplace(service.NewMarketplaceService(db))
			r := newAuthTestRouter(svc, nil, cfg)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/t", nil)
			req.Header.Set("x-api-key", key.Key)
			r.ServeHTTP(w, req)

			require.Equal(t, tc.wantStatus, w.Code, w.Body.String())
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
