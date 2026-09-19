package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestMarketplaceSettingsAuthorization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, role, method, body string
		status                   int
	}{
		{"anonymous", "", "GET", "", 401},
		{"user read", "user", "GET", "", 200},
		{"user cannot write", "user", "PUT", `{"rent_commission_bps":9999}`, 403},
		{"admin write", "admin", "PUT", `{"rent_commission_bps":125,"usage_commission_bps":0}`, 200},
		{"invalid bound", "admin", "PUT", `{"rent_commission_bps":10001}`, 400},
		{"fractional bps", "admin", "PUT", `{"rent_commission_bps":1.2}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer func() { _ = db.Close() }()
			h := NewMarketplaceHandler(service.NewMarketplaceService(db), db, nil, nil, true)
			if tc.status == 200 {
				if tc.method == "GET" {
					mock.ExpectQuery("SELECT rent_commission_bps").WillReturnRows(sqlmock.NewRows([]string{"rent_commission_bps", "usage_commission_bps"}).AddRow(125, 0))
				} else {
					mock.ExpectQuery("UPDATE berth_marketplace_settings").WithArgs(125, 0).WillReturnRows(sqlmock.NewRows([]string{"rent_commission_bps", "usage_commission_bps"}).AddRow(125, 0))
				}
			}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(tc.method, "/marketplace/settings", strings.NewReader(tc.body))
			c.Request.Header.Set("Content-Type", "application/json")
			if tc.role != "" {
				c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 1})
				c.Set(string(middleware.ContextKeyUserRole), tc.role)
			}
			if tc.method == "GET" {
				h.GetSettings(c)
			} else {
				h.UpdateSettings(c)
			}
			require.Equal(t, tc.status, w.Code, w.Body.String())
			if tc.status == 200 {
				require.Contains(t, w.Body.String(), `"rent_commission_bps":125`)
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
