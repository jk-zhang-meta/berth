package handler

import (
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"testing"
)

func TestMarketplaceRevenueScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, role := range []string{"user", "admin"} {
		t.Run(role, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer func() { _ = db.Close() }()
			query := `SELECT .* FROM berth_marketplace_usage_revenue`
			if role == "user" {
				query += ` WHERE seller_id=\$1$`
			} else {
				query += `$`
			}
			expected := mock.ExpectQuery(query)
			if role == "user" {
				expected.WithArgs(int64(9))
			} else {
				expected.WithArgs()
			}
			expected.WillReturnRows(sqlmock.NewRows([]string{"gross", "paid", "pending", "platform"}).AddRow("1.25000001", "1", "0.12500001", "0.125"))
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/marketplace/revenue?seller_id=888", nil)
			c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 9})
			c.Set(string(middleware.ContextKeyUserRole), role)
			h := NewMarketplaceHandler(nil, db, nil, nil, true)
			h.Revenue(c)
			require.Equal(t, 200, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), `"gross_amount":1.25000001`)
			require.Contains(t, w.Body.String(), `"pending_income":0.12500001`)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
