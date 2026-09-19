//go:build unit

package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type berthProxyPolicyService struct {
	service.AdminService
	called bool
}

func (s *berthProxyPolicyService) CreateProxy(_ context.Context, in *service.CreateProxyInput) (*service.Proxy, error) {
	s.called = true
	return &service.Proxy{ID: 77, BackupProxyID: in.BackupProxyID}, nil
}

func (s *berthProxyPolicyService) UpdateProxy(_ context.Context, id int64, in *service.UpdateProxyInput) (*service.Proxy, error) {
	s.called = true
	return &service.Proxy{ID: id, BackupProxyID: in.BackupProxyID}, nil
}

func TestBerthProxyBackupOwnership(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, tc := range []struct {
			name, role     string
			owned, allowed bool
		}{
			{"foreign backup", service.RoleUser, false, false},
			{"own backup", service.RoleUser, true, true},
			{"admin backup", service.RoleAdmin, false, true},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				db, mock, err := sqlmock.New()
				require.NoError(t, err)
				defer func() { _ = db.Close() }()
				if method == http.MethodPut && tc.role != service.RoleAdmin {
					mock.ExpectQuery("SELECT 1 FROM proxy_stewards").WithArgs(int64(10), int64(7)).WillReturnRows(sqlmock.NewRows([]string{"owned"}).AddRow(1))
				}
				mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(20)).WillReturnRows(sqlmock.NewRows([]string{"verified"}).AddRow(true))
				if tc.role != service.RoleAdmin {
					rows := sqlmock.NewRows([]string{"owned"})
					if tc.owned {
						rows.AddRow(1)
					}
					mock.ExpectQuery("SELECT 1 FROM proxy_stewards").WithArgs(int64(20), int64(7)).WillReturnRows(rows)
				}
				if method == http.MethodPost && tc.allowed {
					mock.ExpectExec("INSERT INTO proxy_stewards").WithArgs(int64(77), int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
				}
				svc := &berthProxyPolicyService{}
				h := NewProxyHandler(svc)
				h.SetStewards(service.NewStewardStore(db))
				router := gin.New()
				router.Use(func(c *gin.Context) {
					c.Set(string(middleware.ContextKeyUserRole), tc.role)
					c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 7})
				})
				path := "/proxies"
				if method == http.MethodPost {
					router.POST(path, h.Create)
				} else {
					router.PUT(path+"/:id", h.Update)
					path += "/10"
				}
				body := `{"name":"mine","protocol":"http","host":"127.0.0.1","port":8080,"backup_proxy_id":20,"fallback_mode":"proxy","expires_at":1}`
				req := httptest.NewRequest(method, path, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				want := http.StatusForbidden
				if tc.allowed {
					want = http.StatusOK
				}
				require.Equal(t, want, w.Code, w.Body.String())
				require.Equal(t, tc.allowed, svc.called)
				require.NoError(t, mock.ExpectationsWereMet())
			})
		}
	}
}
