//go:build unit

package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/stretchr/testify/require"
)

func newAdminTestRouter() *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(string(middleware.ContextKeyUserRole), service.RoleAdmin)
		c.Next()
	})
	return r
}

func newAdminTestContext(w http.ResponseWriter) (*gin.Context, *gin.Engine) {
	c, r := gin.CreateTestContext(w)
	c.Set(string(middleware.ContextKeyUserRole), service.RoleAdmin)
	return c, r
}

func runAdminRouteTest(method, path, body, role string, userID int64, params gin.Params, h gin.HandlerFunc) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = params
	if role != "" {
		c.Set(string(middleware.ContextKeyUserRole), role)
	}
	if userID > 0 {
		c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: userID})
	}
	h(c)
	return rec
}

func TestBerthRBAC_FailClosedMissingRoleAndNilStewards(t *testing.T) {
	acctHandler := &AccountHandler{}
	proxyHandler := &ProxyHandler{}
	grokHandler := &GrokOAuthHandler{}
	cnHandler := &CNProviderHandler{}

	// Missing role context MUST always return 403 (fail-closed!)
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		params gin.Params
		fn     gin.HandlerFunc
	}{
		{"accounts list missing role", http.MethodGet, "/accounts", "", nil, acctHandler.List},
		{"accounts get missing role", http.MethodGet, "/accounts/1", "", gin.Params{{Key: "id", Value: "1"}}, acctHandler.GetByID},
		{"claude reset credits missing role", http.MethodPost, "/accounts/1/claude/reset-credits", `{}`, gin.Params{{Key: "id", Value: "1"}}, acctHandler.ClaudeResetCredits},
		{"opencode settings missing role", http.MethodGet, "/accounts/opencode-go-usage/settings", "", nil, acctHandler.GetOpenCodeGoUsageSettings},
		{"proxies list missing role", http.MethodGet, "/proxies", "", nil, proxyHandler.List},
		{"proxies getAll missing role", http.MethodGet, "/proxies/all", "", nil, proxyHandler.GetAll},
		{"grok runtime sanity missing role", http.MethodGet, "/grok/runtime-sanity", "", nil, grokHandler.RuntimeSanity},
		{"cn quota missing role", http.MethodPost, "/accounts/1/cn-quota", "", gin.Params{{Key: "id", Value: "1"}}, cnHandler.QueryQuota},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := runAdminRouteTest(tc.method, tc.path, tc.body, "", 77, tc.params, tc.fn)
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		})
	}

	// Non-admin caller with stewards == nil MUST return 403 (never fall through to global admin query!)
	t.Run("user role with nil stewards fails closed on accounts list", func(t *testing.T) {
		rec := runAdminRouteTest(http.MethodGet, "/accounts", "", service.RoleUser, 77, nil, acctHandler.List)
		require.Equal(t, http.StatusForbidden, rec.Code)
	})
	t.Run("user role with nil stewards fails closed on proxies list", func(t *testing.T) {
		rec := runAdminRouteTest(http.MethodGet, "/proxies", "", service.RoleUser, 77, nil, proxyHandler.List)
		require.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestBerthRBAC_ClosedIDORAndAdminOnlyEndpoints(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	stewards := service.NewStewardStore(db)

	acctHandler := &AccountHandler{stewards: stewards}
	openaiOAuthHandler := &OpenAIOAuthHandler{stewards: stewards}
	grokHandler := &GrokOAuthHandler{stewards: stewards}
	cnHandler := &CNProviderHandler{stewards: stewards}

	// Admin-only endpoints MUST return 403 for RoleUser
	adminOnly := []struct {
		name   string
		method string
		path   string
		body   string
		fn     gin.HandlerFunc
	}{
		{"GetOpenCodeGoUsageSettings", http.MethodGet, "/opencode/settings", "", acctHandler.GetOpenCodeGoUsageSettings},
		{"UpdateOpenCodeGoUsageSettings", http.MethodPut, "/opencode/settings", `{"enabled":true}`, acctHandler.UpdateOpenCodeGoUsageSettings},
		{"GetUpstreamBillingProbeSettings", http.MethodGet, "/probe/settings", "", acctHandler.GetUpstreamBillingProbeSettings},
		{"UpdateUpstreamBillingProbeSettings", http.MethodPut, "/probe/settings", `{"enabled":true}`, acctHandler.UpdateUpstreamBillingProbeSettings},
		{"ProbeUpstreamBillingBatch", http.MethodPost, "/probe/batch", `{"account_ids":[1]}`, acctHandler.ProbeUpstreamBillingBatch},
		{"GetOllamaCloudUsageSettings", http.MethodGet, "/ollama/settings", "", acctHandler.GetOllamaCloudUsageSettings},
		{"UpdateOllamaCloudUsageSettings", http.MethodPut, "/ollama/settings", `{"enabled":true}`, acctHandler.UpdateOllamaCloudUsageSettings},
		{"CheckMixedChannel", http.MethodPost, "/accounts/check-mixed-channel", `{"platform":"anthropic","group_ids":[1]}`, acctHandler.CheckMixedChannel},
		{"SyncUpstreamModelsPreview_SSRF", http.MethodPost, "/accounts/sync-upstream-preview", `{"base_url":"http://169.254.169.254"}`, acctHandler.SyncUpstreamModelsPreview},
		{"GrokRuntimeSanity", http.MethodGet, "/grok/runtime-sanity", "", grokHandler.RuntimeSanity},
	}
	for _, tc := range adminOnly {
		t.Run("admin_only_"+tc.name, func(t *testing.T) {
			rec := runAdminRouteTest(tc.method, tc.path, tc.body, service.RoleUser, 77, nil, tc.fn)
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		})
	}

	// Per-account IDOR endpoints MUST check ownership and deny foreign account with 403
	foreignAccountEndpoints := []struct {
		name   string
		method string
		body   string
		fn     gin.HandlerFunc
	}{
		{"ClaudeResetCredits", http.MethodPost, `{}`, acctHandler.ClaudeResetCredits},
		{"RedeemClaudeResetCredit", http.MethodPost, `{"code":"abc"}`, acctHandler.RedeemClaudeResetCredit},
		{"RefreshReferrals", http.MethodPost, `{}`, openaiOAuthHandler.RefreshReferrals},
		{"SendReferralInvite", http.MethodPost, `{"email":"a@b.com"}`, openaiOAuthHandler.SendReferralInvite},
		{"GetOpenCodeGoUsage", http.MethodGet, "", acctHandler.GetOpenCodeGoUsage},
		{"SetOpenCodeGoUsageAutoRefresh", http.MethodPut, `{"enabled":true}`, acctHandler.SetOpenCodeGoUsageAutoRefresh},
		{"RefreshOpenCodeGoUsage", http.MethodPost, `{}`, acctHandler.RefreshOpenCodeGoUsage},
		{"CNQueryQuota", http.MethodPost, `{}`, cnHandler.QueryQuota},
		{"CNQueryBalance", http.MethodPost, `{}`, cnHandler.QueryBalance},
	}
	for _, tc := range foreignAccountEndpoints {
		t.Run("foreign_idor_"+tc.name, func(t *testing.T) {
			mock.ExpectQuery(`SELECT 1 FROM account_stewards`).
				WithArgs(int64(999), int64(77)).
				WillReturnRows(sqlmock.NewRows([]string{"one"}))
			rec := runAdminRouteTest(tc.method, "/accounts/999", tc.body, service.RoleUser, 77, gin.Params{{Key: "id", Value: "999"}}, tc.fn)
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestBerthRBAC_MandatoryProxyAndPositiveConcurrency(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	stewards := service.NewStewardStore(db)
	h := &AccountHandler{stewards: stewards}

	// Create without proxy_id for RoleUser -> 400
	t.Run("create_missing_proxy_rejected", func(t *testing.T) {
		rec := runAdminRouteTest(http.MethodPost, "/accounts", `{"name":"a","platform":"anthropic","type":"apikey","concurrency":2}`, service.RoleUser, 77, nil, h.Create)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	// Create with concurrency=0 -> 400
	t.Run("create_zero_concurrency_rejected", func(t *testing.T) {
		rec := runAdminRouteTest(http.MethodPost, "/accounts", `{"name":"a","platform":"anthropic","type":"apikey","proxy_id":10,"concurrency":0}`, service.RoleUser, 77, nil, h.Create)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	})

	// Update with proxy_id=0 (unbind attempt) for RoleUser -> 400
	t.Run("update_proxy_unbind_rejected", func(t *testing.T) {
		mock.ExpectQuery(`SELECT 1 FROM account_stewards`).WithArgs(int64(5), int64(77)).WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
		rec := runAdminRouteTest(http.MethodPut, "/accounts/5", `{"proxy_id":0}`, service.RoleUser, 77, gin.Params{{Key: "id", Value: "5"}}, h.Update)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.NoError(t, mock.ExpectationsWereMet())
	})

	// Update with concurrency=0 -> 400
	t.Run("update_zero_concurrency_rejected", func(t *testing.T) {
		mock.ExpectQuery(`SELECT 1 FROM account_stewards`).WithArgs(int64(5), int64(77)).WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
		rec := runAdminRouteTest(http.MethodPut, "/accounts/5", `{"concurrency":0}`, service.RoleUser, 77, gin.Params{{Key: "id", Value: "5"}}, h.Update)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

type berthProxyRegressionAdminStub struct {
	service.AdminService
	proxy    *service.Proxy
	proxies  []service.ProxyWithAccountCount
	accounts []service.ProxyAccountSummary
}

func (s *berthProxyRegressionAdminStub) GetProxy(_ context.Context, _ int64) (*service.Proxy, error) {
	cp := *s.proxy
	return &cp, nil
}
func (s *berthProxyRegressionAdminStub) CreateProxy(_ context.Context, in *service.CreateProxyInput) (*service.Proxy, error) {
	return &service.Proxy{ID: 55, Name: in.Name, Protocol: in.Protocol, Host: in.Host, Port: in.Port, Username: in.Username, Password: in.Password}, nil
}
func (s *berthProxyRegressionAdminStub) UpdateProxy(_ context.Context, id int64, in *service.UpdateProxyInput) (*service.Proxy, error) {
	user := ""
	if in.Username != nil {
		user = *in.Username
	}
	return &service.Proxy{ID: id, Name: in.Name, Protocol: in.Protocol, Host: in.Host, Port: in.Port, Username: user, Password: "secret-password"}, nil
}
func (s *berthProxyRegressionAdminStub) ListProxiesWithAccountCount(_ context.Context, _, _ int, _, _, _, _, _ string) ([]service.ProxyWithAccountCount, int64, error) {
	return s.proxies, int64(len(s.proxies)), nil
}
func (s *berthProxyRegressionAdminStub) ListProxiesByIDsWithAccountCount(_ context.Context, _ []int64, _, _ int, _, _, _, _, _ string) ([]service.ProxyWithAccountCount, int64, error) {
	return s.proxies, int64(len(s.proxies)), nil
}
func (s *berthProxyRegressionAdminStub) GetAllProxiesWithAccountCount(_ context.Context) ([]service.ProxyWithAccountCount, error) {
	return s.proxies, nil
}
func (s *berthProxyRegressionAdminStub) GetProxiesByIDs(_ context.Context, ids []int64) ([]service.Proxy, error) {
	out := make([]service.Proxy, 0, len(ids))
	for _, id := range ids {
		if id == 10 {
			out = append(out, service.Proxy{ID: 10, Name: "my-proxy", Protocol: "http", Host: "1.2.3.4", Port: 8080, Username: "u", Password: "top-secret-password"})
		} else if id == 99 {
			out = append(out, service.Proxy{ID: 99, Name: "Tokyo Rental", Protocol: "socks5", Host: "secret.rent.host", Port: 1080, Username: "rent-user", Password: "rent-password", ExitCountry: "Japan", ExitCountryCode: "JP", ExitTimezone: "Asia/Tokyo"})
		}
	}
	return out, nil
}
func (s *berthProxyRegressionAdminStub) GetProxyAccounts(_ context.Context, _ int64) ([]service.ProxyAccountSummary, error) {
	return s.accounts, nil
}

func TestBerthRBAC_ProxyPasswordRedactionDirectRejectAndRentalListing(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	stewards := service.NewStewardStore(db)

	stub := &berthProxyRegressionAdminStub{
		proxy: &service.Proxy{ID: 10, Name: "my-proxy", Protocol: "http", Host: "1.2.3.4", Port: 8080, Username: "u", Password: "top-secret-password"},
		proxies: []service.ProxyWithAccountCount{
			{Proxy: service.Proxy{ID: 10, Name: "my-proxy", Protocol: "http", Host: "1.2.3.4", Port: 8080, Username: "u", Password: "top-secret-password"}, AccountCount: 1},
		},
		accounts: []service.ProxyAccountSummary{
			{ID: 100, Name: "mine"},
			{ID: 200, Name: "foreign"},
		},
	}
	h := NewProxyHandler(stub)
	h.SetStewards(stewards)

	// 1. GetByID redacts password for RoleUser (Codex Blocker #4.1)
	t.Run("get_by_id_redacts_password_for_user", func(t *testing.T) {
		mock.ExpectQuery(`SELECT 1 FROM proxy_stewards`).WithArgs(int64(10), int64(7)).WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
		rec := runAdminRouteTest(http.MethodGet, "/proxies/10", "", service.RoleUser, 7, gin.Params{{Key: "id", Value: "10"}}, h.GetByID)
		require.Equal(t, http.StatusOK, rec.Code)
		require.NotContains(t, rec.Body.String(), "top-secret-password")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	// 2. Create redacts password for RoleUser
	t.Run("create_redacts_password_for_user", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO proxy_stewards`).WithArgs(int64(55), int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
		rec := runAdminRouteTest(http.MethodPost, "/proxies", `{"name":"p","protocol":"http","host":"1.2.3.4","port":8080,"username":"u","password":"top-secret-password"}`, service.RoleUser, 7, nil, h.Create)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), "top-secret-password")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	// 3. Create rejects fallback_mode="direct" for RoleUser
	t.Run("create_rejects_direct_fallback_for_user", func(t *testing.T) {
		rec := runAdminRouteTest(http.MethodPost, "/proxies", `{"name":"p","protocol":"http","host":"1.2.3.4","port":8080,"fallback_mode":"direct"}`, service.RoleUser, 7, nil, h.Create)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "PROXY_DIRECT_FALLBACK_FORBIDDEN")
	})

	// 4. Update rejects fallback_mode="direct" for RoleUser
	t.Run("update_rejects_direct_fallback_for_user", func(t *testing.T) {
		mock.ExpectQuery(`SELECT 1 FROM proxy_stewards`).WithArgs(int64(10), int64(7)).WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
		rec := runAdminRouteTest(http.MethodPut, "/proxies/10", `{"fallback_mode":"direct"}`, service.RoleUser, 7, gin.Params{{Key: "id", Value: "10"}}, h.Update)
		require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "PROXY_DIRECT_FALLBACK_FORBIDDEN")
		require.NoError(t, mock.ExpectationsWereMet())
	})

	// 5. GetProxyAccounts filters out foreign accounts for RoleUser
	t.Run("get_proxy_accounts_filters_foreign", func(t *testing.T) {
		mock.ExpectQuery(`SELECT 1 FROM proxy_stewards`).WithArgs(int64(10), int64(7)).WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
		mock.ExpectQuery(`SELECT 1 FROM account_stewards`).WithArgs(int64(100), int64(7)).WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
		mock.ExpectQuery(`SELECT 1 FROM account_stewards`).WithArgs(int64(200), int64(7)).WillReturnRows(sqlmock.NewRows([]string{"one"}))
		rec := runAdminRouteTest(http.MethodGet, "/proxies/10/accounts", "", service.RoleUser, 7, gin.Params{{Key: "id", Value: "10"}}, h.GetProxyAccounts)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), `"mine"`)
		require.NotContains(t, rec.Body.String(), `"foreign"`)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	// 6. GetAll includes caller's active rented proxies redacted (no host/port/user/pass, is_rental=true)
	t.Run("get_all_includes_redacted_rentals_and_redacts_owned_passwords", func(t *testing.T) {
		mock.ExpectQuery(`SELECT proxy_id FROM proxy_stewards`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"proxy_id"}).AddRow(int64(10)))
		mock.ExpectQuery(`FROM berth_marketplace_orders`).WithArgs(int64(7)).WillReturnRows(
			sqlmock.NewRows([]string{"rental_proxy_id", "id", "expires_at"}).AddRow(int64(99), int64(501), nil),
		)
		rec := runAdminRouteTest(http.MethodGet, "/proxies/all", "", service.RoleUser, 7, nil, h.GetAll)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), "top-secret-password")
		require.NotContains(t, rec.Body.String(), "rent-password")
		require.NotContains(t, rec.Body.String(), "secret.rent.host")

		var resp struct {
			Data []map[string]any `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		require.Len(t, resp.Data, 2)
		var foundRental map[string]any
		for _, item := range resp.Data {
			if item["id"] == float64(99) {
				foundRental = item
			}
		}
		require.NotNil(t, foundRental)
		require.Equal(t, true, foundRental["is_rental"])
		require.Equal(t, float64(501), foundRental["rental_order_id"])
		require.Equal(t, "", foundRental["host"])
		require.Equal(t, float64(0), foundRental["port"])
		require.NoError(t, mock.ExpectationsWereMet())
	})
}
