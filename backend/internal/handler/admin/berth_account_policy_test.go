//go:build unit

package admin

import (
	"context"
	"encoding/json"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jk-zhang-meta/berth/internal/pkg/openai"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jk-zhang-meta/berth/internal/server/middleware"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func berthPolicyRequest(handler gin.HandlerFunc, role, body string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.CustomRecovery(func(c *gin.Context, _ any) { c.AbortWithStatus(500) }))
	router.POST("/", func(c *gin.Context) {
		c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 77})
		c.Set(string(middleware.ContextKeyUserRole), role)
		handler(c)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	return rec
}

func TestBerthOAuthRejectsForeignProxyBeforeUpstream(t *testing.T) {
	o := &OpenAIOAuthHandler{}
	g := &GrokOAuthHandler{}
	a := &AntigravityOAuthHandler{}
	gem := &GeminiOAuthHandler{}
	claude := &OAuthHandler{}
	cases := map[string]gin.HandlerFunc{
		"openai auth": o.GenerateAuthURL, "openai exchange": o.ExchangeCode,
		"openai refresh": o.RefreshToken, "openai create": o.CreateAccountFromOAuth,
		"openai pat": o.CreateAccountFromCodexPAT,
		"grok auth":  g.GenerateAuthURL, "grok exchange": g.ExchangeCode,
		"grok refresh": g.RefreshToken, "grok create": g.CreateAccountFromOAuth,
		"grok sso":         g.CreateAccountsFromSSO,
		"antigravity auth": a.GenerateAuthURL, "antigravity exchange": a.ExchangeCode,
		"antigravity refresh": a.RefreshToken,
		"gemini auth":         gem.GenerateAuthURL, "gemini exchange": gem.ExchangeCode,
		"grok validate sso": g.ValidateSSOToken, "grok password": g.AuthorizePassword,
		"claude auth": claude.GenerateAuthURL, "claude setup": claude.GenerateSetupTokenURL,
		"claude exchange": claude.ExchangeCode, "claude setup exchange": claude.ExchangeSetupTokenCode,
		"claude cookie": claude.CookieAuth, "claude setup cookie": claude.SetupTokenCookieAuth,
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			rec := berthPolicyRequest(handler, service.RoleUser, `{"proxy_id":88,"session_id":"s","state":"s","code":"c","refresh_token":"r","access_token":"at-test","sso_token":"s"}`)
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		})
	}
}

type berthPolicyProxyRepo struct{ service.ProxyRepository }

func (berthPolicyProxyRepo) GetByID(_ context.Context, id int64) (*service.Proxy, error) {
	return &service.Proxy{ID: id, Protocol: "http", Host: "127.0.0.1", Port: 8080}, nil
}

type berthPolicyOpenAIClient struct{ service.OpenAIOAuthClient }

type berthPolicyShadowService struct {
	service.AdminService
	opts service.ShadowOptions
}

func (s *berthPolicyShadowService) CreateShadow(_ context.Context, _ int64, opts service.ShadowOptions) (*service.Account, error) {
	s.opts = opts
	return &service.Account{ID: 43, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth}, nil
}

func TestBerthShadowHandlerRestrictsPoolOptions(t *testing.T) {
	for _, role := range []string{service.RoleUser, service.RoleAdmin} {
		t.Run(role, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			t.Cleanup(func() { db.Close() })
			svc := &berthPolicyShadowService{}
			h := &OpenAIOAuthHandler{adminService: svc, stewards: service.NewStewardStore(db)}
			if role == service.RoleUser {
				mock.ExpectQuery("SELECT 1 FROM account_stewards").WithArgs(int64(42), int64(77)).WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
			}
			mock.ExpectExec("INSERT INTO account_stewards").WithArgs(int64(43), int64(77)).WillReturnResult(sqlmock.NewResult(0, 1))
			rec := berthPolicyRequest(func(c *gin.Context) {
				c.Params = gin.Params{{Key: "id", Value: "42"}}
				h.CreateShadow(c)
			}, role, `{"priority":999,"group_ids":[91]}`)
			require.Equal(t, 200, rec.Code, rec.Body.String())
			if role == service.RoleUser {
				require.Zero(t, svc.opts.Priority)
				require.Empty(t, svc.opts.GroupIDs)
				require.True(t, svc.opts.SkipDefaultGroupBind)
			} else {
				require.Equal(t, 999, svc.opts.Priority)
				require.Equal(t, []int64{91}, svc.opts.GroupIDs)
				require.False(t, svc.opts.SkipDefaultGroupBind)
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func (berthPolicyOpenAIClient) ExchangeCode(context.Context, string, string, string, string, string) (*openai.TokenResponse, error) {
	return &openai.TokenResponse{AccessToken: "new-access", RefreshToken: "new-refresh", ExpiresIn: 3600}, nil
}

func TestBerthOAuthCreationPoolPolicy(t *testing.T) {
	for _, role := range []string{service.RoleUser, service.RoleAdmin} {
		for _, flow := range []string{"openai", "grok", "sso"} {
			t.Run(role+"/"+flow, func(t *testing.T) {
				svc := newCodexImportMemoryAdminService(nil)
				db, mock, err := sqlmock.New()
				require.NoError(t, err)
				t.Cleanup(func() { db.Close() })
				store := service.NewStewardStore(db)
				mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(88)).WillReturnRows(sqlmock.NewRows([]string{"verified"}).AddRow(true))
				if role == service.RoleUser {
					mock.ExpectQuery("SELECT 1 FROM proxy_stewards").WithArgs(int64(88), int64(77)).WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
				}
				mock.ExpectExec("INSERT INTO account_stewards").WithArgs(int64(100), int64(77)).WillReturnResult(sqlmock.NewResult(0, 1))
				body := map[string]any{"name": "owned", "proxy_id": 88, "priority": 999, "group_ids": []int64{91}, "rate_multiplier": 4, "sso_token": "s", "code": "c"}
				var handler gin.HandlerFunc
				if flow == "openai" {
					oauth := service.NewOpenAIOAuthService(berthPolicyProxyRepo{}, berthPolicyOpenAIClient{})
					t.Cleanup(oauth.Stop)
					auth, err := oauth.GenerateAuthURL(context.Background(), nil, "", service.PlatformOpenAI)
					require.NoError(t, err)
					u, err := url.Parse(auth.AuthURL)
					require.NoError(t, err)
					body["session_id"] = auth.SessionID
					body["state"] = u.Query().Get("state")
					handler = (&OpenAIOAuthHandler{openaiOAuthService: oauth, adminService: svc, stewards: store}).CreateAccountFromOAuth
				} else {
					oauth := service.NewGrokOAuthService(berthPolicyProxyRepo{}, grokImportOAuthClientStub{})
					t.Cleanup(oauth.Stop)
					h := &GrokOAuthHandler{grokOAuthService: oauth, adminService: svc, stewards: store}
					handler = h.CreateAccountsFromSSO
					if flow == "grok" {
						auth, err := oauth.GenerateAuthURL(context.Background(), nil, "")
						require.NoError(t, err)
						body["session_id"] = auth.SessionID
						body["state"] = auth.State
						handler = h.CreateAccountFromOAuth
					}
				}
				rec := berthPolicyRequest(handler, role, stringMustJSON(t, body))
				require.Equal(t, 200, rec.Code, rec.Body.String())
				require.Len(t, svc.createdAccounts, 1)
				input := svc.createdAccounts[0]
				require.Equal(t, int64(88), *input.ProxyID)
				if role == service.RoleUser {
					require.Zero(t, input.Priority)
					require.Empty(t, input.GroupIDs)
					require.Nil(t, input.RateMultiplier)
					require.True(t, input.SkipDefaultGroupBind)
				} else {
					require.Equal(t, 999, input.Priority)
					require.Equal(t, []int64{91}, input.GroupIDs)
					require.False(t, input.SkipDefaultGroupBind)
				}
				require.NoError(t, mock.ExpectationsWereMet())
			})
		}
	}
}

func TestBerthCodexImportOwnedIdentityPreservesAdminFields(t *testing.T) {
	previous := service.DefaultIdempotencyCoordinator()
	service.SetDefaultIdempotencyCoordinator(nil)
	t.Cleanup(func() { service.SetDefaultIdempotencyCoordinator(previous) })
	svc := newCodexImportMemoryAdminService([]service.Account{{ID: 42, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Credentials: map[string]any{"chatgpt_account_id": "owned", "chatgpt_user_id": "identity", "refresh_token": "old"}}})
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	h := &AccountHandler{adminService: svc, stewards: service.NewStewardStore(db)}
	mock.ExpectQuery("SELECT EXISTS").WithArgs(int64(88)).WillReturnRows(sqlmock.NewRows([]string{"verified"}).AddRow(true))
	mock.ExpectQuery("SELECT 1 FROM proxy_stewards").WithArgs(int64(88), int64(77)).WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
	for i := 0; i < 2; i++ {
		mock.ExpectQuery("SELECT 1 FROM account_stewards").WithArgs(int64(42), int64(77)).WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
	}
	body := map[string]any{"contents": []string{stringMustJSON(t, buildCodexRefreshImportValue(t, "owned", "identity", "new"))}, "proxy_id": 88, "priority": 999, "rate_multiplier": 4, "group_ids": []int64{91}}
	rec := berthPolicyRequest(h.ImportCodexSession, service.RoleUser, stringMustJSON(t, body))
	require.Equal(t, 200, rec.Code, rec.Body.String())
	require.Len(t, svc.updatedAccounts, 1)
	require.Empty(t, svc.createdAccounts)
	input := svc.updatedAccounts[0].input
	require.Equal(t, "new", input.Credentials["refresh_token"])
	require.Nil(t, input.Priority)
	require.Nil(t, input.RateMultiplier)
	require.Nil(t, input.GroupIDs)
	require.Equal(t, int64(88), *input.ProxyID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestBerthCodexImportCannotOverwriteForeignIdentity(t *testing.T) {
	previous := service.DefaultIdempotencyCoordinator()
	service.SetDefaultIdempotencyCoordinator(nil)
	t.Cleanup(func() { service.SetDefaultIdempotencyCoordinator(previous) })
	svc := newCodexImportMemoryAdminService([]service.Account{{ID: 42, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Credentials: map[string]any{"chatgpt_account_id": "shared", "chatgpt_user_id": "identity", "refresh_token": "foreign-secret"}}})
	h := &AccountHandler{adminService: svc}
	body, err := json.Marshal(map[string]any{"contents": []string{stringMustJSON(t, buildCodexRefreshImportValue(t, "shared", "identity", "replacement"))}, "priority": 999, "group_ids": []int64{91}, "rate_multiplier": 4})
	require.NoError(t, err)
	rec := berthPolicyRequest(h.ImportCodexSession, service.RoleUser, string(body))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Empty(t, svc.updatedAccounts)
	require.Equal(t, "foreign-secret", svc.accounts[0].Credentials["refresh_token"])
	require.Len(t, svc.createdAccounts, 1)
	require.Zero(t, svc.createdAccounts[0].Priority)
	require.Empty(t, svc.createdAccounts[0].GroupIDs)
	require.Nil(t, svc.createdAccounts[0].RateMultiplier)
}

func stringMustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

func TestBerthDuplicateClaimsBeforeIdempotentReplay(t *testing.T) {
	svc := &duplicateAccountAdminServiceStub{account: &service.Account{ID: 43, Name: "copy", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth}}
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	h := &AccountHandler{adminService: svc, stewards: service.NewStewardStore(db)}
	previous := service.DefaultIdempotencyCoordinator()
	service.SetDefaultIdempotencyCoordinator(service.NewIdempotencyCoordinator(newMemoryIdempotencyRepoStub(), service.DefaultIdempotencyConfig()))
	t.Cleanup(func() { service.SetDefaultIdempotencyCoordinator(previous) })
	mock.ExpectQuery("SELECT 1 FROM account_stewards").WithArgs(int64(42), int64(77)).WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
	mock.ExpectExec("INSERT INTO account_stewards").WithArgs(int64(43), int64(77)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT 1 FROM account_stewards").WithArgs(int64(42), int64(77)).WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))
	call := func() *httptest.ResponseRecorder {
		return berthPolicyRequest(func(c *gin.Context) {
			c.Params = gin.Params{{Key: "id", Value: "42"}}
			c.Request.Header.Set("Idempotency-Key", "berth-duplicate")
			h.Duplicate(c)
		}, service.RoleUser, `{}`)
	}
	require.Equal(t, 200, call().Code)
	second := call()
	require.Equal(t, 200, second.Code)
	require.Equal(t, "true", second.Header().Get("X-Idempotency-Replayed"))
	require.Equal(t, 1, svc.calls)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestBerthGrokReconcileRequiresAdmin(t *testing.T) {
	for _, body := range []string{`{}`, `{"apply":true,"dry_run":false}`} {
		reconciler := &grokOAuthReconcilerStub{result: &service.GrokOAuthReconcileResult{}}
		h := &GrokOAuthHandler{reconciler: reconciler}
		require.Equal(t, http.StatusForbidden, berthPolicyRequest(h.ReconcileOAuthAccounts, service.RoleUser, body).Code)
		require.Zero(t, reconciler.calls)
		require.Equal(t, http.StatusOK, berthPolicyRequest(h.ReconcileOAuthAccounts, service.RoleAdmin, body).Code)
		require.Equal(t, 1, reconciler.calls)
	}
}
