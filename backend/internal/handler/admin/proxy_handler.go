package admin

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jk-zhang-meta/berth/internal/handler/dto"
	"github.com/jk-zhang-meta/berth/internal/pkg/response"
	"github.com/jk-zhang-meta/berth/internal/service"

	"github.com/gin-gonic/gin"
)

// ProxyHandler handles admin proxy management
type ProxyHandler struct {
	adminService       service.AdminService
	stewards           *service.StewardStore
	concurrencyService *service.ConcurrencyService
}

func (h *ProxyHandler) SetStewards(store *service.StewardStore) {
	if h == nil {
		return
	}
	h.stewards = store
}

func (h *ProxyHandler) SetConcurrencyService(cs *service.ConcurrencyService) {
	if h == nil {
		return
	}
	h.concurrencyService = cs
}

func (h *ProxyHandler) proxyRuntimeUsage(ctx context.Context, ids []int64) (map[int64]int, map[int64]int) {
	concurrency := make(map[int64]int, len(ids))
	rpm := make(map[int64]int, len(ids))
	if h == nil || h.concurrencyService == nil || len(ids) == 0 {
		return concurrency, rpm
	}
	if values, err := h.concurrencyService.GetProxyConcurrencyBatch(ctx, ids); err == nil {
		concurrency = values
	}
	if values, err := h.concurrencyService.GetProxyRPMBatch(ctx, ids); err == nil {
		rpm = values
	}
	return concurrency, rpm
}

// NewProxyHandler creates a new admin proxy handler
func NewProxyHandler(adminService service.AdminService) *ProxyHandler {
	return &ProxyHandler{
		adminService: adminService,
	}
}

// CreateProxyRequest represents create proxy request
type CreateProxyRequest struct {
	Name           string `json:"name" binding:"required"`
	Protocol       string `json:"protocol" binding:"required,oneof=http https socks5 socks5h"`
	Host           string `json:"host" binding:"required"`
	Port           int    `json:"port" binding:"required,min=1,max=65535"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	ExpiresAt      *int64 `json:"expires_at"`
	FallbackMode   string `json:"fallback_mode" binding:"omitempty,oneof=none proxy direct"`
	BackupProxyID  *int64 `json:"backup_proxy_id"`
	ExpiryWarnDays int    `json:"expiry_warn_days" binding:"omitempty,min=0"`
	MaxAccounts    int    `json:"max_accounts" binding:"omitempty,min=0"`
	MaxRPM         int    `json:"max_rpm" binding:"omitempty,min=0"`
	MaxConcurrency int    `json:"max_concurrency" binding:"omitempty,min=0"`
}

// UpdateProxyRequest represents update proxy request
type UpdateProxyRequest struct {
	Name           string                 `json:"name"`
	Protocol       string                 `json:"protocol" binding:"omitempty,oneof=http https socks5 socks5h"`
	Host           string                 `json:"host"`
	Port           int                    `json:"port" binding:"omitempty,min=1,max=65535"`
	Username       *string                `json:"username"`
	Password       *string                `json:"password"`
	Status         string                 `json:"status" binding:"omitempty,oneof=active inactive"`
	ExpiresAt      dto.NullableInt64Field `json:"expires_at"`
	FallbackMode   string                 `json:"fallback_mode" binding:"omitempty,oneof=none proxy direct"`
	BackupProxyID  dto.NullableInt64Field `json:"backup_proxy_id"`
	ExpiryWarnDays *int                   `json:"expiry_warn_days" binding:"omitempty,min=0"`
	MaxAccounts    *int                   `json:"max_accounts" binding:"omitempty,min=0"`
	MaxRPM         *int                   `json:"max_rpm" binding:"omitempty,min=0"`
	MaxConcurrency *int                   `json:"max_concurrency" binding:"omitempty,min=0"`
}

// List handles listing all proxies with pagination
// GET /api/v1/admin/proxies
func (h *ProxyHandler) List(c *gin.Context) {
	if h.scopedAdminProxyRead(c) {
		return
	}
	page, pageSize := response.ParsePagination(c)
	protocol := c.Query("protocol")
	status := c.Query("status")
	search := c.Query("search")
	sortBy := c.DefaultQuery("sort_by", "id")
	sortOrder := c.DefaultQuery("sort_order", "desc")
	// 标准化和验证 search 参数
	search = service.TruncateUTF8Bytes(strings.TrimSpace(search), 100)

	adminCaller := isAdminCaller(c)
	ownerFilter, _ := strconv.ParseInt(c.Query("owner_user_id"), 10, 64)
	if !adminCaller {
		uid, ok := requireValidNonAdminSubject(c, h.stewards)
		if !ok {
			return
		}
		ownerFilter = uid
	}

	var proxies []service.ProxyWithAccountCount
	var total int64
	var err error
	if ownerFilter > 0 && h.stewards != nil {
		ids := h.stewards.ListProxyIDs(c.Request.Context(), ownerFilter)
		fetched, fetchErr := h.adminService.GetProxiesByIDs(c.Request.Context(), ids)
		if fetchErr != nil {
			response.ErrorFrom(c, fetchErr)
			return
		}
		searchLower := strings.ToLower(search)
		filtered := make([]service.Proxy, 0, len(fetched))
		for i := range fetched {
			p := fetched[i]
			if protocol != "" && !strings.EqualFold(p.Protocol, protocol) {
				continue
			}
			if status != "" && !strings.EqualFold(p.Status, status) {
				continue
			}
			if searchLower != "" &&
				!strings.Contains(strings.ToLower(p.Name), searchLower) &&
				!strings.Contains(strings.ToLower(p.Host), searchLower) {
				continue
			}
			filtered = append(filtered, p)
		}
		desc := strings.EqualFold(sortOrder, "desc")
		sort.SliceStable(filtered, func(i, j int) bool {
			var less bool
			switch sortBy {
			case "name":
				less = strings.ToLower(filtered[i].Name) < strings.ToLower(filtered[j].Name)
			case "protocol":
				less = filtered[i].Protocol < filtered[j].Protocol
			case "status":
				less = filtered[i].Status < filtered[j].Status
			case "created_at":
				less = filtered[i].CreatedAt.Before(filtered[j].CreatedAt)
			default:
				less = filtered[i].ID < filtered[j].ID
			}
			if desc {
				return !less
			}
			return less
		})
		total = int64(len(filtered))
		start := (page - 1) * pageSize
		if start < 0 {
			start = 0
		}
		if start >= len(filtered) {
			filtered = nil
		} else {
			end := start + pageSize
			if end > len(filtered) {
				end = len(filtered)
			}
			filtered = filtered[start:end]
		}
		proxies = make([]service.ProxyWithAccountCount, 0, len(filtered))
		for i := range filtered {
			p := filtered[i]
			var acctCount int64
			if accounts, aErr := h.adminService.GetProxyAccounts(c.Request.Context(), p.ID); aErr == nil {
				acctCount = int64(len(accounts))
			}
			item := service.ProxyWithAccountCount{
				Proxy:            p,
				AccountCount:     acctCount,
				IPAddress:        p.ExitIP,
				Country:          p.ExitCountry,
				CountryCode:      p.ExitCountryCode,
				Region:           p.ExitRegion,
				City:             p.ExitCity,
				Timezone:         p.ExitTimezone,
				UTCOffsetSeconds: p.ExitUTCOffsetSeconds,
				ASN:              p.ExitASN,
				ISP:              p.ExitISP,
			}
			if p.ExitCheckedAt != nil {
				ts := p.ExitCheckedAt.Unix()
				item.ExitCheckedAt = &ts
			}
			proxies = append(proxies, item)
		}
	} else {
		proxies, total, err = h.adminService.ListProxiesWithAccountCount(c.Request.Context(), page, pageSize, protocol, status, search, sortBy, sortOrder)
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}
	}

	out := make([]dto.AdminProxyWithAccountCount, 0, len(proxies))
	ids := make([]int64, 0, len(proxies))
	for i := range proxies {
		ids = append(ids, proxies[i].ID)
		item := *dto.ProxyWithAccountCountFromServiceAdmin(&proxies[i])
		if service.IsReservedEdgeInternalHost(proxies[i].Host) {
			item.IsEdgeLanding = true
		}
		if !adminCaller {
			item.Password = ""
		}
		out = append(out, item)
	}
	cc, rpm := h.proxyRuntimeUsage(c.Request.Context(), ids)
	for i := range out {
		out[i].Concurrency = cc[out[i].ID]
		out[i].CurrentRPM = rpm[out[i].ID]
	}
	if h.stewards != nil {
		labels := h.stewards.LabelsForProxies(c.Request.Context(), ids)
		for i := range out {
			if lab, ok := labels[out[i].ID]; ok {
				out[i].OwnerUserID = lab.UserID
				out[i].OwnerLabel = lab.Label
			}
		}
	}
	response.Paginated(c, out, total, page, pageSize)
}

// GetAll handles getting all active proxies without pagination
// GET /api/v1/admin/proxies/all
// Optional query param: with_count=true to include account count per proxy
func (h *ProxyHandler) GetAll(c *gin.Context) {
	if h.scopedAdminProxyRead(c) {
		return
	}
	withCount := c.Query("with_count") == "true"

	if !isAdminCaller(c) {
		ownerID, ok := requireValidNonAdminSubject(c, h.stewards)
		if !ok {
			return
		}
		ownedIDs := h.stewards.ListProxyIDs(c.Request.Context(), ownerID)
		rentalInfos := h.stewards.ListActiveRentalProxies(c.Request.Context(), ownerID)
		grantInfos := h.stewards.ListActiveLandingGrantProxies(c.Request.Context(), ownerID)
		rentalByProxyID := make(map[int64]service.RentalProxyInfo, len(rentalInfos))
		grantByProxyID := make(map[int64]service.LandingGrantProxyInfo, len(grantInfos))
		allIDs := make([]int64, 0, len(ownedIDs)+len(rentalInfos)+len(grantInfos))
		seenID := make(map[int64]struct{}, len(ownedIDs)+len(rentalInfos)+len(grantInfos))
		for _, id := range ownedIDs {
			if _, exists := seenID[id]; !exists {
				seenID[id] = struct{}{}
				allIDs = append(allIDs, id)
			}
		}
		for _, info := range rentalInfos {
			rentalByProxyID[info.ProxyID] = info
			if _, exists := seenID[info.ProxyID]; !exists {
				seenID[info.ProxyID] = struct{}{}
				allIDs = append(allIDs, info.ProxyID)
			}
		}
		for _, info := range grantInfos {
			grantByProxyID[info.ProxyID] = info
			if _, exists := seenID[info.ProxyID]; !exists {
				seenID[info.ProxyID] = struct{}{}
				allIDs = append(allIDs, info.ProxyID)
			}
		}
		if len(allIDs) == 0 {
			if withCount {
				response.Success(c, []dto.AdminProxyWithAccountCount{})
			} else {
				response.Success(c, []dto.AdminProxy{})
			}
			return
		}
		fetched, err := h.adminService.GetProxiesByIDs(c.Request.Context(), allIDs)
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}
		if withCount {
			out := make([]dto.AdminProxyWithAccountCount, 0, len(fetched))
			fetchIDs := make([]int64, 0, len(fetched))
			for i := range fetched {
				p := fetched[i]
				fetchIDs = append(fetchIDs, p.ID)
				pw := service.ProxyWithAccountCount{
					Proxy:            p,
					IPAddress:        p.ExitIP,
					Country:          p.ExitCountry,
					CountryCode:      p.ExitCountryCode,
					Region:           p.ExitRegion,
					City:             p.ExitCity,
					Timezone:         p.ExitTimezone,
					UTCOffsetSeconds: p.ExitUTCOffsetSeconds,
					ASN:              p.ExitASN,
					ISP:              p.ExitISP,
				}
				if p.ExitCheckedAt != nil {
					ts := p.ExitCheckedAt.Unix()
					pw.ExitCheckedAt = &ts
				}
				item := *dto.ProxyWithAccountCountFromServiceAdmin(&pw)
				item.Password = ""
				if rentalInfo, isRental := rentalByProxyID[p.ID]; isRental {
					item.Host = ""
					item.Port = 0
					item.Username = ""
					item.Password = ""
					item.IsRental = true
					orderID := rentalInfo.OrderID
					item.RentalOrderID = &orderID
					if rentalInfo.ExpiresAt != nil {
						item.ExpiresAt = rentalInfo.ExpiresAt
					}
				} else if grantInfo, isGrant := grantByProxyID[p.ID]; isGrant {
					item.Host = ""
					item.Port = 0
					item.Username = ""
					item.Password = ""
					item.IPAddress = ""
					item.IsEdgeLanding = true
					if grantInfo.ExpiresAt != nil {
						item.ExpiresAt = grantInfo.ExpiresAt
					}
				} else if service.IsReservedEdgeInternalHost(p.Host) {
					item.IsEdgeLanding = true
				}
				out = append(out, item)
			}
			cc, rpm := h.proxyRuntimeUsage(c.Request.Context(), fetchIDs)
			for i := range out {
				out[i].Concurrency = cc[out[i].ID]
				out[i].CurrentRPM = rpm[out[i].ID]
			}
			response.Success(c, out)
			return
		}
		out := make([]dto.AdminProxy, 0, len(fetched))
		fetchIDs := make([]int64, 0, len(fetched))
		for i := range fetched {
			p := fetched[i]
			fetchIDs = append(fetchIDs, p.ID)
			item := *dto.ProxyFromServiceAdmin(&p)
			item.Password = ""
			if rentalInfo, isRental := rentalByProxyID[p.ID]; isRental {
				item.Host = ""
				item.Port = 0
				item.Username = ""
				item.Password = ""
				item.IsRental = true
				orderID := rentalInfo.OrderID
				item.RentalOrderID = &orderID
				if rentalInfo.ExpiresAt != nil {
					item.ExpiresAt = rentalInfo.ExpiresAt
				}
			} else if grantInfo, isGrant := grantByProxyID[p.ID]; isGrant {
				item.Host = ""
				item.Port = 0
				item.Username = ""
				item.Password = ""
				item.IsEdgeLanding = true
				if grantInfo.ExpiresAt != nil {
					item.ExpiresAt = grantInfo.ExpiresAt
				}
			} else if service.IsReservedEdgeInternalHost(p.Host) {
				item.IsEdgeLanding = true
			}
			out = append(out, item)
		}
		cc, rpm := h.proxyRuntimeUsage(c.Request.Context(), fetchIDs)
		for i := range out {
			out[i].Concurrency = cc[out[i].ID]
			out[i].CurrentRPM = rpm[out[i].ID]
		}
		response.Success(c, out)
		return
	}

	if withCount {
		proxies, err := h.adminService.GetAllProxiesWithAccountCount(c.Request.Context())
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}
		out := make([]dto.AdminProxyWithAccountCount, 0, len(proxies))
		ids := make([]int64, 0, len(proxies))
		for i := range proxies {
			ids = append(ids, proxies[i].ID)
			out = append(out, *dto.ProxyWithAccountCountFromServiceAdmin(&proxies[i]))
		}
		cc, rpm := h.proxyRuntimeUsage(c.Request.Context(), ids)
		for i := range out {
			out[i].Concurrency = cc[out[i].ID]
			out[i].CurrentRPM = rpm[out[i].ID]
		}
		response.Success(c, out)
		return
	}

	proxies, err := h.adminService.GetAllProxies(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	out := make([]dto.AdminProxy, 0, len(proxies))
	ids := make([]int64, 0, len(proxies))
	for i := range proxies {
		ids = append(ids, proxies[i].ID)
		out = append(out, *dto.ProxyFromServiceAdmin(&proxies[i]))
	}
	cc, rpm := h.proxyRuntimeUsage(c.Request.Context(), ids)
	for i := range out {
		out[i].Concurrency = cc[out[i].ID]
		out[i].CurrentRPM = rpm[out[i].ID]
	}
	response.Success(c, out)
}

// GetByID handles getting a proxy by ID
// GET /api/v1/admin/proxies/:id
func (h *ProxyHandler) GetByID(c *gin.Context) {
	if h.scopedAdminProxyRead(c) {
		return
	}
	proxyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid proxy ID")
		return
	}
	if !h.allowProxy(c, proxyID) {
		return
	}

	proxy, err := h.adminService.GetProxy(c.Request.Context(), proxyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	resp := dto.ProxyFromServiceAdmin(proxy)
	if resp != nil {
		if service.IsReservedEdgeInternalHost(proxy.Host) {
			resp.IsEdgeLanding = true
		}
		if !isAdminCaller(c) {
			resp.Password = ""
		}
		cc, rpm := h.proxyRuntimeUsage(c.Request.Context(), []int64{proxyID})
		resp.Concurrency = cc[proxyID]
		resp.CurrentRPM = rpm[proxyID]
	}
	response.Success(c, resp)
}

// Create handles creating a new proxy
// POST /api/v1/admin/proxies
func (h *ProxyHandler) Create(c *gin.Context) {
	var req CreateProxyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	adminCaller := isAdminCaller(c)
	ownerID := getAdminIDFromContext(c)
	if !adminCaller {
		var ok bool
		ownerID, ok = requireValidNonAdminSubject(c, h.stewards)
		if !ok {
			return
		}
		if strings.EqualFold(strings.TrimSpace(req.FallbackMode), service.FallbackModeDirect) {
			response.ErrorFrom(c, service.ErrProxyDirectFallbackForbidden)
			return
		}
	}
	if !allowOwnedBackupProxy(c, h.stewards, req.BackupProxyID) {
		return
	}

	executeAdminIdempotentJSON(c, "admin.proxies.create", req, service.DefaultWriteIdempotencyTTL(), func(ctx context.Context) (any, error) {
		var expiresAt *time.Time
		if req.ExpiresAt != nil && *req.ExpiresAt > 0 {
			t := time.Unix(*req.ExpiresAt, 0).UTC()
			expiresAt = &t
		}
		proxy, err := h.adminService.CreateProxy(ctx, &service.CreateProxyInput{
			Name:           strings.TrimSpace(req.Name),
			Protocol:       strings.TrimSpace(req.Protocol),
			Host:           strings.TrimSpace(req.Host),
			Port:           req.Port,
			Username:       strings.TrimSpace(req.Username),
			Password:       strings.TrimSpace(req.Password),
			ExpiresAt:      expiresAt,
			FallbackMode:   strings.TrimSpace(req.FallbackMode),
			BackupProxyID:  req.BackupProxyID,
			ExpiryWarnDays: req.ExpiryWarnDays,
			MaxAccounts:    req.MaxAccounts,
			MaxRPM:         req.MaxRPM,
			MaxConcurrency: req.MaxConcurrency,
		})
		if err != nil {
			return nil, err
		}
		if h.stewards != nil {
			if claimErr := h.stewards.ClaimProxy(ctx, proxy.ID, ownerID); claimErr != nil && !adminCaller {
				return nil, claimErr
			}
		}
		resp := dto.ProxyFromServiceAdmin(proxy)
		if resp != nil && !adminCaller {
			resp.Password = ""
		}
		return resp, nil
	})
}

func (h *ProxyHandler) allowProxy(c *gin.Context, proxyID int64) bool {
	return requireStewardProxy(c, h.stewards, proxyID)
}

// Update handles updating a proxy
// PUT /api/v1/admin/proxies/:id
func (h *ProxyHandler) Update(c *gin.Context) {
	proxyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid proxy ID")
		return
	}
	if !h.allowProxy(c, proxyID) {
		return
	}

	var req UpdateProxyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	adminCaller := isAdminCaller(c)
	if !adminCaller && strings.EqualFold(strings.TrimSpace(req.FallbackMode), service.FallbackModeDirect) {
		response.ErrorFrom(c, service.ErrProxyDirectFallbackForbidden)
		return
	}
	if !allowOwnedBackupProxy(c, h.stewards, req.BackupProxyID.Value) {
		return
	}

	var expiresAt *time.Time
	if req.ExpiresAt.Value != nil && *req.ExpiresAt.Value > 0 {
		t := time.Unix(*req.ExpiresAt.Value, 0).UTC()
		expiresAt = &t
	}
	if req.Username != nil {
		*req.Username = strings.TrimSpace(*req.Username)
	}
	if req.Password != nil {
		*req.Password = strings.TrimSpace(*req.Password)
	}
	proxy, err := h.adminService.UpdateProxy(c.Request.Context(), proxyID, &service.UpdateProxyInput{
		Name:           strings.TrimSpace(req.Name),
		Protocol:       strings.TrimSpace(req.Protocol),
		Host:           strings.TrimSpace(req.Host),
		Port:           req.Port,
		Username:       req.Username,
		Password:       req.Password,
		Status:         strings.TrimSpace(req.Status),
		ExpiresAt:      expiresAt,
		ClearExpiresAt: req.ExpiresAt.Set && expiresAt == nil,
		FallbackMode:   strings.TrimSpace(req.FallbackMode),
		BackupProxyID:  req.BackupProxyID.Value,
		ClearBackupID:  req.BackupProxyID.Set && req.BackupProxyID.Value == nil,
		ExpiryWarnDays: req.ExpiryWarnDays,
		MaxAccounts:    req.MaxAccounts,
		MaxRPM:         req.MaxRPM,
		MaxConcurrency: req.MaxConcurrency,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	resp := dto.ProxyFromServiceAdmin(proxy)
	if resp != nil && !adminCaller {
		resp.Password = ""
	}
	response.Success(c, resp)
}

// Delete handles deleting a proxy
// DELETE /api/v1/admin/proxies/:id
func (h *ProxyHandler) Delete(c *gin.Context) {
	proxyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid proxy ID")
		return
	}
	if !h.allowProxy(c, proxyID) {
		return
	}

	err = h.adminService.DeleteProxy(c.Request.Context(), proxyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, gin.H{"message": "Proxy deleted successfully"})
}

// BatchDelete handles batch deleting proxies
// POST /api/v1/admin/proxies/batch-delete
func (h *ProxyHandler) BatchDelete(c *gin.Context) {
	type BatchDeleteRequest struct {
		IDs []int64 `json:"ids" binding:"required,min=1"`
	}

	var req BatchDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	if !requireStewardProxies(c, h.stewards, req.IDs) {
		return
	}

	result, err := h.adminService.BatchDeleteProxies(c.Request.Context(), req.IDs)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, result)
}

// Test handles testing proxy connectivity
// POST /api/v1/admin/proxies/:id/test
func (h *ProxyHandler) Test(c *gin.Context) {
	proxyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid proxy ID")
		return
	}
	if !h.allowProxy(c, proxyID) {
		return
	}

	result, err := h.adminService.TestProxy(c.Request.Context(), proxyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, result)
}

// CheckQuality handles checking proxy quality across common AI targets.
// POST /api/v1/admin/proxies/:id/quality-check
func (h *ProxyHandler) CheckQuality(c *gin.Context) {
	proxyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid proxy ID")
		return
	}
	if !h.allowProxy(c, proxyID) {
		return
	}

	result, err := h.adminService.CheckProxyQuality(c.Request.Context(), proxyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, result)
}

// GetStats handles getting proxy statistics
// GET /api/v1/admin/proxies/:id/stats
func (h *ProxyHandler) GetStats(c *gin.Context) {
	proxyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid proxy ID")
		return
	}
	if !h.allowProxy(c, proxyID) {
		return
	}

	// Return mock data for now
	_ = proxyID
	response.Success(c, gin.H{
		"total_accounts":  0,
		"active_accounts": 0,
		"total_requests":  0,
		"success_rate":    100.0,
		"average_latency": 0,
	})
}

// GetProxyAccounts handles getting accounts using a proxy
// GET /api/v1/admin/proxies/:id/accounts
func (h *ProxyHandler) GetProxyAccounts(c *gin.Context) {
	proxyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid proxy ID")
		return
	}
	if !h.allowProxy(c, proxyID) {
		return
	}

	accounts, err := h.adminService.GetProxyAccounts(c.Request.Context(), proxyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	adminCaller := isAdminCaller(c)
	var ownerID int64
	if !adminCaller {
		var ok bool
		ownerID, ok = requireValidNonAdminSubject(c, h.stewards)
		if !ok {
			return
		}
	}

	out := make([]dto.ProxyAccountSummary, 0, len(accounts))
	for i := range accounts {
		if !adminCaller && !h.stewards.OwnsAccount(c.Request.Context(), accounts[i].ID, ownerID) {
			continue
		}
		out = append(out, *dto.ProxyAccountSummaryFromService(&accounts[i]))
	}
	response.Success(c, out)
}

// BatchCreateProxyItem represents a single proxy in batch create request
type BatchCreateProxyItem struct {
	Protocol string `json:"protocol" binding:"required,oneof=http https socks5 socks5h"`
	Host     string `json:"host" binding:"required"`
	Port     int    `json:"port" binding:"required,min=1,max=65535"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// BatchCreateRequest represents batch create proxies request
type BatchCreateRequest struct {
	Proxies []BatchCreateProxyItem `json:"proxies" binding:"required,min=1"`
}

// BatchCreate handles batch creating proxies
// POST /api/v1/admin/proxies/batch
func (h *ProxyHandler) BatchCreate(c *gin.Context) {
	var req BatchCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	adminCaller := isAdminCaller(c)
	ownerID := getAdminIDFromContext(c)
	var ownedDupKeys map[string]struct{}
	if !adminCaller {
		var ok bool
		ownerID, ok = requireValidNonAdminSubject(c, h.stewards)
		if !ok {
			return
		}
		ownedIDs := h.stewards.ListProxyIDs(c.Request.Context(), ownerID)
		ownedProxies, err := h.adminService.GetProxiesByIDs(c.Request.Context(), ownedIDs)
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}
		ownedDupKeys = make(map[string]struct{}, len(ownedProxies))
		for _, p := range ownedProxies {
			ownedDupKeys[buildProxyKey(p.Protocol, p.Host, p.Port, p.Username, p.Password)] = struct{}{}
		}
	}

	created := 0
	skipped := 0

	for _, item := range req.Proxies {
		// Trim all string fields
		host := strings.TrimSpace(item.Host)
		protocol := strings.TrimSpace(item.Protocol)
		username := strings.TrimSpace(item.Username)
		password := strings.TrimSpace(item.Password)

		// Non-admin duplicate check is strictly scoped to caller's owned proxies
		// (prevents cross-tenant credential existence oracle).
		if !adminCaller {
			key := buildProxyKey(protocol, host, item.Port, username, password)
			if _, exists := ownedDupKeys[key]; exists {
				skipped++
				continue
			}
			ownedDupKeys[key] = struct{}{}
		} else {
			exists, err := h.adminService.CheckProxyExists(c.Request.Context(), host, item.Port, username, password)
			if err != nil {
				response.ErrorFrom(c, err)
				return
			}
			if exists {
				skipped++
				continue
			}
		}

		// Create proxy with default name
		createdProxy, err := h.adminService.CreateProxy(c.Request.Context(), &service.CreateProxyInput{
			Name:     "default",
			Protocol: protocol,
			Host:     host,
			Port:     item.Port,
			Username: username,
			Password: password,
		})
		if err != nil {
			// If creation fails due to duplicate, count as skipped
			skipped++
			continue
		}

		if h.stewards != nil {
			if claimErr := h.stewards.ClaimProxy(c.Request.Context(), createdProxy.ID, ownerID); claimErr != nil && !adminCaller {
				response.ErrorFrom(c, claimErr)
				return
			}
		}

		created++
	}

	response.Success(c, gin.H{
		"created": created,
		"skipped": skipped,
	})
}
