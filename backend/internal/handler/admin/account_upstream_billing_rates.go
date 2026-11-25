package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/jk-zhang-meta/berth/internal/pkg/response"
	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/gin-gonic/gin"
)

// upstreamBillingRatesResponse is deliberately smaller than the regular
// account-list response. The frontend uses the returned ID order to detect a
// page boundary/order change and only applies snapshots when the page is
// otherwise stable.
type upstreamBillingRatesResponse struct {
	Items    []service.UpstreamBillingRateSnapshotItem `json:"items"`
	Total    int64                                     `json:"total"`
	Page     int                                       `json:"page"`
	PageSize int                                       `json:"page_size"`
}

// GetUpstreamBillingRates returns persisted upstream billing snapshots for the
// current account-list page. It never probes an upstream and never loads
// today-stats, usage, concurrency, or credentials for the response.
//
// GET /api/v1/admin/accounts/upstream-billing-rates
func (h *AccountHandler) GetUpstreamBillingRates(c *gin.Context) {
	if h.adminService == nil {
		response.Error(c, http.StatusServiceUnavailable, "account service unavailable")
		return
	}

	page, pageSize := response.ParsePagination(c)
	platform := c.Query("platform")
	accountType := c.Query("type")
	status := c.Query("status")
	search := strings.TrimSpace(c.Query("search"))
	if len(search) > 100 {
		search = search[:100]
	}
	privacyMode := strings.TrimSpace(c.Query("privacy_mode"))
	sortBy := c.DefaultQuery("sort_by", "name")
	sortOrder := c.DefaultQuery("sort_order", "asc")

	var groupID int64
	if groupQuery := c.Query("group"); groupQuery != "" {
		if groupQuery == accountListGroupUngroupedQueryValue {
			groupID = service.AccountListGroupUngrouped
		} else {
			parsed, err := strconv.ParseInt(groupQuery, 10, 64)
			if err != nil || parsed < 0 {
				response.BadRequest(c, "invalid group filter")
				return
			}
			groupID = parsed
		}
	}

	var accounts []service.Account
	var total int64
	var err error
	if !isAdminCaller(c) {
		ownerID, ok := requireValidNonAdminSubject(c, h.stewards)
		if !ok {
			return
		}
		ids := h.stewards.ListAccountIDs(c.Request.Context(), ownerID)
		fetched, fetchErr := h.adminService.GetAccountsByIDs(c.Request.Context(), ids)
		if fetchErr != nil {
			response.ErrorFrom(c, fetchErr)
			return
		}
		searchLower := strings.ToLower(search)
		owned := make([]service.Account, 0, len(fetched))
		for _, acc := range fetched {
			if acc == nil {
				continue
			}
			if platform != "" && acc.Platform != platform {
				continue
			}
			if accountType != "" && acc.Type != accountType {
				continue
			}
			if status != "" && acc.Status != status {
				continue
			}
			if searchLower != "" && !strings.Contains(strings.ToLower(acc.Name), searchLower) {
				continue
			}
			owned = append(owned, *acc)
		}
		desc := strings.ToLower(sortOrder) == "desc"
		sort.SliceStable(owned, func(i, j int) bool {
			var less bool
			switch sortBy {
			case "name":
				less = strings.ToLower(owned[i].Name) < strings.ToLower(owned[j].Name)
			case "priority":
				less = owned[i].Priority < owned[j].Priority
			case "status":
				less = owned[i].Status < owned[j].Status
			case "created_at":
				less = owned[i].CreatedAt.Before(owned[j].CreatedAt)
			default:
				less = owned[i].ID < owned[j].ID
			}
			if desc {
				return !less
			}
			return less
		})
		total = int64(len(owned))
		start := (page - 1) * pageSize
		if start < 0 {
			start = 0
		}
		if start >= len(owned) {
			accounts = []service.Account{}
		} else {
			end := start + pageSize
			if end > len(owned) {
				end = len(owned)
			}
			accounts = owned[start:end]
		}
	} else {
		accounts, total, err = h.adminService.ListAccounts(
			c.Request.Context(), page, pageSize, platform, accountType, status,
			search, groupID, privacyMode, sortBy, sortOrder,
		)
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}
	}

	payload := upstreamBillingRatesResponse{
		Items:    service.BuildUpstreamBillingRateSnapshotItems(accounts),
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}
	c.Header("Cache-Control", "private, no-cache")
	etag := buildUpstreamBillingRatesETag(payload)
	if etag != "" {
		c.Header("ETag", etag)
		if ifNoneMatchMatched(c.GetHeader("If-None-Match"), etag) {
			c.Status(http.StatusNotModified)
			return
		}
	}

	response.Success(c, payload)
}

func buildUpstreamBillingRatesETag(payload upstreamBillingRatesResponse) string {
	raw, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "\"" + hex.EncodeToString(sum[:]) + "\""
}
