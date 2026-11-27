package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	infraerrors "github.com/jk-zhang-meta/berth/internal/pkg/errors"
	"github.com/shopspring/decimal"
)

var (
	ErrMarketplaceInvalid             = infraerrors.New(http.StatusBadRequest, "MARKETPLACE_INVALID", "Invalid marketplace request")
	ErrMarketplaceForbidden           = infraerrors.New(http.StatusForbidden, "MARKETPLACE_FORBIDDEN", "This marketplace operation is not allowed")
	ErrMarketplaceNotFound            = infraerrors.New(http.StatusNotFound, "MARKETPLACE_NOT_FOUND", "Marketplace resource not found")
	ErrMarketplaceConflict            = infraerrors.New(http.StatusConflict, "MARKETPLACE_CONFLICT", "The marketplace request conflicts with current availability")
	ErrMarketplaceUnavailable         = fmt.Errorf("%w: resource unavailable", ErrMarketplaceConflict)
	ErrMarketplaceCapacity            = fmt.Errorf("%w: all simultaneous rental slots are occupied", ErrMarketplaceConflict)
	ErrMarketplaceBalance             = infraerrors.New(http.StatusPaymentRequired, "MARKETPLACE_BALANCE", "Insufficient available balance")
	ErrMarketplaceInsufficientBalance = ErrMarketplaceBalance
	ErrMarketplaceIdempotency         = fmt.Errorf("%w: checkout key belongs to another listing", ErrMarketplaceConflict)
)

// MarketplacePaymentReconciler is wired optionally so the marketplace background
// ticker can recover paid intents that crashed before Phase 2 completion.
type MarketplacePaymentReconciler interface {
	ReconcilePaidMarketplaceIntents(ctx context.Context) (int, error)
}

type MarketplaceService struct {
	db                *sql.DB
	OnBalanceChanged  func(context.Context, int64)
	paymentReconciler MarketplacePaymentReconciler
}

func NewMarketplaceService(db *sql.DB) *MarketplaceService { return &MarketplaceService{db: db} }

func (s *MarketplaceService) SetPaymentReconciler(reconciler MarketplacePaymentReconciler) {
	if s == nil {
		return
	}
	s.paymentReconciler = reconciler
}

func (s *MarketplaceService) ReconcilePaidIntents(ctx context.Context) (int, error) {
	if s == nil || s.paymentReconciler == nil {
		return 0, nil
	}
	return s.paymentReconciler.ReconcilePaidMarketplaceIntents(ctx)
}

type MarketplacePublishInput struct {
	UsageRateMultiplier *float64 `json:"usage_rate_multiplier"`
	ResourceType        string   `json:"resource_type"`
	ResourceID          int64    `json:"resource_id"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	RentalMode          string   `json:"rental_mode,omitempty"`
	DurationHours       int      `json:"duration_hours,omitempty"`
	QuotaLimitUSD       *float64 `json:"quota_limit_usd,omitempty"`
	PriceCents          int64    `json:"price_cents"`
	Capacity            int      `json:"capacity"`
	Visibility          string   `json:"visibility,omitempty"`
	TargetBuyerID       *int64   `json:"target_buyer_id,omitempty"`
	TargetBuyer         string   `json:"target_buyer,omitempty"`
}

type MarketplaceListing struct {
	UsageRateMultiplier float64    `json:"usage_rate_multiplier"`
	ID                  int64      `json:"id"`
	ResourceType        string     `json:"resource_type"`
	ResourceID          int64      `json:"resource_id"`
	SellerID            int64      `json:"seller_id"`
	Title               string     `json:"title"`
	Description         string     `json:"description"`
	RentalMode          string     `json:"rental_mode"`
	DurationHours       *int       `json:"duration_hours,omitempty"`
	QuotaLimitUSD       *float64   `json:"quota_limit_usd,omitempty"`
	PriceCents          int64      `json:"price_cents"`
	Capacity            int        `json:"capacity"`
	Visibility          string     `json:"visibility"`
	TargetBuyerID       *int64     `json:"target_buyer_id,omitempty"`
	TargetBuyerLabel    string     `json:"target_buyer_label,omitempty"`
	DeclinedAt          *time.Time `json:"declined_at,omitempty"`
	Status              string     `json:"status"`
	AdminSuspended      bool       `json:"admin_suspended"`
	ActiveRentals       int        `json:"active_rentals"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type MarketplaceOrder struct {
	ID                      int64      `json:"id"`
	ListingID               int64      `json:"listing_id"`
	BuyerID                 int64      `json:"buyer_id"`
	SellerID                int64      `json:"seller_id"`
	Title                   string     `json:"title"`
	ResourceType            string     `json:"resource_type"`
	ResourceID              int64      `json:"resource_id"`
	RentalMode              string     `json:"rental_mode"`
	DurationHours           *int       `json:"duration_hours,omitempty"`
	QuotaLimitUSD           *float64   `json:"quota_limit_usd,omitempty"`
	QuotaUsedUSD            float64    `json:"quota_used_usd"`
	QuotaReservedUSD        float64    `json:"quota_reserved_usd"`
	PriceCents              int64      `json:"price_cents"`
	GroupID                 *int64     `json:"group_id"`
	RentalProxyID           *int64     `json:"rental_proxy_id"`
	StartsAt                time.Time  `json:"starts_at"`
	ExpiresAt               *time.Time `json:"ends_at,omitempty"`
	TerminatingAt           *time.Time `json:"terminating_at,omitempty"`
	Status                  string     `json:"status"`
	CompletionReason        *string    `json:"completion_reason,omitempty"`
	SellerEarnedCents       int64      `json:"seller_earned_cents"`
	RefundCents             int64      `json:"refund_cents"`
	RentCommissionBPS       int        `json:"rent_commission_bps"`
	PlatformCommissionCents int64      `json:"platform_commission_cents"`
	SettledAt               *time.Time `json:"settled_at"`
	CreatedAt               time.Time  `json:"created_at"`
}

type MarketplaceResourceOption struct {
	ResourceType string `json:"resource_type"`
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Platform     string `json:"platform"`
}

type marketplaceScanner interface{ Scan(...any) error }

const marketplaceListingColumns = `l.id,l.resource_type,l.resource_id,l.seller_id,l.title,l.description,l.rental_mode,l.duration_hours,l.quota_limit_usd,l.price_cents,l.capacity,l.visibility,l.target_buyer_id,l.declined_at,l.status,l.admin_suspended,l.created_at,l.updated_at,l.usage_rate_multiplier,
 COALESCE((SELECT u.email FROM users u WHERE u.id=l.target_buyer_id),''),
 COALESCE((SELECT u.username FROM users u WHERE u.id=l.target_buyer_id),''),
 (SELECT count(*) FROM berth_marketplace_orders o WHERE o.listing_id=l.id AND o.status='active' AND (o.expires_at IS NULL OR o.expires_at>clock_timestamp()) AND (o.quota_limit_usd IS NULL OR o.quota_used_usd<o.quota_limit_usd))`

const marketplaceOrderColumns = `id,listing_id,buyer_id,seller_id,title,resource_type,resource_id,rental_mode,duration_hours,quota_limit_usd,quota_used_usd,quota_reserved_usd,price_cents,group_id,rental_proxy_id,starts_at,expires_at,status,completion_reason,seller_earned_cents,refund_cents,settled_at,created_at,rent_commission_bps,platform_commission_cents`

func scanMarketplaceListing(row marketplaceScanner) (*MarketplaceListing, error) {
	var (
		v            MarketplaceListing
		dur          sql.NullInt64
		quota        sql.NullFloat64
		targetID     sql.NullInt64
		declinedAt   sql.NullTime
		targetEmail  string
		targetUser   string
	)
	err := row.Scan(
		&v.ID, &v.ResourceType, &v.ResourceID, &v.SellerID, &v.Title, &v.Description,
		&v.RentalMode, &dur, &quota, &v.PriceCents, &v.Capacity, &v.Visibility,
		&targetID, &declinedAt, &v.Status, &v.AdminSuspended, &v.CreatedAt, &v.UpdatedAt,
		&v.UsageRateMultiplier, &targetEmail, &targetUser, &v.ActiveRentals,
	)
	if err != nil {
		return nil, marketplaceNotFound(err)
	}
	if dur.Valid {
		d := int(dur.Int64)
		v.DurationHours = &d
	}
	if quota.Valid {
		q := quota.Float64
		v.QuotaLimitUSD = &q
	}
	if targetID.Valid {
		tid := targetID.Int64
		v.TargetBuyerID = &tid
		v.TargetBuyerLabel = maskBuyerLabel(targetEmail, targetUser)
	}
	if declinedAt.Valid {
		t := declinedAt.Time
		v.DeclinedAt = &t
	}
	return &v, nil
}

func scanMarketplaceOrder(row marketplaceScanner) (*MarketplaceOrder, error) {
	var (
		v                MarketplaceOrder
		dur              sql.NullInt64
		quotaLimit       sql.NullFloat64
		expiresAt        sql.NullTime
		completionReason sql.NullString
	)
	err := row.Scan(
		&v.ID, &v.ListingID, &v.BuyerID, &v.SellerID, &v.Title, &v.ResourceType, &v.ResourceID,
		&v.RentalMode, &dur, &quotaLimit, &v.QuotaUsedUSD, &v.QuotaReservedUSD,
		&v.PriceCents, &v.GroupID, &v.RentalProxyID, &v.StartsAt, &expiresAt,
		&v.Status, &completionReason, &v.SellerEarnedCents, &v.RefundCents, &v.SettledAt,
		&v.CreatedAt, &v.RentCommissionBPS, &v.PlatformCommissionCents,
	)
	if err != nil {
		return nil, marketplaceNotFound(err)
	}
	if dur.Valid {
		d := int(dur.Int64)
		v.DurationHours = &d
	}
	if quotaLimit.Valid {
		q := quotaLimit.Float64
		v.QuotaLimitUSD = &q
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		v.ExpiresAt = &t
	}
	if completionReason.Valid {
		r := completionReason.String
		v.CompletionReason = &r
	}
	return &v, nil
}

func marketplaceNotFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMarketplaceNotFound
	}
	return err
}

func validateMarketplacePublish(v *MarketplacePublishInput) error {
	if v.UsageRateMultiplier == nil {
		rate := 1.0
		v.UsageRateMultiplier = &rate
	}
	if math.IsNaN(*v.UsageRateMultiplier) || math.IsInf(*v.UsageRateMultiplier, 0) || *v.UsageRateMultiplier <= 0 || *v.UsageRateMultiplier > 1000 {
		return ErrMarketplaceInvalid
	}
	// Upstream groups store NUMERIC(10,4); advertise exactly the billed rate.
	rate := math.Round(*v.UsageRateMultiplier*10000) / 10000
	if rate == 0 {
		return ErrMarketplaceInvalid
	}
	v.UsageRateMultiplier = &rate
	v.ResourceType = strings.TrimSpace(v.ResourceType)
	v.Title = strings.TrimSpace(v.Title)
	v.Description = strings.TrimSpace(v.Description)
	v.RentalMode = strings.TrimSpace(v.RentalMode)
	if v.RentalMode == "" {
		v.RentalMode = MarketplaceRentalModeDuration
	}
	v.Visibility = strings.TrimSpace(v.Visibility)
	if v.Visibility == "" {
		v.Visibility = MarketplaceVisibilityPublic
	}
	v.TargetBuyer = strings.TrimSpace(v.TargetBuyer)

	if (v.ResourceType != "account" && v.ResourceType != "proxy") || v.ResourceID <= 0 || v.Title == "" || !utf8.ValidString(v.Title) || !utf8.ValidString(v.Description) || utf8.RuneCountInString(v.Title) > 100 || utf8.RuneCountInString(v.Description) > 2000 || strings.ContainsRune(v.Title, 0) || strings.ContainsRune(v.Description, 0) || v.PriceCents < 1 || v.PriceCents > 100000000 || v.Capacity < 1 || v.Capacity > 1000 {
		return ErrMarketplaceInvalid
	}

	if v.ResourceType == "proxy" && v.RentalMode != MarketplaceRentalModeDuration {
		return ErrMarketplaceInvalid
	}

	switch v.RentalMode {
	case MarketplaceRentalModeDuration:
		if v.DurationHours < 1 || v.DurationHours > 8760 || v.QuotaLimitUSD != nil {
			return ErrMarketplaceInvalid
		}
	case MarketplaceRentalModeQuota:
		if v.DurationHours != 0 || v.QuotaLimitUSD == nil {
			return ErrMarketplaceInvalid
		}
		if err := validateMarketplaceQuotaLimit(v.QuotaLimitUSD); err != nil {
			return err
		}
	case MarketplaceRentalModeHybrid:
		if v.DurationHours < 1 || v.DurationHours > 8760 || v.QuotaLimitUSD == nil {
			return ErrMarketplaceInvalid
		}
		if err := validateMarketplaceQuotaLimit(v.QuotaLimitUSD); err != nil {
			return err
		}
	default:
		return ErrMarketplaceInvalid
	}

	switch v.Visibility {
	case MarketplaceVisibilityPublic:
		if v.TargetBuyerID != nil || v.TargetBuyer != "" {
			return ErrMarketplaceInvalid
		}
	case MarketplaceVisibilityTargeted:
		if (v.TargetBuyerID == nil || *v.TargetBuyerID <= 0) && v.TargetBuyer == "" {
			return ErrMarketplaceTargetBuyerInvalid
		}
		if v.TargetBuyer != "" && (!utf8.ValidString(v.TargetBuyer) || strings.ContainsRune(v.TargetBuyer, 0) || utf8.RuneCountInString(v.TargetBuyer) > 255) {
			return ErrMarketplaceTargetBuyerInvalid
		}
	default:
		return ErrMarketplaceInvalid
	}

	return nil
}

func validateMarketplaceQuotaLimit(limit *float64) error {
	if limit == nil || math.IsNaN(*limit) || math.IsInf(*limit, 0) || *limit < 0.01 || *limit > 1000000 {
		return ErrMarketplaceInvalid
	}
	quantized := QuantizeUsageBillingAmount(*limit)
	if quantized < 0.01 || quantized > 1000000 {
		return ErrMarketplaceInvalid
	}
	*limit = quantized
	return nil
}

func (s *MarketplaceService) Publish(ctx context.Context, userID int64, isAdmin bool, input MarketplacePublishInput) (*MarketplaceListing, error) {
	if userID <= 0 {
		return nil, ErrMarketplaceForbidden
	}
	if err := validateMarketplacePublish(&input); err != nil {
		return nil, err
	}
	var result *MarketplaceListing
	err := withMarketplaceTxRetry(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		owner, err := marketplaceLockResource(ctx, tx, input.ResourceType, input.ResourceID)
		if err != nil {
			return err
		}
		if owner == 0 && isAdmin {
			table, column := "account_stewards", "account_id"
			if input.ResourceType == "proxy" {
				table, column = "proxy_stewards", "proxy_id"
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO "+table+" ("+column+",user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING", input.ResourceID, userID); err != nil {
				return err
			}
			owner, err = marketplaceLockResource(ctx, tx, input.ResourceType, input.ResourceID)
			if err != nil {
				return err
			}
		}
		if owner <= 0 || (!isAdmin && owner != userID) {
			return ErrMarketplaceForbidden
		}
		var sellerActive bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL)", owner).Scan(&sellerActive); err != nil {
			return err
		}
		if !sellerActive {
			return ErrMarketplaceUnavailable
		}

		// Do not allow bypassing admin moderation suspension via targeted/new listing.
		var suspended bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM berth_marketplace_listings WHERE resource_type=$1 AND resource_id=$2 AND admin_suspended=true)`, input.ResourceType, input.ResourceID).Scan(&suspended); err != nil {
			return err
		}
		if suspended {
			return ErrMarketplaceForbidden
		}

		var targetBuyerID *int64
		if input.Visibility == MarketplaceVisibilityTargeted {
			var resolved int64
			if input.TargetBuyerID != nil && *input.TargetBuyerID > 0 {
				err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL`, *input.TargetBuyerID).Scan(&resolved)
			} else {
				err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE deleted_at IS NULL AND status='active' AND (lower(email)=lower($1) OR lower(username)=lower($1) OR id::text=$1) LIMIT 1`, input.TargetBuyer).Scan(&resolved)
			}
			if errors.Is(err, sql.ErrNoRows) || (err == nil && (resolved <= 0 || resolved == owner)) {
				return ErrMarketplaceTargetBuyerInvalid
			}
			if err != nil {
				return err
			}
			targetBuyerID = &resolved
		}

		if input.ResourceType == "account" {
			groupID, groupErr := s.ensureAccountGroupTx(ctx, tx, input.ResourceID, owner)
			if groupErr != nil {
				return groupErr
			}
			// Preserve pricing for active orders: each order snapshots usage_rate_multiplier
			// at checkout (R-4), and only update shared groups.rate_multiplier when no active
			// rental order is currently bound to this group.
			if _, err = tx.ExecContext(ctx, `UPDATE groups SET rate_multiplier=$1,updated_at=clock_timestamp()
 WHERE id=$2 AND NOT EXISTS(SELECT 1 FROM berth_marketplace_orders o WHERE o.group_id=$2 AND o.status='active')`, *input.UsageRateMultiplier, groupID); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO scheduler_outbox(event_type,group_id) VALUES('group_changed',$1)", groupID); err != nil {
				return err
			}
		}

		var durationArg any
		if input.DurationHours > 0 {
			durationArg = input.DurationHours
		}
		var quotaArg any
		if input.QuotaLimitUSD != nil {
			quotaArg = *input.QuotaLimitUSD
		}

		var id int64
		if input.Visibility == MarketplaceVisibilityTargeted {
			err = tx.QueryRowContext(ctx, `INSERT INTO berth_marketplace_listings(resource_type,resource_id,seller_id,title,description,rental_mode,duration_hours,quota_limit_usd,price_cents,capacity,usage_rate_multiplier,visibility,target_buyer_id)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'targeted',$12)
 ON CONFLICT(resource_type,resource_id,target_buyer_id) WHERE visibility='targeted' AND status='active'
 DO UPDATE SET title=EXCLUDED.title,description=EXCLUDED.description,rental_mode=EXCLUDED.rental_mode,
 duration_hours=EXCLUDED.duration_hours,quota_limit_usd=EXCLUDED.quota_limit_usd,price_cents=EXCLUDED.price_cents,
 capacity=EXCLUDED.capacity,usage_rate_multiplier=EXCLUDED.usage_rate_multiplier,status='active',declined_at=NULL,updated_at=clock_timestamp()
 WHERE berth_marketplace_listings.seller_id=EXCLUDED.seller_id AND NOT berth_marketplace_listings.admin_suspended RETURNING id`,
				input.ResourceType, input.ResourceID, owner, input.Title, input.Description, input.RentalMode,
				durationArg, quotaArg, input.PriceCents, input.Capacity, *input.UsageRateMultiplier, *targetBuyerID).Scan(&id)
		} else {
			err = tx.QueryRowContext(ctx, `INSERT INTO berth_marketplace_listings(resource_type,resource_id,seller_id,title,description,rental_mode,duration_hours,quota_limit_usd,price_cents,capacity,usage_rate_multiplier,visibility,target_buyer_id)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'public',NULL)
 ON CONFLICT(resource_type,resource_id) WHERE visibility='public' AND status<>'removed'
 DO UPDATE SET title=EXCLUDED.title,description=EXCLUDED.description,rental_mode=EXCLUDED.rental_mode,
 duration_hours=EXCLUDED.duration_hours,quota_limit_usd=EXCLUDED.quota_limit_usd,price_cents=EXCLUDED.price_cents,
 capacity=EXCLUDED.capacity,usage_rate_multiplier=EXCLUDED.usage_rate_multiplier,status='active',updated_at=clock_timestamp()
 WHERE berth_marketplace_listings.seller_id=EXCLUDED.seller_id AND NOT berth_marketplace_listings.admin_suspended RETURNING id`,
				input.ResourceType, input.ResourceID, owner, input.Title, input.Description, input.RentalMode,
				durationArg, quotaArg, input.PriceCents, input.Capacity, *input.UsageRateMultiplier).Scan(&id)
		}
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMarketplaceForbidden
		}
		if err != nil {
			return err
		}
		v, err := scanMarketplaceListing(tx.QueryRowContext(ctx, "SELECT "+marketplaceListingColumns+" FROM berth_marketplace_listings l WHERE l.id=$1", id))
		if err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		sanitizeListingForCaller(v, userID, isAdmin)
		result = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Both publication and checkout lock the resource before its listing.
func marketplaceLockResource(ctx context.Context, tx *sql.Tx, kind string, id int64) (int64, error) {
	var query string
	switch kind {
	case "account":
		query = `SELECT COALESCE((SELECT user_id FROM account_stewards WHERE account_id=a.id),0) FROM accounts a
 WHERE a.id=$1 AND a.deleted_at IS NULL AND a.status='active' AND a.schedulable=true AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()) FOR UPDATE OF a`
	case "proxy":
		query = `SELECT COALESCE((SELECT user_id FROM proxy_stewards WHERE proxy_id=p.id),0) FROM proxies p
 WHERE p.id=$1 AND p.deleted_at IS NULL AND p.status='active' AND (p.expires_at IS NULL OR p.expires_at>clock_timestamp())
 AND NULLIF(p.exit_ip,'') IS NOT NULL AND NULLIF(p.exit_timezone,'') IS NOT NULL AND p.exit_checked_at IS NOT NULL
 AND COALESCE(p.source_type,'')<>'edge_landing_grant' AND LOWER(p.host) NOT LIKE '%.edge.internal'
 AND NOT EXISTS(SELECT 1 FROM berth_marketplace_orders o WHERE o.rental_proxy_id=p.id) FOR UPDATE OF p`
	default:
		return 0, ErrMarketplaceInvalid
	}
	var owner int64
	err := tx.QueryRowContext(ctx, query, id).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrMarketplaceUnavailable
	}
	return owner, err
}

func (s *MarketplaceService) List(ctx context.Context, userID int64, isAdmin bool, scope string) ([]MarketplaceListing, error) {
	if userID <= 0 {
		return nil, ErrMarketplaceForbidden
	}
	var where string
	args := []any{}
	switch scope {
	case "", "market":
		where = "l.status='active' AND (l.visibility='public' OR l.target_buyer_id=$1)"
		args = append(args, userID)
	case "offers":
		where = "l.status='active' AND l.visibility='targeted' AND l.target_buyer_id=$1"
		args = append(args, userID)
	case "mine":
		where = "l.seller_id=$1"
		args = append(args, userID)
	case "all":
		if !isAdmin {
			return nil, ErrMarketplaceForbidden
		}
		where = "TRUE"
	default:
		return nil, ErrMarketplaceInvalid
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+marketplaceListingColumns+" FROM berth_marketplace_listings l WHERE "+where+" ORDER BY l.id DESC LIMIT 200", args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []MarketplaceListing{}
	for rows.Next() {
		v, err := scanMarketplaceListing(rows)
		if err != nil {
			return nil, err
		}
		sanitizeListingForCaller(v, userID, isAdmin)
		out = append(out, *v)
	}
	return out, rows.Err()
}

func (s *MarketplaceService) Orders(ctx context.Context, userID int64, isAdmin bool) ([]MarketplaceOrder, error) {
	if userID <= 0 {
		return nil, ErrMarketplaceForbidden
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+marketplaceOrderColumns+" FROM berth_marketplace_orders WHERE ($2 OR buyer_id=$1 OR seller_id=$1) ORDER BY id DESC LIMIT 200", userID, isAdmin)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []MarketplaceOrder{}
	for rows.Next() {
		v, err := scanMarketplaceOrder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

func (s *MarketplaceService) SetListingStatus(ctx context.Context, userID int64, isAdmin bool, listingID int64, status string) (*MarketplaceListing, error) {
	if userID <= 0 {
		return nil, ErrMarketplaceForbidden
	}
	if status != "active" && status != "paused" && status != "removed" {
		return nil, ErrMarketplaceInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var id int64
	err = tx.QueryRowContext(ctx, `UPDATE berth_marketplace_listings SET status=$1,
 admin_suspended=CASE WHEN $3 THEN $1<>'active' ELSE admin_suspended END,updated_at=clock_timestamp()
 WHERE id=$2 AND ($3 OR seller_id=$4) AND ($3 OR $1<>'active' OR NOT admin_suspended) RETURNING id`, status, listingID, isAdmin, userID).Scan(&id)
	if err != nil {
		return nil, marketplaceNotFound(err)
	}
	v, err := scanMarketplaceListing(tx.QueryRowContext(ctx, "SELECT "+marketplaceListingColumns+" FROM berth_marketplace_listings l WHERE id=$1", id))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	sanitizeListingForCaller(v, userID, isAdmin)
	return v, nil
}

func (s *MarketplaceService) Checkout(ctx context.Context, userID, listingID int64, key string) (*MarketplaceOrder, error) {
	if userID <= 0 || listingID <= 0 || key == "" || len(key) > 128 || strings.TrimSpace(key) != key || !utf8.ValidString(key) || strings.ContainsRune(key, 0) {
		return nil, ErrMarketplaceInvalid
	}
	var (
		order     *MarketplaceOrder
		notifyIDs []int64
	)
	err := withMarketplaceTxRetry(ctx, func() error {
		order = nil
		notifyIDs = nil
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		// Same buyer/key is serialized even when retries name different listings.
		if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", fmt.Sprintf("berth-checkout:%d:%s", userID, key)); err != nil {
			return err
		}
		replay, err := scanMarketplaceOrder(tx.QueryRowContext(ctx, "SELECT "+marketplaceOrderColumns+" FROM berth_marketplace_orders WHERE buyer_id=$1 AND idempotency_key=$2", userID, key))
		if err == nil {
			if replay.ListingID != listingID {
				return ErrMarketplaceIdempotency
			}
			_ = tx.Rollback()
			order = replay
			notifyIDs = []int64{replay.BuyerID, replay.SellerID}
			return nil
		}
		if !errors.Is(err, ErrMarketplaceNotFound) {
			return err
		}
		var kind string
		var resourceID int64
		if err = tx.QueryRowContext(ctx, "SELECT resource_type,resource_id FROM berth_marketplace_listings WHERE id=$1", listingID).Scan(&kind, &resourceID); err != nil {
			return marketplaceNotFound(err)
		}
		// Global lock order: accounts/proxies -> listings -> orders -> users ORDER BY id.
		owner, err := marketplaceLockResource(ctx, tx, kind, resourceID)
		if err != nil {
			return err
		}
		listing, err := scanMarketplaceListing(tx.QueryRowContext(ctx, "SELECT "+marketplaceListingColumns+" FROM berth_marketplace_listings l WHERE id=$1 FOR UPDATE OF l", listingID))
		if err != nil {
			return err
		}
		if listing.SellerID == userID {
			return ErrMarketplaceForbidden
		}
		if listing.Visibility == MarketplaceVisibilityTargeted && (listing.TargetBuyerID == nil || *listing.TargetBuyerID != userID) {
			return ErrMarketplaceForbidden
		}
		if listing.Status != "active" || owner != listing.SellerID {
			return ErrMarketplaceUnavailable
		}
		if listing.ActiveRentals >= listing.Capacity {
			return ErrMarketplaceCapacity
		}

		// Cross-listing active capacity guard: verify total active rentals across
		// BOTH public and targeted listings on this resource never violate
		// capacity/exclusivity (serialized by the resource row lock above).
		var totalResourceActive int
		var minActiveListingCap int
		if err = tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(MIN(l2.capacity),0)
 FROM berth_marketplace_orders o
 JOIN berth_marketplace_listings l2 ON l2.id=o.listing_id
 WHERE o.resource_type=$1 AND o.resource_id=$2 AND o.status='active'
   AND (o.expires_at IS NULL OR o.expires_at>clock_timestamp())
   AND (o.quota_limit_usd IS NULL OR o.quota_used_usd<o.quota_limit_usd)`, kind, resourceID).Scan(&totalResourceActive, &minActiveListingCap); err != nil {
			return err
		}
		effectiveCap := listing.Capacity
		if totalResourceActive > 0 && minActiveListingCap > 0 && minActiveListingCap < effectiveCap {
			effectiveCap = minActiveListingCap
		}
		if totalResourceActive >= effectiveCap {
			return ErrMarketplaceCapacity
		}

		if err = marketplaceLockUsers(ctx, tx, userID, listing.SellerID, true); err != nil {
			return err
		}
		var now time.Time
		if err = tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			return err
		}

		var endPtr *time.Time
		if listing.DurationHours != nil {
			end := now.Add(time.Duration(*listing.DurationHours) * time.Hour)
			endPtr = &end
		}
		table := "accounts"
		if kind == "proxy" {
			table = "proxies"
		}
		if endPtr != nil {
			var termAvailable bool
			if err = tx.QueryRowContext(ctx, "SELECT expires_at IS NULL OR expires_at >= $2 FROM "+table+" WHERE id=$1", resourceID, *endPtr).Scan(&termAvailable); err != nil {
				return err
			}
			if !termAvailable {
				return ErrMarketplaceUnavailable
			}
		}

		var groupID, proxyID *int64
		if kind == "account" {
			id, e := s.ensureAccountGroupTx(ctx, tx, resourceID, owner)
			if e != nil {
				return e
			}
			groupID = &id
			var groupActive bool
			if err = tx.QueryRowContext(ctx, "SELECT status='active' AND deleted_at IS NULL FROM groups WHERE id=$1", id).Scan(&groupActive); err != nil {
				return err
			}
			if !groupActive {
				return ErrMarketplaceUnavailable
			}
		} else {
			if endPtr == nil {
				return ErrMarketplaceInvalid
			}
			var id int64
			// Inherit max_accounts, max_rpm, max_concurrency and link source_proxy_id
			// so rented proxy clones aggregate physical proxy capacity (R-7).
			err = tx.QueryRowContext(ctx, `INSERT INTO proxies(name,protocol,host,port,username,password,status,expires_at,fallback_mode,backup_proxy_id,expiry_warn_days,exit_ip,exit_country,exit_country_code,exit_region,exit_city,exit_timezone,exit_utc_offset_seconds,exit_asn,exit_isp,exit_checked_at,max_accounts,max_rpm,max_concurrency,source_proxy_id,source_type)
 SELECT 'Berth rental proxy',protocol,host,port,username,password,'active',LEAST(COALESCE(expires_at,$2),$2),'none',NULL,0,exit_ip,exit_country,exit_country_code,exit_region,exit_city,exit_timezone,exit_utc_offset_seconds,exit_asn,exit_isp,exit_checked_at,max_accounts,max_rpm,max_concurrency,id,'marketplace_rental' FROM proxies WHERE id=$1 RETURNING id`, resourceID, *endPtr).Scan(&id)
			if err != nil {
				return err
			}
			proxyID = &id
		}

		var durationArg any
		if listing.DurationHours != nil {
			durationArg = *listing.DurationHours
		}
		var quotaArg any
		if listing.QuotaLimitUSD != nil {
			quotaArg = *listing.QuotaLimitUSD
		}
		var endArg any
		if endPtr != nil {
			endArg = *endPtr
		}

		orderRateMult := listing.UsageRateMultiplier
		if orderRateMult <= 0 {
			orderRateMult = 1.0
		}
		var id int64
		err = tx.QueryRowContext(ctx, `INSERT INTO berth_marketplace_orders(listing_id,buyer_id,seller_id,idempotency_key,title,resource_type,resource_id,rental_mode,duration_hours,quota_limit_usd,price_cents,group_id,rental_proxy_id,starts_at,expires_at,rent_commission_bps,usage_rate_multiplier)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,(SELECT rent_commission_bps FROM berth_marketplace_settings WHERE id=1),$16) RETURNING id`,
			listing.ID, userID, listing.SellerID, key, listing.Title, kind, resourceID,
			listing.RentalMode, durationArg, quotaArg, listing.PriceCents, groupID, proxyID, now, endArg, orderRateMult).Scan(&id)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE users SET balance=balance-$1::numeric/100,updated_at=clock_timestamp() WHERE id=$2 AND balance-COALESCE(frozen_balance,0)>=$1::numeric/100`, listing.PriceCents, userID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrMarketplaceBalance
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO berth_marketplace_ledger(order_id,user_id,kind,amount_cents) VALUES($1,$2,'hold',$3)", id, userID, -listing.PriceCents); err != nil {
			return err
		}
		created, err := scanMarketplaceOrder(tx.QueryRowContext(ctx, "SELECT "+marketplaceOrderColumns+" FROM berth_marketplace_orders WHERE id=$1", id))
		if err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		order = created
		notifyIDs = []int64{userID}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(notifyIDs) > 0 {
		s.notifyBalances(ctx, notifyIDs...)
	}
	return order, nil
}

func marketplaceLockUsers(ctx context.Context, tx *sql.Tx, buyerID, sellerID int64, active bool) error {
	rows, err := tx.QueryContext(ctx, "SELECT id,status,deleted_at FROM users WHERE id IN ($1,$2) ORDER BY id FOR UPDATE", buyerID, sellerID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	count := 0
	for rows.Next() {
		var id int64
		var status string
		var deleted *time.Time
		if err = rows.Scan(&id, &status, &deleted); err != nil {
			return err
		}
		if active && (status != "active" || deleted != nil) {
			return ErrMarketplaceUnavailable
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if count != 2 {
		return ErrMarketplaceUnavailable
	}
	return nil
}

// Integer arithmetic keeps the audit exact: earned rounds down, remainder is refunded.
func marketplaceSettlement(price int64, start, end, at time.Time) (earned, refund int64) {
	if !at.After(start) {
		return 0, price
	}
	if !at.Before(end) {
		return price, 0
	}
	duration := end.Sub(start).Microseconds()
	elapsed := at.Sub(start).Microseconds()
	// The intermediate product may exceed int64 for a year-long rental.
	hi, lo := bits.Mul64(uint64(price), uint64(elapsed))
	quotient, _ := bits.Div64(hi, lo, uint64(duration))
	earned = int64(quotient)
	return earned, price - earned
}

func (s *MarketplaceService) Terminate(ctx context.Context, userID int64, isAdmin bool, orderID int64) (*MarketplaceOrder, error) {
	if userID <= 0 {
		return nil, ErrMarketplaceForbidden
	}
	return s.settleOrder(ctx, orderID, userID, isAdmin, false)
}

func (s *MarketplaceService) settleOrder(ctx context.Context, orderID, userID int64, isAdmin, dueOnly bool) (*MarketplaceOrder, error) {
	var (
		settledOrder *MarketplaceOrder
		shouldNotify bool
	)
	err := withMarketplaceTxRetry(ctx, func() error {
		settledOrder = nil
		shouldNotify = false
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		order, err := scanMarketplaceOrder(tx.QueryRowContext(ctx, "SELECT "+marketplaceOrderColumns+" FROM berth_marketplace_orders WHERE id=$1 FOR UPDATE", orderID))
		if err != nil {
			return err
		}
		if !dueOnly && !isAdmin && userID != order.BuyerID && userID != order.SellerID {
			return ErrMarketplaceForbidden
		}
		if order.Status != "active" {
			_ = tx.Rollback()
			settledOrder = order
			shouldNotify = true
			return nil
		}
		if err = marketplaceLockUsers(ctx, tx, order.BuyerID, order.SellerID, false); err != nil {
			return err
		}
		var now time.Time
		if err = tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			return err
		}
		var quotaUsedStr string
		var quotaLimitStr sql.NullString
		var terminatingAt sql.NullTime
		if err = tx.QueryRowContext(ctx, "SELECT quota_used_usd::text,quota_limit_usd::text,terminating_at FROM berth_marketplace_orders WHERE id=$1", order.ID).Scan(&quotaUsedStr, &quotaLimitStr, &terminatingAt); err != nil {
			return err
		}
		quotaUsedDec, err := decimal.NewFromString(quotaUsedStr)
		if err != nil {
			return err
		}
		var quotaLimitDec decimal.Decimal
		if quotaLimitStr.Valid {
			quotaLimitDec, err = decimal.NewFromString(quotaLimitStr.String)
			if err != nil {
				return err
			}
		}

		timeExpired := order.ExpiresAt != nil && !now.Before(*order.ExpiresAt)
		quotaExhausted := quotaLimitDec.IsPositive() && quotaUsedDec.GreaterThanOrEqual(quotaLimitDec)
		if dueOnly && !timeExpired && !quotaExhausted && !terminatingAt.Valid {
			settledOrder = order
			return nil
		}

		// Two-phase termination (R-3): if unexpired pre-dispatch quota reservations
		// are still in flight, enter terminating state immediately (blocking all new
		// admissions and revoking Edge leases) and defer escrow payout/refund until
		// in-flight requests finish settling or their reservations expire.
		var inFlightReservations int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM berth_marketplace_quota_reservations
 WHERE order_id=$1 AND status='reserved' AND expires_at>$2`, order.ID, now).Scan(&inFlightReservations); err != nil {
			return err
		}

		status := "terminated"
		var completionReason string
		switch {
		case quotaExhausted:
			status = "completed"
			completionReason = MarketplaceCompletionQuotaExhausted
		case timeExpired:
			status = "completed"
			completionReason = MarketplaceCompletionTimeExpired
		case order.CompletionReason != nil && strings.TrimSpace(*order.CompletionReason) != "":
			completionReason = strings.TrimSpace(*order.CompletionReason)
		case userID == order.BuyerID:
			completionReason = MarketplaceCompletionBuyerTerminated
		case userID == order.SellerID:
			completionReason = MarketplaceCompletionSellerTerminated
		default:
			completionReason = MarketplaceCompletionAdminTerminated
		}

		if inFlightReservations > 0 {
			if order.RentalProxyID != nil {
				if _, err = tx.ExecContext(ctx, "UPDATE proxies SET status='expired',expires_at=LEAST(COALESCE(expires_at,$2),$2),updated_at=clock_timestamp() WHERE id=$1", *order.RentalProxyID, now); err != nil {
					return err
				}
			}
			effectiveTermAt := now
			if terminatingAt.Valid {
				effectiveTermAt = terminatingAt.Time
			}
			if _, err = tx.ExecContext(ctx, `UPDATE berth_marketplace_orders
 SET terminating_at=COALESCE(terminating_at,$2),completion_reason=COALESCE(completion_reason,$3)
 WHERE id=$1`, order.ID, now, completionReason); err != nil {
				return err
			}
			if err = tx.Commit(); err != nil {
				return err
			}
			order.TerminatingAt = &effectiveTermAt
			order.CompletionReason = &completionReason
			settledOrder = order
			return nil
		}

		earned, commission, refund := marketplaceSettlementSplit(
			order.RentalMode,
			order.PriceCents,
			order.RentCommissionBPS,
			order.StartsAt,
			order.ExpiresAt,
			now,
			quotaUsedDec,
			quotaLimitDec,
		)

		if _, err = tx.ExecContext(ctx, "UPDATE users SET balance=balance+$1::numeric/100,updated_at=clock_timestamp() WHERE id=$2", earned, order.SellerID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE users SET balance=balance+$1::numeric/100,updated_at=clock_timestamp() WHERE id=$2", refund, order.BuyerID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO berth_marketplace_ledger(order_id,user_id,kind,amount_cents) VALUES($1,$2,'payout',$3),($1,$4,'refund',$5)`, order.ID, order.SellerID, earned, order.BuyerID, refund); err != nil {
			return err
		}
		if order.RentalProxyID != nil {
			if _, err = tx.ExecContext(ctx, "UPDATE proxies SET status='expired',expires_at=LEAST(COALESCE(expires_at,$2),$2),updated_at=clock_timestamp() WHERE id=$1", *order.RentalProxyID, now); err != nil {
				return err
			}
		}
		if commission > 0 {
			if _, err = tx.ExecContext(ctx, "INSERT INTO berth_marketplace_ledger(order_id,kind,amount_cents) VALUES($1,'platform_commission',$2)", order.ID, commission); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE berth_marketplace_quota_reservations SET status='expired',updated_at=clock_timestamp() WHERE order_id=$1 AND status='reserved'`, order.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE berth_marketplace_orders SET status=$2,completion_reason=$3,seller_earned_cents=$4,refund_cents=$5,settled_at=$6,platform_commission_cents=$7,quota_reserved_usd=0 WHERE id=$1`,
			order.ID, status, completionReason, earned, refund, now, commission); err != nil {
			return err
		}
		order.Status = status
		order.CompletionReason = &completionReason
		order.SellerEarnedCents = earned
		order.RefundCents = refund
		order.PlatformCommissionCents = commission
		order.QuotaReservedUSD = 0
		order.SettledAt = &now
		if err = tx.Commit(); err != nil {
			return err
		}
		settledOrder = order
		shouldNotify = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if settledOrder != nil && settledOrder.GroupID != nil && *settledOrder.GroupID > 0 &&
		(settledOrder.Status != "active" || settledOrder.TerminatingAt != nil) {
		revCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		_, _ = RevokeActiveEdgeLeasesForUserGroup(revCtx, settledOrder.BuyerID, *settledOrder.GroupID)
		cancel()
	}
	if shouldNotify && settledOrder != nil {
		s.notifyBalances(ctx, settledOrder.BuyerID, settledOrder.SellerID)
	}
	return settledOrder, nil
}

func (s *MarketplaceService) notifyBalances(ctx context.Context, ids ...int64) {
	if s.OnBalanceChanged == nil {
		return
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	for _, id := range ids {
		s.OnBalanceChanged(bounded, id)
	}
}

func (s *MarketplaceService) SettleDue(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM berth_marketplace_orders
 WHERE status='active'
   AND (terminating_at IS NOT NULL
     OR (expires_at IS NOT NULL AND expires_at<=clock_timestamp())
     OR (quota_limit_usd IS NOT NULL AND quota_used_usd>=quota_limit_usd))
 ORDER BY COALESCE(terminating_at,expires_at,starts_at),id LIMIT 100`)
	if err != nil {
		return 0, err
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, id := range ids {
		v, e := s.settleOrder(ctx, id, 0, false, true)
		if e != nil {
			return count, e
		}
		if v.Status != "active" {
			count++
		}
	}
	return count, nil
}
