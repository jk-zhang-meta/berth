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

type MarketplaceService struct {
	db               *sql.DB
	OnBalanceChanged func(context.Context, int64)
}

func NewMarketplaceService(db *sql.DB) *MarketplaceService { return &MarketplaceService{db: db} }

type MarketplacePublishInput struct {
	UsageRateMultiplier *float64 `json:"usage_rate_multiplier"`
	ResourceType        string   `json:"resource_type"`
	ResourceID          int64    `json:"resource_id"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	DurationHours       int      `json:"duration_hours"`
	PriceCents          int64    `json:"price_cents"`
	Capacity            int      `json:"capacity"`
}

type MarketplaceListing struct {
	UsageRateMultiplier float64   `json:"usage_rate_multiplier"`
	ID                  int64     `json:"id"`
	ResourceType        string    `json:"resource_type"`
	ResourceID          int64     `json:"resource_id"`
	SellerID            int64     `json:"seller_id"`
	Title               string    `json:"title"`
	Description         string    `json:"description"`
	DurationHours       int       `json:"duration_hours"`
	PriceCents          int64     `json:"price_cents"`
	Capacity            int       `json:"capacity"`
	Status              string    `json:"status"`
	AdminSuspended      bool      `json:"admin_suspended"`
	ActiveRentals       int       `json:"active_rentals"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type MarketplaceOrder struct {
	ID                      int64      `json:"id"`
	ListingID               int64      `json:"listing_id"`
	BuyerID                 int64      `json:"buyer_id"`
	SellerID                int64      `json:"seller_id"`
	Title                   string     `json:"title"`
	ResourceType            string     `json:"resource_type"`
	ResourceID              int64      `json:"resource_id"`
	DurationHours           int        `json:"duration_hours"`
	PriceCents              int64      `json:"price_cents"`
	GroupID                 *int64     `json:"group_id"`
	RentalProxyID           *int64     `json:"rental_proxy_id"`
	StartsAt                time.Time  `json:"starts_at"`
	ExpiresAt               time.Time  `json:"ends_at"`
	Status                  string     `json:"status"`
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

const marketplaceListingColumns = `l.id,l.resource_type,l.resource_id,l.seller_id,l.title,l.description,l.duration_hours,l.price_cents,l.capacity,l.status,l.admin_suspended,l.created_at,l.updated_at,l.usage_rate_multiplier,
 (SELECT count(*) FROM berth_marketplace_orders o WHERE o.listing_id=l.id AND o.status='active' AND o.expires_at>clock_timestamp())`
const marketplaceOrderColumns = `id,listing_id,buyer_id,seller_id,title,resource_type,resource_id,duration_hours,price_cents,group_id,rental_proxy_id,starts_at,expires_at,status,seller_earned_cents,refund_cents,settled_at,created_at,rent_commission_bps,platform_commission_cents`

func scanMarketplaceListing(row marketplaceScanner) (*MarketplaceListing, error) {
	var v MarketplaceListing
	err := row.Scan(&v.ID, &v.ResourceType, &v.ResourceID, &v.SellerID, &v.Title, &v.Description, &v.DurationHours, &v.PriceCents, &v.Capacity, &v.Status, &v.AdminSuspended, &v.CreatedAt, &v.UpdatedAt, &v.UsageRateMultiplier, &v.ActiveRentals)
	return &v, marketplaceNotFound(err)
}
func scanMarketplaceOrder(row marketplaceScanner) (*MarketplaceOrder, error) {
	var v MarketplaceOrder
	err := row.Scan(&v.ID, &v.ListingID, &v.BuyerID, &v.SellerID, &v.Title, &v.ResourceType, &v.ResourceID, &v.DurationHours, &v.PriceCents, &v.GroupID, &v.RentalProxyID, &v.StartsAt, &v.ExpiresAt, &v.Status, &v.SellerEarnedCents, &v.RefundCents, &v.SettledAt, &v.CreatedAt, &v.RentCommissionBPS, &v.PlatformCommissionCents)
	return &v, marketplaceNotFound(err)
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
	if (v.ResourceType != "account" && v.ResourceType != "proxy") || v.ResourceID <= 0 || v.Title == "" || !utf8.ValidString(v.Title) || !utf8.ValidString(v.Description) || utf8.RuneCountInString(v.Title) > 100 || utf8.RuneCountInString(v.Description) > 2000 || strings.ContainsRune(v.Title, 0) || strings.ContainsRune(v.Description, 0) || v.DurationHours < 1 || v.DurationHours > 8760 || v.PriceCents < 1 || v.PriceCents > 100000000 || v.Capacity < 1 || v.Capacity > 1000 {
		return ErrMarketplaceInvalid
	}
	return nil
}

func (s *MarketplaceService) Publish(ctx context.Context, userID int64, isAdmin bool, input MarketplacePublishInput) (*MarketplaceListing, error) {
	if userID <= 0 {
		return nil, ErrMarketplaceForbidden
	}
	if err := validateMarketplacePublish(&input); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	owner, err := marketplaceLockResource(ctx, tx, input.ResourceType, input.ResourceID)
	if err != nil {
		return nil, err
	}
	if owner == 0 && isAdmin {
		table, column := "account_stewards", "account_id"
		if input.ResourceType == "proxy" {
			table, column = "proxy_stewards", "proxy_id"
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO "+table+" ("+column+",user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING", input.ResourceID, userID); err != nil {
			return nil, err
		}
		owner, err = marketplaceLockResource(ctx, tx, input.ResourceType, input.ResourceID)
		if err != nil {
			return nil, err
		}
	}
	if owner <= 0 || (!isAdmin && owner != userID) {
		return nil, ErrMarketplaceForbidden
	}
	var sellerActive bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL)", owner).Scan(&sellerActive); err != nil {
		return nil, err
	}
	if !sellerActive {
		return nil, ErrMarketplaceUnavailable
	}
	if input.ResourceType == "account" {
		groupID, groupErr := s.ensureAccountGroupTx(ctx, tx, input.ResourceID, owner)
		if groupErr != nil {
			return nil, groupErr
		}
		if _, err = tx.ExecContext(ctx, "UPDATE groups SET rate_multiplier=$1,updated_at=clock_timestamp() WHERE id=$2", *input.UsageRateMultiplier, groupID); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO scheduler_outbox(event_type,group_id) VALUES('group_changed',$1)", groupID); err != nil {
			return nil, err
		}
	}
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO berth_marketplace_listings(resource_type,resource_id,seller_id,title,description,duration_hours,price_cents,capacity,usage_rate_multiplier)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(resource_type,resource_id) DO UPDATE SET title=EXCLUDED.title,description=EXCLUDED.description,
 duration_hours=EXCLUDED.duration_hours,price_cents=EXCLUDED.price_cents,capacity=EXCLUDED.capacity,usage_rate_multiplier=EXCLUDED.usage_rate_multiplier,status='active',updated_at=clock_timestamp()
 WHERE berth_marketplace_listings.seller_id=EXCLUDED.seller_id AND NOT berth_marketplace_listings.admin_suspended RETURNING id`, input.ResourceType, input.ResourceID, owner, input.Title, input.Description, input.DurationHours, input.PriceCents, input.Capacity, *input.UsageRateMultiplier).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMarketplaceForbidden
	}
	if err != nil {
		return nil, err
	}
	result, err := scanMarketplaceListing(tx.QueryRowContext(ctx, "SELECT "+marketplaceListingColumns+" FROM berth_marketplace_listings l WHERE l.id=$1", id))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
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
	where := "l.status='active'"
	args := []any{}
	switch scope {
	case "", "market":
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
	return v, nil
}

func (s *MarketplaceService) Checkout(ctx context.Context, userID, listingID int64, key string) (*MarketplaceOrder, error) {
	if userID <= 0 || listingID <= 0 || key == "" || len(key) > 128 || strings.TrimSpace(key) != key || !utf8.ValidString(key) || strings.ContainsRune(key, 0) {
		return nil, ErrMarketplaceInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	// Same buyer/key is serialized even when retries name different listings.
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", fmt.Sprintf("berth-checkout:%d:%s", userID, key)); err != nil {
		return nil, err
	}
	replay, err := scanMarketplaceOrder(tx.QueryRowContext(ctx, "SELECT "+marketplaceOrderColumns+" FROM berth_marketplace_orders WHERE buyer_id=$1 AND idempotency_key=$2", userID, key))
	if err == nil {
		if replay.ListingID != listingID {
			return nil, ErrMarketplaceIdempotency
		}
		_ = tx.Rollback()
		s.notifyBalances(ctx, replay.BuyerID, replay.SellerID)
		return replay, nil
	}
	if !errors.Is(err, ErrMarketplaceNotFound) {
		return nil, err
	}
	var kind string
	var resourceID int64
	if err = tx.QueryRowContext(ctx, "SELECT resource_type,resource_id FROM berth_marketplace_listings WHERE id=$1", listingID).Scan(&kind, &resourceID); err != nil {
		return nil, marketplaceNotFound(err)
	}
	owner, err := marketplaceLockResource(ctx, tx, kind, resourceID)
	if err != nil {
		return nil, err
	}
	listing, err := scanMarketplaceListing(tx.QueryRowContext(ctx, "SELECT "+marketplaceListingColumns+" FROM berth_marketplace_listings l WHERE id=$1 FOR UPDATE OF l", listingID))
	if err != nil {
		return nil, err
	}
	if listing.SellerID == userID {
		return nil, ErrMarketplaceForbidden
	}
	if listing.Status != "active" || owner != listing.SellerID {
		return nil, ErrMarketplaceUnavailable
	}
	if listing.ActiveRentals >= listing.Capacity {
		return nil, ErrMarketplaceCapacity
	}
	if err = marketplaceLockUsers(ctx, tx, userID, listing.SellerID, true); err != nil {
		return nil, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return nil, err
	}
	end := now.Add(time.Duration(listing.DurationHours) * time.Hour)
	table := "accounts"
	if kind == "proxy" {
		table = "proxies"
	}
	var termAvailable bool
	if err = tx.QueryRowContext(ctx, "SELECT expires_at IS NULL OR expires_at >= $2 FROM "+table+" WHERE id=$1", resourceID, end).Scan(&termAvailable); err != nil {
		return nil, err
	}
	if !termAvailable {
		return nil, ErrMarketplaceUnavailable
	}
	var groupID, proxyID *int64
	if kind == "account" {
		id, e := s.ensureAccountGroupTx(ctx, tx, resourceID, owner)
		if e != nil {
			return nil, e
		}
		groupID = &id
		var groupActive bool
		if err = tx.QueryRowContext(ctx, "SELECT status='active' AND deleted_at IS NULL FROM groups WHERE id=$1", id).Scan(&groupActive); err != nil {
			return nil, err
		}
		if !groupActive {
			return nil, ErrMarketplaceUnavailable
		}
	} else {
		var id int64
		err = tx.QueryRowContext(ctx, `INSERT INTO proxies(name,protocol,host,port,username,password,status,expires_at,fallback_mode,backup_proxy_id,expiry_warn_days,exit_ip,exit_country,exit_country_code,exit_region,exit_city,exit_timezone,exit_utc_offset_seconds,exit_asn,exit_isp,exit_checked_at)
 SELECT 'Berth rental proxy',protocol,host,port,username,password,'active',LEAST(COALESCE(expires_at,$2),$2),'none',NULL,0,exit_ip,exit_country,exit_country_code,exit_region,exit_city,exit_timezone,exit_utc_offset_seconds,exit_asn,exit_isp,exit_checked_at FROM proxies WHERE id=$1 RETURNING id`, resourceID, end).Scan(&id)
		if err != nil {
			return nil, err
		}
		proxyID = &id
	}
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO berth_marketplace_orders(listing_id,buyer_id,seller_id,idempotency_key,title,resource_type,resource_id,duration_hours,price_cents,group_id,rental_proxy_id,starts_at,expires_at,rent_commission_bps)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,(SELECT rent_commission_bps FROM berth_marketplace_settings WHERE id=1)) RETURNING id`, listing.ID, userID, listing.SellerID, key, listing.Title, kind, resourceID, listing.DurationHours, listing.PriceCents, groupID, proxyID, now, end).Scan(&id)
	if err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE users SET balance=balance-$1::numeric/100,updated_at=clock_timestamp() WHERE id=$2 AND balance-COALESCE(frozen_balance,0)>=$1::numeric/100`, listing.PriceCents, userID)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, ErrMarketplaceBalance
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO berth_marketplace_ledger(order_id,user_id,kind,amount_cents) VALUES($1,$2,'hold',$3)", id, userID, -listing.PriceCents); err != nil {
		return nil, err
	}
	order, err := scanMarketplaceOrder(tx.QueryRowContext(ctx, "SELECT "+marketplaceOrderColumns+" FROM berth_marketplace_orders WHERE id=$1", id))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	s.notifyBalances(ctx, userID)
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	order, err := scanMarketplaceOrder(tx.QueryRowContext(ctx, "SELECT "+marketplaceOrderColumns+" FROM berth_marketplace_orders WHERE id=$1 FOR UPDATE", orderID))
	if err != nil {
		return nil, err
	}
	if !dueOnly && !isAdmin && userID != order.BuyerID && userID != order.SellerID {
		return nil, ErrMarketplaceForbidden
	}
	if order.Status != "active" {
		_ = tx.Rollback()
		s.notifyBalances(ctx, order.BuyerID, order.SellerID)
		return order, nil
	}
	if err = marketplaceLockUsers(ctx, tx, order.BuyerID, order.SellerID, false); err != nil {
		return nil, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return nil, err
	}
	if dueOnly && now.Before(order.ExpiresAt) {
		return order, nil
	}
	earned, refund := marketplaceSettlement(order.PriceCents, order.StartsAt, order.ExpiresAt, now)
	commission := earned * int64(order.RentCommissionBPS) / 10000
	earned -= commission
	status := "terminated"
	if !now.Before(order.ExpiresAt) {
		status = "completed"
	}
	if _, err = tx.ExecContext(ctx, "UPDATE users SET balance=balance+$1::numeric/100,updated_at=clock_timestamp() WHERE id=$2", earned, order.SellerID); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE users SET balance=balance+$1::numeric/100,updated_at=clock_timestamp() WHERE id=$2", refund, order.BuyerID); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO berth_marketplace_ledger(order_id,user_id,kind,amount_cents) VALUES($1,$2,'payout',$3),($1,$4,'refund',$5)`, order.ID, order.SellerID, earned, order.BuyerID, refund); err != nil {
		return nil, err
	}
	if order.RentalProxyID != nil {
		if _, err = tx.ExecContext(ctx, "UPDATE proxies SET status='expired',expires_at=LEAST(COALESCE(expires_at,$2),$2),updated_at=clock_timestamp() WHERE id=$1", *order.RentalProxyID, now); err != nil {
			return nil, err
		}
	}
	if commission > 0 {
		if _, err = tx.ExecContext(ctx, "INSERT INTO berth_marketplace_ledger(order_id,kind,amount_cents) VALUES($1,'platform_commission',$2)", order.ID, commission); err != nil {
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE berth_marketplace_orders SET status=$2,seller_earned_cents=$3,refund_cents=$4,settled_at=$5,platform_commission_cents=$6 WHERE id=$1`, order.ID, status, earned, refund, now, commission); err != nil {
		return nil, err
	}
	order.Status = status
	order.SellerEarnedCents = earned
	order.RefundCents = refund
	order.PlatformCommissionCents = commission
	order.SettledAt = &now
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	s.notifyBalances(ctx, order.BuyerID, order.SellerID)
	return order, nil
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
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM berth_marketplace_orders WHERE status='active' AND expires_at<=clock_timestamp() ORDER BY expires_at,id LIMIT 100")
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
