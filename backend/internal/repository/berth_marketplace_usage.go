package repository

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"math/bits"
	"strings"

	"github.com/jk-zhang-meta/berth/internal/service"
	"github.com/shopspring/decimal"
)

// Match global lock hierarchy across checkout, settlement, and usage billing:
// accounts -> berth_marketplace_listings -> berth_marketplace_orders -> users (ORDER BY id).
func lockMarketplaceBillingUsers(ctx context.Context, tx *sql.Tx, cmd *service.UsageBillingCommand) error {
	if cmd.AccountQuotaCost > 0 {
		var id int64
		if err := tx.QueryRowContext(ctx, "SELECT id FROM accounts WHERE id=$1 FOR UPDATE", cmd.AccountID).Scan(&id); err != nil {
			return err
		}
	}
	m := cmd.MarketplaceUsage
	if m == nil {
		if cmd.SettlementKind == service.UsageSettlementMarketplaceQuota || cmd.SettlementKind == service.UsageSettlementMarketplaceDuration {
			return errors.New("invalid marketplace usage settlement")
		}
		return nil
	}
	if m.AccountID != cmd.AccountID || m.SellerID <= 0 || m.GroupID <= 0 || m.CommissionBPS < 0 || m.CommissionBPS > 10000 || m.AdmittedAt.IsZero() || math.IsNaN(cmd.BalanceCost) || math.IsInf(cmd.BalanceCost, 0) || cmd.BalanceCost < 0 || math.IsNaN(cmd.MarketplaceQuotaCost) || math.IsInf(cmd.MarketplaceQuotaCost, 0) || cmd.MarketplaceQuotaCost < 0 || cmd.SubscriptionCost > 0 {
		return errors.New("invalid marketplace usage settlement")
	}

	if cmd.SettlementKind == service.UsageSettlementMarketplaceQuota {
		if m.OrderID <= 0 || cmd.BalanceCost > 0 {
			return errors.New("invalid marketplace quota settlement")
		}
		var orderID int64
		if err := tx.QueryRowContext(ctx, "SELECT id FROM berth_marketplace_orders WHERE id=$1 FOR UPDATE", m.OrderID).Scan(&orderID); err != nil {
			return err
		}
	}

	rows, err := tx.QueryContext(ctx, "SELECT id FROM users WHERE id IN ($1,$2) ORDER BY id FOR UPDATE", cmd.UserID, m.SellerID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	expected := 2
	if cmd.UserID == m.SellerID {
		expected = 1
	}
	if n != expected {
		return errors.New("marketplace billing user missing")
	}
	return nil
}

func creditMarketplaceUsage(ctx context.Context, tx *sql.Tx, cmd *service.UsageBillingCommand, result *service.UsageBillingApplyResult) error {
	m := cmd.MarketplaceUsage
	// Self-use remains ordinary platform usage; it cannot create a cashback loop.
	if m == nil || m.SellerID == cmd.UserID {
		return nil
	}
	if cmd.SettlementKind == service.UsageSettlementMarketplaceQuota {
		return settleMarketplaceQuotaUsage(ctx, tx, cmd, result)
	}
	if cmd.BalanceCost <= 0 {
		return nil
	}
	var net string
	funded := cmd.BalanceCost
	if result.NewBalance != nil && *result.NewBalance < 0 {
		funded = math.Max(0, cmd.BalanceCost+*result.NewBalance)
	}
	err := tx.QueryRowContext(ctx, `INSERT INTO berth_marketplace_usage_revenue
 (request_id,api_key_id,buyer_id,seller_id,account_id,group_id,commission_bps,gross_amount,seller_amount,platform_amount,admitted_at,funded_amount,seller_paid_amount)
 VALUES ($1,$2,$3,$4,$5,$6,$7::integer,$8::numeric,
 $8::numeric-trunc($8::numeric*($7::integer)/10000,8),trunc($8::numeric*($7::integer)/10000,8),$9,$10::numeric,
 $10::numeric-trunc($10::numeric*($7::integer)/10000,8))
 RETURNING seller_paid_amount::text`, cmd.RequestID, cmd.APIKeyID, cmd.UserID, m.SellerID, cmd.AccountID, m.GroupID, m.CommissionBPS, cmd.BalanceCost, m.AdmittedAt, service.QuantizeUsageBillingAmount(funded)).Scan(&net)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE users SET balance=balance+$2::numeric,updated_at=clock_timestamp() WHERE id=$1", m.SellerID, net); err != nil {
		return err
	}
	result.MarketplaceSellerID = m.SellerID
	return nil
}

// settleMarketplaceQuotaUsage settles prepaid quota/hybrid rental usage inside
// the same UsageBillingRepository.Apply transaction: releases any pre-dispatch
// reservation, increments quota_used_usd, appends to berth_marketplace_order_usage,
// and immediately settles 100% of price_cents if quota_used_usd >= quota_limit_usd.
func settleMarketplaceQuotaUsage(ctx context.Context, tx *sql.Tx, cmd *service.UsageBillingCommand, result *service.UsageBillingApplyResult) error {
	m := cmd.MarketplaceUsage
	if m == nil || m.OrderID <= 0 {
		return errors.New("missing marketplace order id for quota settlement")
	}

	releasedReservedStr := "0"
	opID := strings.TrimSpace(cmd.MarketplaceOperationID)
	if opID == "" {
		opID = strings.TrimSpace(m.OperationID)
	}
	if opID != "" {
		var reservedStr string
		err := tx.QueryRowContext(ctx, `UPDATE berth_marketplace_quota_reservations
 SET status='settled',updated_at=clock_timestamp()
 WHERE operation_id=$1 AND order_id=$2 AND status='reserved'
 RETURNING reserved_usd::text`, opID, m.OrderID).Scan(&reservedStr)
		if err == nil {
			releasedReservedStr = reservedStr
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}

	if cmd.MarketplaceQuotaCost <= 0 && releasedReservedStr == "0" {
		return nil
	}

	var (
		status            string
		rentalMode        string
		quotaUsedStr      string
		quotaLimitStr     sql.NullString
		priceCents        int64
		rentCommissionBPS int
		sellerID          int64
		buyerID           int64
	)
	err := tx.QueryRowContext(ctx, `UPDATE berth_marketplace_orders
 SET quota_used_usd=quota_used_usd+$1::numeric,
     quota_reserved_usd=GREATEST(0,quota_reserved_usd-$2::numeric)
 WHERE id=$3
 RETURNING status,rental_mode,quota_used_usd::text,quota_limit_usd::text,price_cents,rent_commission_bps,seller_id,buyer_id`,
		cmd.MarketplaceQuotaCost, releasedReservedStr, m.OrderID).Scan(
		&status, &rentalMode, &quotaUsedStr, &quotaLimitStr,
		&priceCents, &rentCommissionBPS, &sellerID, &buyerID,
	)
	if err != nil {
		return err
	}

	if cmd.MarketplaceQuotaCost > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO berth_marketplace_order_usage
 (order_id,request_id,api_key_id,buyer_id,seller_id,account_id,group_id,amount_usd,quota_used_after_usd,admitted_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10)`,
			m.OrderID, cmd.RequestID, cmd.APIKeyID, buyerID, sellerID, cmd.AccountID, m.GroupID,
			cmd.MarketplaceQuotaCost, quotaUsedStr, m.AdmittedAt); err != nil {
			return err
		}
	}

	if status != "active" || !quotaLimitStr.Valid {
		return nil
	}
	quotaUsedDec, err := decimal.NewFromString(quotaUsedStr)
	if err != nil {
		return err
	}
	quotaLimitDec, err := decimal.NewFromString(quotaLimitStr.String)
	if err != nil {
		return err
	}
	if !quotaLimitDec.IsPositive() || quotaUsedDec.LessThan(quotaLimitDec) {
		return nil
	}

	if rentCommissionBPS < 0 {
		rentCommissionBPS = 0
	}
	if rentCommissionBPS > 10000 {
		rentCommissionBPS = 10000
	}
	hi, lo := bits.Mul64(uint64(priceCents), uint64(rentCommissionBPS))
	commQ, _ := bits.Div64(hi, lo, 10000)
	commission := int64(commQ)
	earned := priceCents - commission

	if _, err := tx.ExecContext(ctx, "UPDATE users SET balance=balance+$1::numeric/100,updated_at=clock_timestamp() WHERE id=$2", earned, sellerID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO berth_marketplace_ledger(order_id,user_id,kind,amount_cents) VALUES($1,$2,'payout',$3),($1,$4,'refund',0)`, m.OrderID, sellerID, earned, buyerID); err != nil {
		return err
	}
	if commission > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO berth_marketplace_ledger(order_id,kind,amount_cents) VALUES($1,'platform_commission',$2)`, m.OrderID, commission); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE berth_marketplace_quota_reservations SET status='released',updated_at=clock_timestamp() WHERE order_id=$1 AND status='reserved'`, m.OrderID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE berth_marketplace_orders
 SET status='completed',completion_reason='quota_exhausted',seller_earned_cents=$2,refund_cents=0,platform_commission_cents=$3,quota_reserved_usd=0,settled_at=clock_timestamp()
 WHERE id=$1`, m.OrderID, earned, commission); err != nil {
		return err
	}

	result.MarketplaceQuotaExhausted = true
	result.MarketplaceSellerID = sellerID
	result.MarketplaceSettledOrderID = m.OrderID
	return nil
}
