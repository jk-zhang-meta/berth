package repository

import (
	"context"
	"database/sql"
	"errors"
	"math"

	"github.com/jk-zhang-meta/berth/internal/service"
)

// Match checkout's account-before-users lock order, including legacy bills
// which could otherwise deadlock with a rental of the same account.
func lockMarketplaceBillingUsers(ctx context.Context, tx *sql.Tx, cmd *service.UsageBillingCommand) error {
	if cmd.AccountQuotaCost > 0 {
		var id int64
		if err := tx.QueryRowContext(ctx, "SELECT id FROM accounts WHERE id=$1 FOR UPDATE", cmd.AccountID).Scan(&id); err != nil {
			return err
		}
	}
	m := cmd.MarketplaceUsage
	if m == nil {
		return nil
	}
	if m.AccountID != cmd.AccountID || m.SellerID <= 0 || m.GroupID <= 0 || m.CommissionBPS < 0 || m.CommissionBPS > 10000 || m.AdmittedAt.IsZero() || math.IsNaN(cmd.BalanceCost) || math.IsInf(cmd.BalanceCost, 0) || cmd.BalanceCost < 0 || cmd.SubscriptionCost > 0 {
		return errors.New("invalid marketplace usage settlement")
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
	if m == nil || m.SellerID == cmd.UserID || cmd.BalanceCost <= 0 {
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
