package service

import (
	"context"

	"github.com/lib/pq"
)

// Release funded proceeds only once the buyer's recorded debt has been paid.
// Partial top-ups keep the unfunded remainder pending, never spendable by seller.
func (s *MarketplaceService) SettleUsageReceivables(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT r.buyer_id FROM berth_marketplace_usage_revenue r
 JOIN users u ON u.id=r.buyer_id WHERE r.funded_amount<r.gross_amount AND u.balance>=0 ORDER BY r.buyer_id LIMIT 100`)
	if err != nil {
		return 0, err
	}
	var buyers []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, err
		}
		buyers = append(buyers, id)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, buyer := range buyers {
		credited, err := s.settleUsageBuyer(ctx, buyer)
		if err != nil {
			return n, err
		}
		n += len(credited)
		if s.OnBalanceChanged != nil {
			for _, id := range credited {
				s.OnBalanceChanged(ctx, id)
			}
		}
	}
	return n, nil
}

func (s *MarketplaceService) settleUsageBuyer(ctx context.Context, buyer int64) ([]int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT seller_id FROM berth_marketplace_usage_revenue WHERE buyer_id=$1 AND funded_amount<gross_amount ORDER BY seller_id LIMIT 100`, buyer)
	if err != nil {
		return nil, err
	}
	ids := []int64{buyer}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	var paid bool
	if err = tx.QueryRowContext(ctx, "SELECT balance>=0 FROM users WHERE id=$1", buyer).Scan(&paid); err != nil {
		return nil, err
	}
	if !paid {
		return nil, nil
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,seller_id,(seller_amount-seller_paid_amount)::text FROM berth_marketplace_usage_revenue
 WHERE buyer_id=$1 AND seller_id=ANY($2) AND funded_amount<gross_amount ORDER BY id LIMIT 500 FOR UPDATE`, buyer, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	type pending struct {
		id, seller int64
		amount     string
	}
	var items []pending
	for rows.Next() {
		var p pending
		if err = rows.Scan(&p.id, &p.seller, &p.amount); err != nil {
			_ = rows.Close()
			return nil, err
		}
		items = append(items, p)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	var credited []int64
	for _, p := range items {
		if _, err = tx.ExecContext(ctx, "UPDATE users SET balance=balance+$2::numeric,updated_at=clock_timestamp() WHERE id=$1", p.seller, p.amount); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE berth_marketplace_usage_revenue SET funded_amount=gross_amount,seller_paid_amount=seller_amount WHERE id=$1", p.id); err != nil {
			return nil, err
		}
		credited = append(credited, p.seller)
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return credited, nil
}
