package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/jk-zhang-meta/berth/internal/service"
)

func startBerthMarketplace(db *sql.DB, market *service.MarketplaceService, standard bool) (func(), error) {
	ctx, cancel := context.WithCancel(context.Background())
	rows, err := db.QueryContext(ctx, `SELECT s.account_id,s.user_id FROM account_stewards s JOIN accounts a ON a.id=s.account_id JOIN users u ON u.id=s.user_id WHERE a.deleted_at IS NULL AND u.deleted_at IS NULL ORDER BY s.account_id`)
	if err != nil {
		cancel()
		return nil, err
	}
	var owned [][2]int64
	for rows.Next() {
		var ids [2]int64
		if err = rows.Scan(&ids[0], &ids[1]); err != nil {
			_ = rows.Close()
			cancel()
			return nil, err
		}
		owned = append(owned, ids)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		cancel()
		return nil, err
	}
	if !standard {
		var count int
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM berth_marketplace_orders WHERE status='active'`).Scan(&count); err != nil {
			cancel()
			return nil, err
		}
		if len(owned) > 0 || count > 0 {
			cancel()
			return nil, fmt.Errorf("personal accounts and marketplace require standard run mode")
		}
		return cancel, nil
	}
	for _, ids := range owned {
		if _, err = market.EnsureAccountGroup(ctx, ids[0], ids[1]); err != nil {
			cancel()
			return nil, fmt.Errorf("provision private account group: %w", err)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			settleCtx, stop := context.WithTimeout(ctx, 30*time.Second)
			_, err := market.SettleDue(settleCtx)
			if err == nil {
				_, err = market.SettleUsageReceivables(settleCtx)
			}
			stop()
			if err != nil && ctx.Err() == nil {
				log.Printf("[Marketplace] settlement retry required: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done }, nil
}
