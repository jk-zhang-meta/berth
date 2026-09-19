package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func (s *MarketplaceService) EnsureAccountGroup(ctx context.Context, accountID, ownerID int64) (int64, error) {
	if accountID <= 0 || ownerID <= 0 {
		return 0, ErrMarketplaceInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	id, err := s.ensureAccountGroupTx(ctx, tx, accountID, ownerID)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *MarketplaceService) ensureAccountGroupTx(ctx context.Context, tx *sql.Tx, accountID, ownerID int64) (int64, error) {
	var platform string
	var actualOwner int64
	err := tx.QueryRowContext(ctx, `SELECT a.platform,COALESCE((SELECT user_id FROM account_stewards WHERE account_id=a.id),0)
 FROM accounts a WHERE a.id=$1 AND a.deleted_at IS NULL FOR UPDATE OF a`, accountID).Scan(&platform, &actualOwner)
	if err != nil {
		return 0, marketplaceNotFound(err)
	}
	if actualOwner != ownerID || ownerID <= 0 {
		return 0, ErrMarketplaceForbidden
	}
	var groupID, mappedOwner int64
	err = tx.QueryRowContext(ctx, "SELECT group_id,owner_user_id FROM berth_account_groups WHERE account_id=$1", accountID).Scan(&groupID, &mappedOwner)
	created := false
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `INSERT INTO groups(name,description,platform,subscription_type,is_exclusive,status,rate_multiplier)
 VALUES($1,'Private account access managed by Berth',$2,'standard',true,'active',1) RETURNING id`, fmt.Sprintf("Berth account %d", accountID), platform).Scan(&groupID)
		if err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO berth_account_groups(account_id,group_id,owner_user_id) VALUES($1,$2,$3)", accountID, groupID, ownerID); err != nil {
			return 0, err
		}
		created = true
	} else if err != nil {
		return 0, err
	} else if mappedOwner != ownerID {
		return 0, ErrMarketplaceForbidden
	}
	// Append only. Never erase any upstream administrator group assignments.
	result, err := tx.ExecContext(ctx, "INSERT INTO account_groups(account_id,group_id,priority) VALUES($1,$2,50) ON CONFLICT DO NOTHING", accountID, groupID)
	if err != nil {
		return 0, err
	}
	added, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if created || added > 0 {
		// Published in the same transaction; includes group 0 to retire the ungrouped candidate.
		_, err = tx.ExecContext(ctx, `INSERT INTO scheduler_outbox(event_type,account_id,group_id,payload) VALUES('account_groups_changed',$1,NULL,
   jsonb_build_object('group_ids',COALESCE((SELECT jsonb_agg(group_id) FROM account_groups WHERE account_id=$1),'[]'::jsonb)||'[0]'::jsonb))`, accountID)
		if err != nil {
			return 0, err
		}
		if created {
			if _, err = tx.ExecContext(ctx, "INSERT INTO scheduler_outbox(event_type,group_id) VALUES('group_changed',$1)", groupID); err != nil {
				return 0, err
			}
		}
	}
	return groupID, nil
}

func (s *MarketplaceService) GroupAccess(ctx context.Context, userID, groupID int64) (managed, allowed bool, err error) {
	if groupID <= 0 {
		return false, false, nil
	}
	err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM berth_account_groups WHERE group_id=$2),
 EXISTS(SELECT 1 FROM berth_account_groups m JOIN groups g ON g.id=m.group_id JOIN accounts a ON a.id=m.account_id
 JOIN users u ON u.id=$1 WHERE m.group_id=$2 AND g.deleted_at IS NULL AND g.status='active' AND a.deleted_at IS NULL
 AND u.deleted_at IS NULL AND u.status='active' AND (
 u.role='admin' OR (m.owner_user_id=u.id AND EXISTS(SELECT 1 FROM account_stewards st WHERE st.account_id=a.id AND st.user_id=u.id)) OR
 EXISTS(SELECT 1 FROM berth_marketplace_orders o WHERE o.group_id=m.group_id AND o.buyer_id=u.id AND o.status='active' AND o.starts_at<=clock_timestamp() AND o.expires_at>clock_timestamp())))`, userID, groupID).Scan(&managed, &allowed)
	return
}

func (s *MarketplaceService) AccessibleGroupIDs(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT m.group_id FROM berth_account_groups m JOIN groups g ON g.id=m.group_id
 JOIN accounts a ON a.id=m.account_id JOIN users u ON u.id=$1
 WHERE g.deleted_at IS NULL AND g.status='active' AND a.deleted_at IS NULL AND u.deleted_at IS NULL AND u.status='active'
 AND (u.role='admin' OR (m.owner_user_id=u.id AND EXISTS(SELECT 1 FROM account_stewards st WHERE st.account_id=a.id AND st.user_id=u.id)) OR
 EXISTS(SELECT 1 FROM berth_marketplace_orders o WHERE o.group_id=m.group_id AND o.buyer_id=u.id AND o.status='active' AND o.starts_at<=clock_timestamp() AND o.expires_at>clock_timestamp()))
 ORDER BY m.group_id`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *MarketplaceService) CanUseRentalProxy(ctx context.Context, userID, proxyID int64) (bool, error) {
	var allowed bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM berth_marketplace_orders o JOIN proxies p ON p.id=o.rental_proxy_id
 WHERE o.buyer_id=$1 AND o.rental_proxy_id=$2 AND o.resource_type='proxy' AND o.status='active' AND o.starts_at<=clock_timestamp() AND o.expires_at>clock_timestamp()
 AND p.deleted_at IS NULL AND p.status='active' AND p.expires_at>clock_timestamp())`, userID, proxyID).Scan(&allowed)
	return allowed, err
}

// CheckRentalProxy protects lease clones even after accounts have cached a proxy.
func (s *MarketplaceService) CheckRentalProxy(ctx context.Context, proxyID int64) (rental, allowed bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM berth_marketplace_orders WHERE rental_proxy_id=$1),
 EXISTS(SELECT 1 FROM berth_marketplace_orders o JOIN proxies p ON p.id=o.rental_proxy_id
 WHERE o.rental_proxy_id=$1 AND o.status='active' AND o.starts_at<=clock_timestamp() AND o.expires_at>clock_timestamp()
 AND p.status='active' AND p.deleted_at IS NULL AND p.expires_at>clock_timestamp())`, proxyID).Scan(&rental, &allowed)
	return
}

func (s *MarketplaceService) CheckAccountProxy(ctx context.Context, accountID int64) (rental, allowed bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM accounts a JOIN berth_marketplace_orders o ON o.rental_proxy_id=a.proxy_id WHERE a.id=$1),
 EXISTS(SELECT 1 FROM accounts a JOIN berth_marketplace_orders o ON o.rental_proxy_id=a.proxy_id JOIN proxies p ON p.id=a.proxy_id
 WHERE a.id=$1 AND a.deleted_at IS NULL AND o.status='active' AND o.starts_at<=clock_timestamp() AND o.expires_at>clock_timestamp()
 AND p.status='active' AND p.deleted_at IS NULL AND p.expires_at>clock_timestamp())`, accountID).Scan(&rental, &allowed)
	return
}

func (s *MarketplaceService) ResourceOptions(ctx context.Context, userID int64, isAdmin bool) ([]MarketplaceResourceOption, error) {
	if userID <= 0 {
		return nil, ErrMarketplaceForbidden
	}
	rows, err := s.db.QueryContext(ctx, `SELECT 'account',a.id,a.name,a.platform FROM accounts a LEFT JOIN account_stewards st ON st.account_id=a.id
 WHERE a.deleted_at IS NULL AND a.status='active' AND a.schedulable=true AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()) AND ($2 OR st.user_id=$1)
 UNION ALL SELECT 'proxy',p.id,p.name,'' FROM proxies p LEFT JOIN proxy_stewards st ON st.proxy_id=p.id
 WHERE p.deleted_at IS NULL AND p.status='active' AND (p.expires_at IS NULL OR p.expires_at>clock_timestamp()) AND ($2 OR st.user_id=$1)
 AND NULLIF(p.exit_ip,'') IS NOT NULL AND NULLIF(p.exit_timezone,'') IS NOT NULL AND p.exit_checked_at IS NOT NULL
 AND NOT EXISTS(SELECT 1 FROM berth_marketplace_orders o WHERE o.rental_proxy_id=p.id)
 ORDER BY 1,2 LIMIT 500`, userID, isAdmin)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []MarketplaceResourceOption{}
	for rows.Next() {
		var v MarketplaceResourceOption
		if err = rows.Scan(&v.ResourceType, &v.ID, &v.Name, &v.Platform); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
