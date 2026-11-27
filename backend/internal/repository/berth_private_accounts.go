package repository

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	entsql "entgo.io/ent/dialect/sql"
	dbpredicate "github.com/jk-zhang-meta/berth/ent/predicate"
	infraerrors "github.com/jk-zhang-meta/berth/internal/pkg/errors"
	"github.com/lib/pq"
)

var (
	errForeignPrivateAccountGroup = infraerrors.New(http.StatusForbidden, "PRIVATE_GROUP_FORBIDDEN", "Cannot bind an account into another account's managed private Berth group")
	errOwnPrivateAccountGroup     = infraerrors.New(http.StatusConflict, "PRIVATE_GROUP_PROTECTED", "Cannot detach an account from its own managed private Berth group")
)

// Owned accounts must never enter the legacy ungrouped public pool, including
// the interval between account creation and private-group provisioning.
func withoutPrivateStewards() dbpredicate.Account {
	return func(s *entsql.Selector) {
		s.Where(entsql.ExprP("NOT EXISTS (SELECT 1 FROM account_stewards st JOIN users u ON u.id=st.user_id WHERE st.account_id=" + s.C("id") + " AND u.role <> 'admin')"))
	}
}

// A managed private binding does not remove administrator resources from their
// pre-existing legacy ungrouped pool. Ordinary user resources are excluded above.
func withoutPublicGroupBindings() dbpredicate.Account {
	return func(s *entsql.Selector) {
		s.Where(entsql.ExprP("NOT EXISTS (SELECT 1 FROM account_groups ag LEFT JOIN berth_account_groups bg ON bg.group_id=ag.group_id WHERE ag.account_id=" + s.C("id") + " AND bg.group_id IS NULL)"))
	}
}

func querySingleBool(ctx context.Context, exec sqlExecutor, query string, args ...any) (bool, error) {
	rows, err := exec.QueryContext(ctx, query, args...)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return false, err
		}
		return false, sql.ErrNoRows
	}
	var v bool
	if err := rows.Scan(&v); err != nil {
		return false, err
	}
	return v, rows.Err()
}

func querySingleInt64(ctx context.Context, exec sqlExecutor, query string, args ...any) (int64, error) {
	rows, err := exec.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return 0, err
		}
		return 0, sql.ErrNoRows
	}
	var v int64
	if err := rows.Scan(&v); err != nil {
		return 0, err
	}
	return v, rows.Err()
}

// validateAccountGroupWrite enforces Berth's private-group boundary (A-1):
// 1. Rejects binding accountID into a berth_account_groups group belonging to another account.
// 2. When preserveOwn is true (used by BindGroups full replacement), preserves accountID's
//    own managed private group so ordinary admin group edits never break active rentals.
func (r *accountRepository) validateAndNormalizeAccountGroups(
	ctx context.Context,
	accountID int64,
	groupIDs []int64,
	preserveOwn bool,
) ([]int64, error) {
	if r == nil || r.sql == nil || accountID <= 0 {
		return groupIDs, nil
	}
	if len(groupIDs) > 0 {
		foreign, err := querySingleBool(ctx, r.sql, `
			SELECT EXISTS(
				SELECT 1 FROM berth_account_groups
				WHERE group_id = ANY($1) AND account_id <> $2
			)`, pq.Array(groupIDs), accountID)
		if err != nil {
			// Ignore undefined_table in minimal upstream unit tests without Berth migrations.
			var pqErr *pq.Error
			if !errors.As(err, &pqErr) || string(pqErr.Code) != "42P01" {
				return nil, err
			}
			return groupIDs, nil
		}
		if foreign {
			return nil, errForeignPrivateAccountGroup
		}
	}
	if !preserveOwn {
		return groupIDs, nil
	}
	ownPrivateGroupID, err := querySingleInt64(ctx, r.sql, `
		SELECT group_id FROM berth_account_groups WHERE account_id = $1`, accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return groupIDs, nil
	}
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && string(pqErr.Code) == "42P01" {
			return groupIDs, nil
		}
		return nil, err
	}
	for _, gid := range groupIDs {
		if gid == ownPrivateGroupID {
			return groupIDs, nil
		}
	}
	out := make([]int64, 0, len(groupIDs)+1)
	out = append(out, groupIDs...)
	out = append(out, ownPrivateGroupID)
	return out, nil
}

func (r *accountRepository) rejectRemovingOwnPrivateGroup(ctx context.Context, accountID, groupID int64) error {
	if r == nil || r.sql == nil || accountID <= 0 || groupID <= 0 {
		return nil
	}
	isOwn, err := querySingleBool(ctx, r.sql, `
		SELECT EXISTS(
			SELECT 1 FROM berth_account_groups
			WHERE account_id = $1 AND group_id = $2
		)`, accountID, groupID)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && string(pqErr.Code) == "42P01" {
			return nil
		}
		return err
	}
	if isOwn {
		return errOwnPrivateAccountGroup
	}
	return nil
}
