package service

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type AccountRental struct {
	ID              int64      `json:"id"`
	AccountID       int64      `json:"account_id"`
	AccountName     string     `json:"account_name,omitempty"`
	AccountPlatform string     `json:"account_platform,omitempty"`
	OwnerUserID     int64      `json:"owner_user_id"`
	BorrowerUserID  *int64     `json:"borrower_user_id,omitempty"`
	Status          string     `json:"status"`
	TokenQuota      *int64     `json:"token_quota,omitempty"`
	TokensUsed      int64      `json:"tokens_used"`
	DurationHours   *int       `json:"duration_hours,omitempty"`
	Concurrency     *int       `json:"concurrency,omitempty"`
	Exclusive       bool       `json:"exclusive"`
	Note            string     `json:"note,omitempty"`
	RequestedAt     *time.Time `json:"requested_at,omitempty"`
	StartsAt        *time.Time `json:"starts_at,omitempty"`
	EndsAt          *time.Time `json:"ends_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

type RentalStore struct {
	db *sql.DB
}

func NewRentalStore(db *sql.DB) *RentalStore {
	if db == nil {
		return nil
	}
	return &RentalStore{db: db}
}

func (s *RentalStore) List(ctx context.Context, userID int64, scope string) ([]AccountRental, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	query := `
		SELECT r.id, r.account_id, COALESCE(a.name, ''), COALESCE(a.platform, ''),
		       r.owner_user_id, r.borrower_user_id, r.status, r.token_quota, r.duration_hours,
		       r.concurrency, r.exclusive, COALESCE(r.note, ''), r.requested_at, r.starts_at,
		       r.ends_at, r.created_at
		FROM account_rentals r
		LEFT JOIN accounts a ON a.id = r.account_id AND a.deleted_at IS NULL
	`
	args := []any{}
	switch scope {
	case "market":
		query += ` WHERE r.status = 'listed'`
	case "mine":
		if userID > 0 {
			query += ` WHERE r.owner_user_id = $1 OR r.borrower_user_id = $1`
			args = append(args, userID)
		}
	}
	query += ` ORDER BY r.updated_at DESC LIMIT 200`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []AccountRental
	for rows.Next() {
		item, err := scanRental(rows)
		if err != nil {
			return nil, err
		}
		s.fillUsage(ctx, &item)
		items = append(items, item)
	}
	return items, rows.Err()
}

type CreateRentalInput struct {
	AccountID     int64
	OwnerUserID   int64
	TokenQuota    *int64
	DurationHours *int
	Concurrency   *int
	Exclusive     bool
	Note          string
}

func (s *RentalStore) Create(ctx context.Context, in CreateRentalInput) (*AccountRental, error) {
	if s == nil || s.db == nil || in.AccountID <= 0 || in.OwnerUserID <= 0 {
		return nil, fmt.Errorf("invalid rental")
	}
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO account_rentals (
			account_id, owner_user_id, status, token_quota, duration_hours, concurrency, exclusive, note
		) VALUES ($1,$2,'listed',$3,$4,$5,$6,$7)
		RETURNING id, account_id, owner_user_id, borrower_user_id, status, token_quota, duration_hours,
		          concurrency, exclusive, COALESCE(note, ''), requested_at, starts_at, ends_at, created_at
	`, in.AccountID, in.OwnerUserID, in.TokenQuota, in.DurationHours, in.Concurrency, in.Exclusive, strings.TrimSpace(in.Note))
	item, err := scanRentalReturning(row)
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (s *RentalStore) Request(ctx context.Context, id, borrowerID int64) error {
	if s == nil || s.db == nil || id <= 0 || borrowerID <= 0 {
		return fmt.Errorf("invalid request")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE account_rentals
		SET status = 'active',
		    borrower_user_id = $1,
		    requested_at = now(),
		    starts_at = now(),
		    ends_at = CASE
		        WHEN duration_hours IS NOT NULL AND duration_hours > 0
		        THEN now() + make_interval(hours => duration_hours)
		        ELSE NULL
		    END,
		    updated_at = now()
		WHERE id = $2
		  AND status = 'listed'
		  AND owner_user_id <> $1
		  AND NOT EXISTS (
			SELECT 1 FROM account_rentals x
			WHERE x.account_id = account_rentals.account_id
			  AND x.id <> account_rentals.id
			  AND x.exclusive = TRUE
			  AND x.status = 'active'
			  AND (x.ends_at IS NULL OR x.ends_at > now())
		  )
	`, borrowerID, id)
	return rentalRows(res, err, "rental is not available")
}

func (s *RentalStore) BorrowedAccountIDs(ctx context.Context, userID int64) []int64 {
	if s == nil || s.db == nil || userID <= 0 {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT account_id
		FROM account_rentals
		WHERE borrower_user_id = $1
		  AND status = 'active'
		  AND (ends_at IS NULL OR ends_at > now())
	`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

func (s *RentalStore) ListedAccountIDs(ctx context.Context, userID int64) map[int64]int64 {
	out := map[int64]int64{}
	if s == nil || s.db == nil || userID <= 0 {
		return out
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT account_id, id
		FROM account_rentals
		WHERE owner_user_id = $1 AND status IN ('listed', 'active', 'requested')
	`, userID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var accountID, rentalID int64
		if err := rows.Scan(&accountID, &rentalID); err == nil {
			out[accountID] = rentalID
		}
	}
	return out
}

func (s *RentalStore) Approve(ctx context.Context, id, ownerID int64) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("invalid approve")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE account_rentals
		SET status = 'active',
		    starts_at = now(),
		    ends_at = CASE
		        WHEN duration_hours IS NOT NULL AND duration_hours > 0
		        THEN now() + make_interval(hours => duration_hours)
		        ELSE NULL
		    END,
		    updated_at = now()
		WHERE id = $1 AND owner_user_id = $2 AND status = 'requested' AND borrower_user_id IS NOT NULL
	`, id, ownerID)
	return rentalRows(res, err, "cannot approve rental")
}

func (s *RentalStore) Reject(ctx context.Context, id, ownerID int64) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE account_rentals
		SET status = 'rejected', updated_at = now()
		WHERE id = $1 AND owner_user_id = $2 AND status = 'requested'
	`, id, ownerID)
	return rentalRows(res, err, "cannot reject rental")
}

func (s *RentalStore) Revoke(ctx context.Context, id, ownerID int64) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE account_rentals
		SET status = 'revoked', updated_at = now()
		WHERE id = $1 AND owner_user_id = $2 AND status IN ('active', 'requested', 'listed')
	`, id, ownerID)
	return rentalRows(res, err, "cannot reclaim rental")
}

func (s *RentalStore) BlockedAccounts(ctx context.Context, userID int64) map[int64]struct{} {
	out := map[int64]struct{}{}
	if s == nil || s.db == nil {
		return out
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT account_id
		FROM account_rentals
		WHERE exclusive = TRUE
		  AND status = 'active'
		  AND (ends_at IS NULL OR ends_at > now())
		  AND borrower_user_id IS NOT NULL
		  AND borrower_user_id <> $1
	`, userID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			out[id] = struct{}{}
		}
	}
	return out
}

func (s *RentalStore) fillUsage(ctx context.Context, item *AccountRental) {
	if s == nil || s.db == nil || item == nil || item.BorrowerUserID == nil || item.StartsAt == nil {
		return
	}
	var used sql.NullInt64
	_ = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(input_tokens + output_tokens + cache_read_tokens + cache_creation_tokens), 0)
		FROM usage_logs
		WHERE user_id = $1 AND account_id = $2 AND created_at >= $3
	`, *item.BorrowerUserID, item.AccountID, *item.StartsAt).Scan(&used)
	if used.Valid {
		item.TokensUsed = used.Int64
	}
	if item.TokenQuota != nil && item.TokensUsed >= *item.TokenQuota && item.Status == "active" {
		_, _ = s.db.ExecContext(ctx, `UPDATE account_rentals SET status = 'expired', updated_at = now() WHERE id = $1 AND status = 'active'`, item.ID)
		item.Status = "expired"
	}
}

func rentalRows(res sql.Result, err error, msg string) error {
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func scanRental(row scannable) (AccountRental, error) {
	var item AccountRental
	var borrower sql.NullInt64
	var quota sql.NullInt64
	var hours, conc sql.NullInt64
	var requested, starts, ends sql.NullTime
	err := row.Scan(
		&item.ID, &item.AccountID, &item.AccountName, &item.AccountPlatform,
		&item.OwnerUserID, &borrower, &item.Status, &quota, &hours, &conc,
		&item.Exclusive, &item.Note, &requested, &starts, &ends, &item.CreatedAt,
	)
	if err != nil {
		return item, err
	}
	if borrower.Valid {
		item.BorrowerUserID = &borrower.Int64
	}
	if quota.Valid {
		item.TokenQuota = &quota.Int64
	}
	if hours.Valid {
		h := int(hours.Int64)
		item.DurationHours = &h
	}
	if conc.Valid {
		c := int(conc.Int64)
		item.Concurrency = &c
	}
	if requested.Valid {
		item.RequestedAt = &requested.Time
	}
	if starts.Valid {
		item.StartsAt = &starts.Time
	}
	if ends.Valid {
		item.EndsAt = &ends.Time
	}
	return item, nil
}

func scanRentalReturning(row *sql.Row) (*AccountRental, error) {
	var item AccountRental
	var borrower sql.NullInt64
	var quota sql.NullInt64
	var hours, conc sql.NullInt64
	var requested, starts, ends sql.NullTime
	err := row.Scan(
		&item.ID, &item.AccountID, &item.OwnerUserID, &borrower, &item.Status, &quota, &hours,
		&conc, &item.Exclusive, &item.Note, &requested, &starts, &ends, &item.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if borrower.Valid {
		item.BorrowerUserID = &borrower.Int64
	}
	if quota.Valid {
		item.TokenQuota = &quota.Int64
	}
	if hours.Valid {
		h := int(hours.Int64)
		item.DurationHours = &h
	}
	if conc.Valid {
		c := int(conc.Int64)
		item.Concurrency = &c
	}
	if requested.Valid {
		item.RequestedAt = &requested.Time
	}
	if starts.Valid {
		item.StartsAt = &starts.Time
	}
	if ends.Valid {
		item.EndsAt = &ends.Time
	}
	return &item, nil
}
