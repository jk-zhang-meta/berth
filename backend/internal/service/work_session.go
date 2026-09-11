package service

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"
)

const workSessionLiveWindow = 15 * time.Minute

type workSessionCtxKey struct{}

// WorkSession is a durable coding-session identity, independent of sticky hashes.
type WorkSession struct {
	ID                 int64      `json:"id"`
	UserID             int64      `json:"user_id"`
	APIKeyID           *int64     `json:"api_key_id,omitempty"`
	ClientSessionID    string     `json:"client_session_id"`
	Platform           string     `json:"platform"`
	Title              string     `json:"title,omitempty"`
	CWD                string     `json:"cwd,omitempty"`
	Host               string     `json:"host,omitempty"`
	AgsID              string     `json:"ags_id,omitempty"`
	Importance         int        `json:"importance"`
	AssignedAccountID  *int64     `json:"assigned_account_id,omitempty"`
	LastAccountID      *int64     `json:"last_account_id,omitempty"`
	AccountName        string     `json:"account_name,omitempty"`
	AccountPlatform    string     `json:"account_platform,omitempty"`
	Status             string     `json:"status"`
	LastSeenAt         time.Time  `json:"last_seen_at"`
	CreatedAt          time.Time  `json:"created_at"`
	Requests           int64      `json:"requests"`
	InputTokens        int64      `json:"input_tokens"`
	OutputTokens       int64      `json:"output_tokens"`
	CacheReadTokens    int64      `json:"cache_read_tokens"`
	CacheCreationTokens int64     `json:"cache_creation_tokens"`
	TotalTokens        int64      `json:"total_tokens"`
	TotalCost          float64    `json:"total_cost"`
	Queue              []SessionQueueMember `json:"queue"`
}

type SessionQueueMember struct {
	AccountID   int64  `json:"account_id"`
	AccountName string `json:"account_name,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Priority    int    `json:"priority"`
}

// WorkSessionPref is the scheduling snapshot for one inbound request.
type WorkSessionPref struct {
	UserID            int64
	APIKeyID          int64
	ClientSessionID   string
	Platform          string
	AssignedAccountID int64
	QueueAccountIDs   []int64
	Importance        int
	Occupancy          map[int64]int
	BlockedAccountIDs  map[int64]struct{}
	AllowedAccountIDs  map[int64]struct{}
}

// WorkSessionStore persists work sessions with raw SQL (usage_logs already
// bypasses Ent for session_id). Nil-safe: every method no-ops on a nil store.
type WorkSessionStore struct {
	db *sql.DB
}

func NewWorkSessionStore(db *sql.DB) *WorkSessionStore {
	if db == nil {
		return nil
	}
	return &WorkSessionStore{db: db}
}

func WorkSessionPrefFromContext(ctx context.Context) *WorkSessionPref {
	if ctx == nil {
		return nil
	}
	pref, _ := ctx.Value(workSessionCtxKey{}).(*WorkSessionPref)
	return pref
}

func withWorkSessionPref(ctx context.Context, pref *WorkSessionPref) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if pref == nil {
		return ctx
	}
	return context.WithValue(ctx, workSessionCtxKey{}, pref)
}

func (s *WorkSessionStore) Prepare(ctx context.Context, userID, apiKeyID int64, clientSessionID, platform string) (context.Context, *WorkSession) {
	if s == nil || userID <= 0 {
		return ctx, nil
	}
	clientSessionID = strings.TrimSpace(clientSessionID)
	if clientSessionID == "" {
		return ctx, nil
	}
	session, err := s.Touch(ctx, userID, apiKeyID, clientSessionID, platform)
	if err != nil || session == nil {
		return ctx, nil
	}
	queue := s.Queue(ctx, session.ID)
	session.Queue = queue
	pref := &WorkSessionPref{
		UserID:          userID,
		APIKeyID:        apiKeyID,
		ClientSessionID: clientSessionID,
		Platform:        session.Platform,
		Importance:      session.Importance,
		Occupancy:       s.LiveOccupancy(ctx),
	}
	for _, member := range queue {
		if member.Platform != "" && normalizeSessionPlatform(member.Platform) != session.Platform {
			continue
		}
		pref.QueueAccountIDs = append(pref.QueueAccountIDs, member.AccountID)
	}
	if len(pref.QueueAccountIDs) > 0 {
		pref.AssignedAccountID = pickQueueAccount(pref.QueueAccountIDs, pref.Occupancy, nil)
	} else if session.AssignedAccountID != nil {
		pref.AssignedAccountID = *session.AssignedAccountID
	}
	return withWorkSessionPref(ctx, pref), session
}

func (s *WorkSessionStore) Touch(ctx context.Context, userID, apiKeyID int64, clientSessionID, platform string) (*WorkSession, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	var key any
	if apiKeyID > 0 {
		key = apiKeyID
	}
	platform = normalizeSessionPlatform(platform)
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO work_sessions (
			user_id, api_key_id, client_session_id, platform, last_seen_at, created_at, status
		) VALUES ($1, $2, $3, $4, now(), now(), 'live')
		ON CONFLICT (user_id, platform, client_session_id) DO UPDATE SET
			api_key_id = COALESCE(EXCLUDED.api_key_id, work_sessions.api_key_id),
			last_seen_at = now(),
			status = 'live'
		RETURNING id, user_id, api_key_id, client_session_id, platform, COALESCE(title, ''),
			COALESCE(cwd, ''), COALESCE(host, ''), COALESCE(ags_id, ''), importance, assigned_account_id,
			last_account_id, status, last_seen_at, created_at
	`, userID, key, clientSessionID, platform)
	return scanWorkSession(row)
}

func (s *WorkSessionStore) BindAccount(ctx context.Context, userID int64, clientSessionID, platform string, accountID int64) {
	if s == nil || s.db == nil || userID <= 0 || accountID <= 0 || strings.TrimSpace(clientSessionID) == "" {
		return
	}
	platform = normalizeSessionPlatform(platform)
	_, _ = s.db.ExecContext(ctx, `
		UPDATE work_sessions
		SET last_account_id = $1,
		    last_seen_at = now(),
		    status = 'live'
		WHERE user_id = $2 AND client_session_id = $3 AND platform = $4
	`, accountID, userID, clientSessionID, platform)
}

func normalizeSessionPlatform(platform string) string {
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform == "" || platform == "composite" {
		return "unknown"
	}
	return platform
}

func (s *WorkSessionStore) LiveOccupancy(ctx context.Context) map[int64]int {
	out := map[int64]int{}
	if s == nil || s.db == nil {
		return out
	}
	cutoff := time.Now().Add(-workSessionLiveWindow)
	rows, err := s.db.QueryContext(ctx, `
		SELECT last_account_id, COUNT(*)
		FROM work_sessions
		WHERE status = 'live'
		  AND last_account_id IS NOT NULL
		  AND last_seen_at >= $1
		GROUP BY last_account_id
	`, cutoff)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var accountID int64
		var n int
		if err := rows.Scan(&accountID, &n); err == nil {
			out[accountID] = n
		}
	}
	return out
}

func (s *WorkSessionStore) List(ctx context.Context, userID int64) ([]WorkSession, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	query := `
		SELECT ws.id, ws.user_id, ws.api_key_id, ws.client_session_id, ws.platform,
		       COALESCE(ws.title, ''), COALESCE(ws.cwd, ''), COALESCE(ws.host, ''), COALESCE(ws.ags_id, ''),
		       ws.importance, ws.assigned_account_id, ws.last_account_id,
		       COALESCE(a.name, ''), COALESCE(a.platform, ''),
		       ws.status, ws.last_seen_at, ws.created_at,
		       COALESCE(u.requests, 0), COALESCE(u.input_tokens, 0), COALESCE(u.output_tokens, 0),
		       COALESCE(u.cache_read_tokens, 0), COALESCE(u.cache_creation_tokens, 0),
		       COALESCE(u.total_cost, 0)
		FROM work_sessions ws
		LEFT JOIN accounts a ON a.id = COALESCE(ws.assigned_account_id, ws.last_account_id) AND a.deleted_at IS NULL
		LEFT JOIN (
			SELECT user_id, session_id,
			       COUNT(*)::bigint AS requests,
			       COALESCE(SUM(input_tokens), 0)::bigint AS input_tokens,
			       COALESCE(SUM(output_tokens), 0)::bigint AS output_tokens,
			       COALESCE(SUM(cache_read_tokens), 0)::bigint AS cache_read_tokens,
			       COALESCE(SUM(cache_creation_tokens), 0)::bigint AS cache_creation_tokens,
			       COALESCE(SUM(total_cost), 0) AS total_cost
			FROM usage_logs
			WHERE session_id IS NOT NULL AND session_id <> ''
			GROUP BY user_id, session_id
		) u ON u.user_id = ws.user_id AND u.session_id = ws.client_session_id
	`
	args := []any{}
	if userID > 0 {
		query += ` WHERE ws.user_id = $1`
		args = append(args, userID)
	}
	query += ` ORDER BY ws.last_seen_at DESC LIMIT 200`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []WorkSession
	for rows.Next() {
		item, err := scanWorkSessionList(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	s.attachQueues(ctx, items)
	return items, nil
}

type WorkSessionPatch struct {
	Title             *string
	Importance        *int
	AssignedAccountID *int64
	ClearAssignment   bool
	Status            *string
	CWD               *string
	AgsID             *string
}

type WorkSessionRequest struct {
	ID           int64     `json:"id"`
	RequestID    string    `json:"request_id"`
	Model        string    `json:"model"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	TotalCost    float64   `json:"total_cost"`
	CreatedAt    time.Time `json:"created_at"`
	AccountID    int64     `json:"account_id"`
}

func (s *WorkSessionStore) ListRequests(ctx context.Context, sessionID, userID int64) ([]WorkSessionRequest, error) {
	if s == nil || s.db == nil || sessionID <= 0 {
		return nil, nil
	}
	query := `
		SELECT ul.id, ul.request_id, ul.model, ul.input_tokens, ul.output_tokens,
		       ul.total_cost, ul.created_at, ul.account_id
		FROM usage_logs ul
		JOIN work_sessions ws ON ws.user_id = ul.user_id AND ws.client_session_id = ul.session_id
		WHERE ws.id = $1
	`
	args := []any{sessionID}
	if userID > 0 {
		query += ` AND ws.user_id = $2`
		args = append(args, userID)
	}
	query += ` ORDER BY ul.created_at DESC LIMIT 100`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []WorkSessionRequest
	for rows.Next() {
		var item WorkSessionRequest
		if err := rows.Scan(&item.ID, &item.RequestID, &item.Model, &item.InputTokens, &item.OutputTokens, &item.TotalCost, &item.CreatedAt, &item.AccountID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *WorkSessionStore) Patch(ctx context.Context, id, userID int64, patch WorkSessionPatch) error {
	if s == nil || s.db == nil || id <= 0 {
		return nil
	}
	query := `UPDATE work_sessions SET last_seen_at = last_seen_at`
	args := []any{}
	push := func(expr string, value any) {
		args = append(args, value)
		query += `, ` + expr + ` = $` + strconv.Itoa(len(args))
	}
	if patch.Title != nil {
		push("title", strings.TrimSpace(*patch.Title))
	}
	if patch.Importance != nil {
		imp := *patch.Importance
		if imp < 1 {
			imp = 1
		}
		if imp > 100 {
			imp = 100
		}
		push("importance", imp)
	}
	if patch.ClearAssignment {
		query += `, assigned_account_id = NULL`
	} else if patch.AssignedAccountID != nil {
		push("assigned_account_id", *patch.AssignedAccountID)
	}
	if patch.Status != nil {
		status := strings.TrimSpace(*patch.Status)
		if status == "live" || status == "ended" {
			push("status", status)
		}
	}
	if patch.CWD != nil {
		push("cwd", strings.TrimSpace(*patch.CWD))
	}
	if patch.AgsID != nil {
		push("ags_id", strings.TrimSpace(*patch.AgsID))
	}
	args = append(args, id)
	query += ` WHERE id = $` + strconv.Itoa(len(args))
	if userID > 0 {
		args = append(args, userID)
		query += ` AND user_id = $` + strconv.Itoa(len(args))
	}
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func occupancyPenalty(occupancy int, importance int) float64 {
	penalty := float64(occupancy)
	if importance > 0 && importance <= 20 {
		penalty *= 4
	} else if importance > 0 && importance <= 40 {
		penalty *= 2
	}
	return penalty
}

func scanWorkSession(row *sql.Row) (*WorkSession, error) {
	var item WorkSession
	var apiKeyID, assigned, last sql.NullInt64
	if err := row.Scan(
		&item.ID, &item.UserID, &apiKeyID, &item.ClientSessionID, &item.Platform,
		&item.Title, &item.CWD, &item.Host, &item.AgsID, &item.Importance, &assigned, &last,
		&item.Status, &item.LastSeenAt, &item.CreatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if apiKeyID.Valid {
		item.APIKeyID = &apiKeyID.Int64
	}
	if assigned.Valid {
		item.AssignedAccountID = &assigned.Int64
	}
	if last.Valid {
		item.LastAccountID = &last.Int64
	}
	return &item, nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanWorkSessionList(row scannable) (WorkSession, error) {
	var item WorkSession
	var apiKeyID, assigned, last sql.NullInt64
	err := row.Scan(
		&item.ID, &item.UserID, &apiKeyID, &item.ClientSessionID, &item.Platform,
		&item.Title, &item.CWD, &item.Host, &item.AgsID, &item.Importance, &assigned, &last,
		&item.AccountName, &item.AccountPlatform, &item.Status, &item.LastSeenAt, &item.CreatedAt,
		&item.Requests, &item.InputTokens, &item.OutputTokens, &item.CacheReadTokens,
		&item.CacheCreationTokens, &item.TotalCost,
	)
	if err != nil {
		return item, err
	}
	if apiKeyID.Valid {
		item.APIKeyID = &apiKeyID.Int64
	}
	if assigned.Valid {
		item.AssignedAccountID = &assigned.Int64
	}
	if last.Valid {
		item.LastAccountID = &last.Int64
	}
	item.TotalTokens = item.InputTokens + item.OutputTokens + item.CacheReadTokens + item.CacheCreationTokens
	return item, nil
}

func pickQueueAccount(queue []int64, occupancy map[int64]int, excluded map[int64]struct{}) int64 {
	var best int64
	bestOcc := int(^uint(0) >> 1)
	for _, id := range queue {
		if id <= 0 {
			continue
		}
		if _, skip := excluded[id]; skip {
			continue
		}
		occ := 0
		if occupancy != nil {
			occ = occupancy[id]
		}
		if occ == 0 {
			return id
		}
		if occ < bestOcc {
			best = id
			bestOcc = occ
		}
	}
	return best
}

func (s *WorkSessionStore) Queue(ctx context.Context, sessionID int64) []SessionQueueMember {
	if s == nil || s.db == nil || sessionID <= 0 {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT q.account_id, COALESCE(a.name, ''), COALESCE(a.platform, ''), q.priority
		FROM work_session_queue q
		LEFT JOIN accounts a ON a.id = q.account_id AND a.deleted_at IS NULL
		WHERE q.session_id = $1
		ORDER BY q.priority ASC, q.id ASC
	`, sessionID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var items []SessionQueueMember
	for rows.Next() {
		var item SessionQueueMember
		if err := rows.Scan(&item.AccountID, &item.AccountName, &item.Platform, &item.Priority); err == nil {
			items = append(items, item)
		}
	}
	return items
}

func (s *WorkSessionStore) attachQueues(ctx context.Context, sessions []WorkSession) {
	for i := range sessions {
		sessions[i].Queue = s.Queue(ctx, sessions[i].ID)
		if sessions[i].Queue == nil {
			sessions[i].Queue = []SessionQueueMember{}
		}
	}
}

func (s *WorkSessionStore) ReplaceQueue(ctx context.Context, sessionID, userID int64, accountIDs []int64) error {
	if s == nil || s.db == nil || sessionID <= 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var sessionPlatform string
	q := `SELECT platform FROM work_sessions WHERE id = $1`
	args := []any{sessionID}
	if userID > 0 {
		q += ` AND user_id = $2`
		args = append(args, userID)
	}
	if err := tx.QueryRowContext(ctx, q, args...).Scan(&sessionPlatform); err != nil {
		return err
	}
	sessionPlatform = normalizeSessionPlatform(sessionPlatform)
	if _, err := tx.ExecContext(ctx, `DELETE FROM work_session_queue WHERE session_id = $1`, sessionID); err != nil {
		return err
	}
	seen := map[int64]struct{}{}
	var first *int64
	for i, accountID := range accountIDs {
		if accountID <= 0 {
			continue
		}
		if _, dup := seen[accountID]; dup {
			continue
		}
		var accountPlatform string
		if err := tx.QueryRowContext(ctx, `SELECT platform FROM accounts WHERE id = $1 AND deleted_at IS NULL`, accountID).Scan(&accountPlatform); err != nil {
			continue
		}
		if normalizeSessionPlatform(accountPlatform) != sessionPlatform {
			continue
		}
		seen[accountID] = struct{}{}
		if first == nil {
			id := accountID
			first = &id
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO work_session_queue (session_id, account_id, priority) VALUES ($1, $2, $3)
		`, sessionID, accountID, (i+1)*10); err != nil {
			return err
		}
	}
	if first == nil {
		_, _ = tx.ExecContext(ctx, `UPDATE work_sessions SET assigned_account_id = NULL WHERE id = $1`, sessionID)
	} else {
		_, _ = tx.ExecContext(ctx, `UPDATE work_sessions SET assigned_account_id = $1 WHERE id = $2`, *first, sessionID)
	}
	return tx.Commit()
}
