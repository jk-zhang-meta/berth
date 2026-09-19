package service

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const workSessionLiveWindow = 15 * time.Minute

type workSessionCtxKey struct{}

type WorkSession struct {
	ID                  int64                `json:"id"`
	UserID              int64                `json:"user_id"`
	APIKeyID            *int64               `json:"api_key_id,omitempty"`
	ClientSessionID     string               `json:"client_session_id"`
	Platform            string               `json:"platform"`
	Agent               string               `json:"agent,omitempty"`
	AgsID               string               `json:"ags_id,omitempty"`
	DeviceID            string               `json:"device_id,omitempty"`
	Title               string               `json:"title,omitempty"`
	Description         string               `json:"description,omitempty"`
	CWD                 string               `json:"cwd,omitempty"`
	Host                string               `json:"host,omitempty"`
	Importance          int                  `json:"importance"`
	AssignedAccountID   *int64               `json:"assigned_account_id,omitempty"`
	LastAccountID       *int64               `json:"last_account_id,omitempty"`
	AccountName         string               `json:"account_name,omitempty"`
	AccountPlatform     string               `json:"account_platform,omitempty"`
	Status              string               `json:"status"`
	StartedAt           time.Time            `json:"started_at"`
	EndedAt             *time.Time           `json:"ended_at,omitempty"`
	LastSeenAt          time.Time            `json:"last_seen_at"`
	CreatedAt           time.Time            `json:"created_at"`
	Requests            int64                `json:"requests"`
	InputTokens         int64                `json:"input_tokens"`
	OutputTokens        int64                `json:"output_tokens"`
	CacheReadTokens     int64                `json:"cache_read_tokens"`
	CacheCreationTokens int64                `json:"cache_creation_tokens"`
	TotalTokens         int64                `json:"total_tokens"`
	TotalCost           float64              `json:"total_cost"`
	Queue               []SessionQueueMember `json:"queue"`
}

type SessionQueueMember struct {
	AccountID   int64  `json:"account_id"`
	AccountName string `json:"account_name,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Priority    int    `json:"priority"`
}

type WorkSessionPref struct {
	UserID            int64
	APIKeyID          int64
	ClientSessionID   string
	Platform          string
	AssignedAccountID int64
	QueueAccountIDs   []int64
	Importance        int
	Occupancy         map[int64]int
}

type AgentSessionReport struct {
	DeviceID    string
	AgsID       string
	Agent       string
	CWD         string
	Host        string
	Description string
	StartedAt   *time.Time
	EndedAt     *time.Time
	Status      string
	Accounts    []string
}

type AGSPoolAccount struct {
	ID          int64   `json:"id"`
	Email       string  `json:"email"`
	AccountKey  string  `json:"account_key"`
	Plan        string  `json:"plan"`
	Headroom    float64 `json:"headroom"`
	Assigned    bool    `json:"assigned"`
	Schedulable bool    `json:"schedulable"`
}

type WorkSessionStore struct{ db *sql.DB }

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

func normalizeSessionPlatform(platform string) string {
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform == "" || platform == "composite" {
		return "unknown"
	}
	return platform
}

func platformForAgent(agent string) string {
	switch strings.ToLower(strings.TrimSpace(agent)) {
	case "codex", "openai":
		return PlatformOpenAI
	case "claude", "claude-code", "anthropic":
		return PlatformAnthropic
	default:
		return "unknown"
	}
}

func (s *WorkSessionStore) Prepare(ctx context.Context, userID, apiKeyID int64, clientSessionID, platform string) (context.Context, *WorkSession) {
	if s == nil || userID <= 0 || strings.TrimSpace(clientSessionID) == "" {
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
		if member.Platform == "" || normalizeSessionPlatform(member.Platform) == session.Platform {
			pref.QueueAccountIDs = append(pref.QueueAccountIDs, member.AccountID)
		}
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
			user_id, api_key_id, client_session_id, platform, status,
			started_at, last_seen_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'live', now(), now(), now(), now())
		ON CONFLICT (user_id, platform, client_session_id) WHERE client_session_id <> '' DO UPDATE SET
			api_key_id = COALESCE(EXCLUDED.api_key_id, work_sessions.api_key_id),
			last_seen_at = now(), updated_at = now(), status = 'live', ended_at = NULL
		RETURNING id, user_id, api_key_id, client_session_id, platform,
			COALESCE(agent, ''), COALESCE(ags_id, ''), COALESCE(device_id, ''),
			COALESCE(title, ''), COALESCE(description, ''), COALESCE(cwd, ''), COALESCE(host, ''),
			importance, assigned_account_id, last_account_id, status,
			started_at, ended_at, last_seen_at, created_at
	`, userID, key, clientSessionID, platform)
	return scanWorkSession(row)
}

func (s *WorkSessionStore) ReportAgentSession(ctx context.Context, userID, apiKeyID int64, report AgentSessionReport) (*WorkSession, error) {
	if s == nil || s.db == nil || userID <= 0 {
		return nil, nil
	}
	report.DeviceID = strings.TrimSpace(report.DeviceID)
	report.AgsID = strings.TrimSpace(report.AgsID)
	if report.DeviceID == "" && report.AgsID == "" {
		return nil, fmt.Errorf("device_id or ags_id is required")
	}
	platform := platformForAgent(report.Agent)
	clientID := report.AgsID
	if clientID == "" {
		clientID = report.DeviceID
	}
	status := strings.ToLower(strings.TrimSpace(report.Status))
	if status != "ended" {
		status = "live"
	}
	started := time.Now()
	if report.StartedAt != nil && !report.StartedAt.IsZero() {
		started = *report.StartedAt
	}
	var ended any
	if status == "ended" {
		if report.EndedAt != nil && !report.EndedAt.IsZero() {
			ended = *report.EndedAt
		} else {
			ended = time.Now()
		}
	}
	var apiKey any
	if apiKeyID > 0 {
		apiKey = apiKeyID
	}
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO work_sessions (
			user_id, api_key_id, client_session_id, platform, agent, ags_id, device_id,
			description, cwd, host, status, started_at, ended_at, last_seen_at, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9,$10,$11,$12,$13,now(),now(),now())
		ON CONFLICT (user_id, device_id) WHERE device_id IS NOT NULL AND device_id <> '' DO UPDATE SET
			api_key_id = COALESCE(EXCLUDED.api_key_id, work_sessions.api_key_id),
			client_session_id = CASE WHEN work_sessions.client_session_id = '' THEN EXCLUDED.client_session_id ELSE work_sessions.client_session_id END,
			platform = CASE WHEN EXCLUDED.platform = 'unknown' THEN work_sessions.platform ELSE EXCLUDED.platform END,
			agent = CASE WHEN EXCLUDED.agent = '' THEN work_sessions.agent ELSE EXCLUDED.agent END,
			agS_id = COALESCE(NULLIF(EXCLUDED.ags_id,''), work_sessions.ags_id),
			description = COALESCE(NULLIF(EXCLUDED.description,''), work_sessions.description),
			cwd = COALESCE(NULLIF(EXCLUDED.cwd,''), work_sessions.cwd),
			host = COALESCE(NULLIF(EXCLUDED.host,''), work_sessions.host),
			status = EXCLUDED.status,
			started_at = LEAST(work_sessions.started_at, EXCLUDED.started_at),
			ended_at = CASE WHEN EXCLUDED.status = 'ended' THEN COALESCE(EXCLUDED.ended_at, now()) ELSE NULL END,
			last_seen_at = now(), updated_at = now()
		RETURNING id, user_id, api_key_id, client_session_id, platform,
			COALESCE(agent, ''), COALESCE(ags_id, ''), COALESCE(device_id, ''),
			COALESCE(title, ''), COALESCE(description, ''), COALESCE(cwd, ''), COALESCE(host, ''),
			importance, assigned_account_id, last_account_id, status,
			started_at, ended_at, last_seen_at, created_at
	`, userID, apiKey, clientID, platform, strings.TrimSpace(report.Agent), report.AgsID, report.DeviceID,
		strings.TrimSpace(report.Description), strings.TrimSpace(report.CWD), strings.TrimSpace(report.Host),
		status, started, ended)
	session, err := scanWorkSession(row)
	if err != nil || session == nil {
		return session, err
	}
	if report.Accounts != nil {
		ids := s.resolveAccountSelectors(ctx, userID, report.Accounts)
		if err := s.ReplaceQueue(ctx, session.ID, userID, ids); err != nil {
			return nil, err
		}
		session.Queue = s.Queue(ctx, session.ID)
	}
	return session, nil
}

func (s *WorkSessionStore) UpdateAgentDescription(ctx context.Context, userID int64, deviceID, description string) error {
	if s == nil || s.db == nil || userID <= 0 || strings.TrimSpace(deviceID) == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE work_sessions SET description = $1, last_seen_at = now(), updated_at = now()
		WHERE user_id = $2 AND device_id = $3
	`, strings.TrimSpace(description), userID, strings.TrimSpace(deviceID))
	return err
}

func (s *WorkSessionStore) EndAgentSession(ctx context.Context, userID int64, deviceID string, endedAt time.Time) error {
	if s == nil || s.db == nil || userID <= 0 || strings.TrimSpace(deviceID) == "" {
		return nil
	}
	if endedAt.IsZero() {
		endedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE work_sessions
		SET status = 'ended', ended_at = $1, last_seen_at = $1, updated_at = now()
		WHERE user_id = $2 AND device_id = $3
	`, endedAt, userID, strings.TrimSpace(deviceID))
	return err
}

func (s *WorkSessionStore) BindAccount(ctx context.Context, userID int64, clientSessionID, platform string, accountID int64) {
	if s == nil || s.db == nil || userID <= 0 || accountID <= 0 || strings.TrimSpace(clientSessionID) == "" {
		return
	}
	_, _ = s.db.ExecContext(ctx, `
		UPDATE work_sessions SET last_account_id = $1, last_seen_at = now(), updated_at = now(), status = 'live', ended_at = NULL
		WHERE user_id = $2 AND client_session_id = $3 AND platform = $4
	`, accountID, userID, clientSessionID, normalizeSessionPlatform(platform))
}

func (s *WorkSessionStore) LiveOccupancy(ctx context.Context) map[int64]int {
	out := map[int64]int{}
	if s == nil || s.db == nil {
		return out
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT last_account_id, COUNT(*) FROM work_sessions
		WHERE status='live' AND last_account_id IS NOT NULL AND last_seen_at >= $1
		GROUP BY last_account_id
	`, time.Now().Add(-workSessionLiveWindow))
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n int
		if rows.Scan(&id, &n) == nil {
			out[id] = n
		}
	}
	return out
}

func (s *WorkSessionStore) reconcileStale(ctx context.Context, userID int64) error {
	if s == nil || s.db == nil {
		return nil
	}
	query := `
		UPDATE work_sessions
		SET status = 'ended', ended_at = COALESCE(ended_at, last_seen_at), updated_at = now()
		WHERE status = 'live' AND last_seen_at < $1`
	args := []any{time.Now().Add(-workSessionLiveWindow)}
	if userID > 0 {
		query += ` AND user_id = $2`
		args = append(args, userID)
	}
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func (s *WorkSessionStore) List(ctx context.Context, userID int64) ([]WorkSession, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if err := s.reconcileStale(ctx, userID); err != nil {
		return nil, err
	}
	query := `
		SELECT ws.id, ws.user_id, ws.api_key_id, ws.client_session_id, ws.platform,
		       COALESCE(ws.agent,''), COALESCE(ws.ags_id,''), COALESCE(ws.device_id,''),
		       COALESCE(ws.title,''), COALESCE(ws.description,''), COALESCE(ws.cwd,''), COALESCE(ws.host,''),
		       ws.importance, ws.assigned_account_id, ws.last_account_id,
		       COALESCE(a.name,''), COALESCE(a.platform,''), ws.status,
		       ws.started_at, ws.ended_at, ws.last_seen_at, ws.created_at,
		       COALESCE(u.requests,0), COALESCE(u.input_tokens,0), COALESCE(u.output_tokens,0),
		       COALESCE(u.cache_read_tokens,0), COALESCE(u.cache_creation_tokens,0), COALESCE(u.total_cost,0)
		FROM work_sessions ws
		LEFT JOIN accounts a ON a.id = COALESCE(ws.assigned_account_id, ws.last_account_id) AND a.deleted_at IS NULL
		LEFT JOIN (
			SELECT user_id, session_id, COUNT(*)::bigint requests,
			       COALESCE(SUM(input_tokens),0)::bigint input_tokens,
			       COALESCE(SUM(output_tokens),0)::bigint output_tokens,
			       COALESCE(SUM(cache_read_tokens),0)::bigint cache_read_tokens,
			       COALESCE(SUM(cache_creation_tokens),0)::bigint cache_creation_tokens,
			       COALESCE(SUM(total_cost),0) total_cost
			FROM usage_logs WHERE session_id IS NOT NULL AND session_id <> '' GROUP BY user_id, session_id
		) u ON u.user_id = ws.user_id AND u.session_id = ws.client_session_id`
	args := []any{}
	if userID > 0 {
		query += ` WHERE ws.user_id = $1`
		args = append(args, userID)
	}
	query += ` ORDER BY (ws.status='live') DESC, ws.last_seen_at DESC LIMIT 500`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []WorkSession{}
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
	Description       *string
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

func (s *WorkSessionStore) Patch(ctx context.Context, id, userID int64, patch WorkSessionPatch) error {
	if s == nil || s.db == nil || id <= 0 {
		return nil
	}
	query := `UPDATE work_sessions SET updated_at = now()`
	args := []any{}
	push := func(field string, value any) {
		args = append(args, value)
		query += `, ` + field + ` = $` + strconv.Itoa(len(args))
	}
	if patch.Title != nil {
		push("title", strings.TrimSpace(*patch.Title))
	}
	if patch.Description != nil {
		push("description", strings.TrimSpace(*patch.Description))
	}
	if patch.Importance != nil {
		v := *patch.Importance
		if v < 1 {
			v = 1
		}
		if v > 100 {
			v = 100
		}
		push("importance", v)
	}
	if patch.ClearAssignment {
		query += `, assigned_account_id = NULL`
	} else if patch.AssignedAccountID != nil {
		push("assigned_account_id", *patch.AssignedAccountID)
	}
	if patch.Status != nil {
		v := strings.ToLower(strings.TrimSpace(*patch.Status))
		if v == "live" {
			push("status", v)
			query += `, ended_at = NULL`
		} else if v == "ended" {
			push("status", v)
			query += `, ended_at = COALESCE(ended_at, now())`
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

func (s *WorkSessionStore) ListRequests(ctx context.Context, sessionID, userID int64) ([]WorkSessionRequest, error) {
	if s == nil || s.db == nil || sessionID <= 0 {
		return nil, nil
	}
	query := `SELECT ul.id, ul.request_id, ul.model, ul.input_tokens, ul.output_tokens, ul.total_cost, ul.created_at, ul.account_id
		FROM usage_logs ul JOIN work_sessions ws ON ws.user_id=ul.user_id AND ws.client_session_id=ul.session_id
		WHERE ws.id=$1`
	args := []any{sessionID}
	if userID > 0 {
		args = append(args, userID)
		query += ` AND ws.user_id=$2`
	}
	query += ` ORDER BY ul.created_at DESC LIMIT 100`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []WorkSessionRequest{}
	for rows.Next() {
		var item WorkSessionRequest
		if err := rows.Scan(&item.ID, &item.RequestID, &item.Model, &item.InputTokens, &item.OutputTokens, &item.TotalCost, &item.CreatedAt, &item.AccountID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *WorkSessionStore) Queue(ctx context.Context, sessionID int64) []SessionQueueMember {
	if s == nil || s.db == nil || sessionID <= 0 {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT q.account_id,COALESCE(a.name,''),COALESCE(a.platform,''),q.priority
		FROM work_session_queue q LEFT JOIN accounts a ON a.id=q.account_id AND a.deleted_at IS NULL
		WHERE q.session_id=$1 ORDER BY q.priority ASC,q.id ASC`, sessionID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	items := []SessionQueueMember{}
	for rows.Next() {
		var item SessionQueueMember
		if rows.Scan(&item.AccountID, &item.AccountName, &item.Platform, &item.Priority) == nil {
			items = append(items, item)
		}
	}
	return items
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
	q := `SELECT platform FROM work_sessions WHERE id=$1`
	args := []any{sessionID}
	if userID > 0 {
		q += ` AND user_id=$2`
		args = append(args, userID)
	}
	if err := tx.QueryRowContext(ctx, q, args...).Scan(&sessionPlatform); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM work_session_queue WHERE session_id=$1`, sessionID); err != nil {
		return err
	}
	seen := map[int64]struct{}{}
	var first *int64
	for i, id := range accountIDs {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		var platform string
		accountQuery := `SELECT a.platform FROM accounts a WHERE a.id=$1 AND a.deleted_at IS NULL`
		accountArgs := []any{id}
		if userID > 0 {
			accountQuery += ` AND EXISTS (SELECT 1 FROM account_stewards s WHERE s.account_id=a.id AND s.user_id=$2)`
			accountArgs = append(accountArgs, userID)
		}
		if tx.QueryRowContext(ctx, accountQuery, accountArgs...).Scan(&platform) != nil {
			continue
		}
		if normalizeSessionPlatform(sessionPlatform) != "unknown" && normalizeSessionPlatform(platform) != normalizeSessionPlatform(sessionPlatform) {
			continue
		}
		seen[id] = struct{}{}
		if first == nil {
			v := id
			first = &v
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO work_session_queue(session_id,account_id,priority) VALUES($1,$2,$3)`, sessionID, id, (i+1)*10); err != nil {
			return err
		}
	}
	if first == nil {
		_, _ = tx.ExecContext(ctx, `UPDATE work_sessions SET assigned_account_id=NULL,updated_at=now() WHERE id=$1`, sessionID)
	} else {
		_, _ = tx.ExecContext(ctx, `UPDATE work_sessions SET assigned_account_id=$1,updated_at=now() WHERE id=$2`, *first, sessionID)
	}
	return tx.Commit()
}

func (s *WorkSessionStore) resolveAccountSelectors(ctx context.Context, userID int64, selectors []string) []int64 {
	if s == nil || s.db == nil || userID <= 0 {
		return nil
	}
	ids := []int64{}
	seen := map[int64]struct{}{}
	for _, raw := range selectors {
		selector := strings.TrimSpace(raw)
		if selector == "" {
			continue
		}
		var id int64
		err := s.db.QueryRowContext(ctx, `SELECT a.id FROM accounts a JOIN account_stewards s ON s.account_id=a.id
			WHERE s.user_id=$1 AND a.deleted_at IS NULL AND (lower(a.name)=lower($2) OR a.id::text=$2) LIMIT 1`, userID, selector).Scan(&id)
		if err == nil {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
	}
	return ids
}

func (s *WorkSessionStore) ListAGSPoolAccounts(ctx context.Context, userID int64) ([]AGSPoolAccount, error) {
	if s == nil || s.db == nil || userID <= 0 {
		return []AGSPoolAccount{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,a.name,a.platform,a.concurrency,a.status
		FROM accounts a JOIN account_stewards s ON s.account_id=a.id
		WHERE s.user_id=$1 AND a.deleted_at IS NULL ORDER BY a.priority ASC,a.id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	occupancy := s.LiveOccupancy(ctx)
	items := []AGSPoolAccount{}
	for rows.Next() {
		var id int64
		var name, platform, status string
		var concurrency int
		if err := rows.Scan(&id, &name, &platform, &concurrency, &status); err != nil {
			return nil, err
		}
		headroom := 1.0
		if concurrency > 0 {
			used := occupancy[id]
			headroom = float64(concurrency-used) / float64(concurrency)
			if headroom < 0 {
				headroom = 0
			}
		}
		items = append(items, AGSPoolAccount{ID: id, Email: name, AccountKey: strconv.FormatInt(id, 10), Plan: platform, Headroom: headroom, Schedulable: status == StatusActive})
	}
	return items, rows.Err()
}

func (s *WorkSessionStore) ResolveAGSPoolAccounts(ctx context.Context, userID int64, selectors []string) map[string]string {
	out := map[string]string{}
	for _, selector := range selectors {
		selector = strings.TrimSpace(selector)
		if selector == "" {
			continue
		}
		ids := s.resolveAccountSelectors(ctx, userID, []string{selector})
		if len(ids) > 0 {
			out[selector] = "available"
		} else {
			out[selector] = "unknown"
		}
	}
	return out
}

func (s *WorkSessionStore) attachQueues(ctx context.Context, items []WorkSession) {
	for i := range items {
		items[i].Queue = s.Queue(ctx, items[i].ID)
	}
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
		occ := occupancy[id]
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

func workSessionQueueSet(pref *WorkSessionPref) map[int64]struct{} {
	if pref == nil || len(pref.QueueAccountIDs) == 0 {
		return nil
	}
	out := make(map[int64]struct{}, len(pref.QueueAccountIDs))
	for _, id := range pref.QueueAccountIDs {
		out[id] = struct{}{}
	}
	return out
}

type scannable interface{ Scan(dest ...any) error }

func scanWorkSession(row scannable) (*WorkSession, error) {
	var item WorkSession
	var apiKey, assigned, last sql.NullInt64
	var ended sql.NullTime
	err := row.Scan(&item.ID, &item.UserID, &apiKey, &item.ClientSessionID, &item.Platform, &item.Agent, &item.AgsID, &item.DeviceID, &item.Title, &item.Description, &item.CWD, &item.Host, &item.Importance, &assigned, &last, &item.Status, &item.StartedAt, &ended, &item.LastSeenAt, &item.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if apiKey.Valid {
		item.APIKeyID = &apiKey.Int64
	}
	if assigned.Valid {
		item.AssignedAccountID = &assigned.Int64
	}
	if last.Valid {
		item.LastAccountID = &last.Int64
	}
	if ended.Valid {
		item.EndedAt = &ended.Time
	}
	return &item, nil
}

func scanWorkSessionList(row scannable) (WorkSession, error) {
	var item WorkSession
	var apiKey, assigned, last sql.NullInt64
	var ended sql.NullTime
	err := row.Scan(&item.ID, &item.UserID, &apiKey, &item.ClientSessionID, &item.Platform, &item.Agent, &item.AgsID, &item.DeviceID, &item.Title, &item.Description, &item.CWD, &item.Host, &item.Importance, &assigned, &last, &item.AccountName, &item.AccountPlatform, &item.Status, &item.StartedAt, &ended, &item.LastSeenAt, &item.CreatedAt, &item.Requests, &item.InputTokens, &item.OutputTokens, &item.CacheReadTokens, &item.CacheCreationTokens, &item.TotalCost)
	if err != nil {
		return item, err
	}
	if apiKey.Valid {
		item.APIKeyID = &apiKey.Int64
	}
	if assigned.Valid {
		item.AssignedAccountID = &assigned.Int64
	}
	if last.Valid {
		item.LastAccountID = &last.Int64
	}
	if ended.Valid {
		item.EndedAt = &ended.Time
	}
	item.TotalTokens = item.InputTokens + item.OutputTokens + item.CacheReadTokens + item.CacheCreationTokens
	return item, nil
}
