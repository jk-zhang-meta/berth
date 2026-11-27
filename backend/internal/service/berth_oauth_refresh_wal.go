package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"
)

const (
	RefreshJournalStagePending            = "pending"
	RefreshJournalStageCommitted          = "committed"
	RefreshJournalStagePreSendAborted     = "pre_send_aborted"
	RefreshJournalStageUnknownQuarantined = "unknown_quarantined"

	refreshWALPersistTimeout      = 10 * time.Second
	refreshWALMinCooldown         = 5 * time.Second
	refreshWALMaxCooldown         = 5 * time.Minute
	refreshWALStalePendingTimeout = 90 * time.Second
)

var (
	// ErrRefreshPreSend marks an error proven to have occurred BEFORE any TCP connect succeeded.
	ErrRefreshPreSend = errors.New("oauth refresh aborted before TCP connect")
	// ErrRefreshOutcomeUnknownQuarantined indicates an ambiguous post-connect failure
	// where upstream may already have rotated the single-use refresh token.
	// Callers MUST NOT retry with the old refresh_token.
	ErrRefreshOutcomeUnknownQuarantined = errors.New("oauth refresh outcome unknown; quarantined to prevent token reuse ban")
	// ErrRefreshInFlight indicates another worker owns a pending WAL entry for this token.
	ErrRefreshInFlight = errors.New("oauth refresh already pending in WAL journal")
	// ErrRefreshRateLimitedCooldown indicates a per-token Retry-After cooldown is active.
	ErrRefreshRateLimitedCooldown = errors.New("oauth refresh in per-token retry-after cooldown")
	// ErrRefreshCredentialVersionConflict indicates optimistic CAS conflict on account_cages.credential_version.
	ErrRefreshCredentialVersionConflict = errors.New("oauth refresh credential_version CAS conflict")
)

// RefreshCooldownError wraps a clean upstream non-rotating rate-limit/503 response
// carrying an optional Retry-After duration (clamped to [5s, 5m]).
type RefreshCooldownError struct {
	RetryAfter time.Duration
	Err        error
}

func (e *RefreshCooldownError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("oauth refresh rate-limited (retry after %s): %v", e.RetryAfter, e.Err)
	}
	return fmt.Sprintf("oauth refresh rate-limited (retry after %s)", e.RetryAfter)
}

func (e *RefreshCooldownError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ComputeRefreshTokenFingerprint computes SHA256(clientID + "\x00" + refreshToken) as 64 lowercase hex.
func ComputeRefreshTokenFingerprint(clientID, refreshToken string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(strings.TrimSpace(clientID)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(refreshToken)))
	return hex.EncodeToString(h.Sum(nil))
}

// RefreshTraceTracker records low-level httptrace events during a single upstream
// OAuth refresh call so the WAL engine can prove whether TCP connect succeeded.
//
// Codex Review Blocker Gate: ONLY transport-proven pre-connect dial failures
// (!Connected()) may transition a pending WAL entry to `pre_send_aborted`.
// Any failure once TCP connect succeeds (EOF, timeout, reset, TLS/write/decode error)
// MUST transition to `unknown_quarantined`.
type RefreshTraceTracker struct {
	connectAttempted atomic.Bool
	connected        atomic.Bool
	wroteRequest     atomic.Bool
	gotFirstByte     atomic.Bool
}

// NewRefreshTraceTracker creates a tracker and attaches an httptrace.ClientTrace to ctx.
func NewRefreshTraceTracker(ctx context.Context) (context.Context, *RefreshTraceTracker) {
	tracker := &RefreshTraceTracker{}
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) {
			tracker.connectAttempted.Store(true)
		},
		ConnectDone: func(_, _ string, err error) {
			tracker.connectAttempted.Store(true)
			if err == nil {
				tracker.connected.Store(true)
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			// A reused pooled connection means TCP is already connected!
			if info.Conn != nil {
				tracker.connected.Store(true)
			}
		},
		WroteHeaders: func() {
			tracker.connected.Store(true)
		},
		WroteRequest: func(_ httptrace.WroteRequestInfo) {
			tracker.connected.Store(true)
			tracker.wroteRequest.Store(true)
		},
		GotFirstResponseByte: func() {
			tracker.connected.Store(true)
			tracker.gotFirstByte.Store(true)
		},
	}
	return httptrace.WithClientTrace(ctx, trace), tracker
}

// Connected reports whether any TCP connection succeeded (or a pooled socket was acquired).
func (t *RefreshTraceTracker) Connected() bool {
	return t != nil && t.connected.Load()
}

// WroteRequest reports whether httptrace observed WroteRequest.
func (t *RefreshTraceTracker) WroteRequest() bool {
	return t != nil && t.wroteRequest.Load()
}

// MarkConnected manually marks the attempt as post-connect (used by custom transports/tests).
func (t *RefreshTraceTracker) MarkConnected() {
	if t != nil {
		t.connected.Store(true)
	}
}

// IsProvenPreConnectError returns true ONLY when the tracker confirms no TCP connect
// succeeded AND the error itself is a transport-proven pre-connect dial/proxy error
// (or explicitly wrapped with ErrRefreshPreSend).
func IsProvenPreConnectError(tracker *RefreshTraceTracker, err error) bool {
	if err == nil {
		return false
	}
	// If TCP connect succeeded (or a pooled conn was acquired), it is NEVER pre-connect.
	if tracker != nil && tracker.Connected() {
		return false
	}
	if errors.Is(err, ErrRefreshPreSend) {
		return true
	}
	// If httptrace observed ConnectStart without ConnectDone(nil), verify the error is a net dial/DNS error.
	if tracker != nil && tracker.connectAttempted.Load() && !tracker.Connected() {
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			return true
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			return true
		}
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			if errors.As(urlErr.Err, &opErr) && opErr.Op == "dial" {
				return true
			}
			if errors.As(urlErr.Err, &dnsErr) {
				return true
			}
		}
	}
	return false
}

// OAuthRefreshJournalEntry mirrors a row in `oauth_refresh_journal`.
type OAuthRefreshJournalEntry struct {
	ID                    int64
	AccountID             int64
	CageID                int64
	Platform              string
	TokenFingerprint      string
	AttemptID             string
	Stage                 string
	BaseCredentialVersion int64
	NewCredentialVersion  *int64
	NewTokenFingerprint   string
	ErrorClass            string
	ErrorDetail           string
	RetryAfterUntil       *time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// CommitRefreshTxInput contains all data persisted atomically in a single transaction
// under context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second).
type CommitRefreshTxInput struct {
	JournalID             int64
	AccountID             int64
	CageID                int64
	BaseCredentialVersion int64
	NewCredentials        map[string]any
	NewTokenFingerprint   string
}

// OAuthRefreshWALStore is the durable persistence contract backing BerthOAuthRefreshWAL.
type OAuthRefreshWALStore interface {
	LoadActiveCageForAccount(ctx context.Context, accountID int64) (cageID int64, credentialVersion int64, err error)
	FindLatestByTokenFingerprint(ctx context.Context, platform, tokenFingerprint string) (*OAuthRefreshJournalEntry, error)
	InsertPending(ctx context.Context, entry *OAuthRefreshJournalEntry) (int64, error)
	MarkPreSendAborted(ctx context.Context, journalID int64, errClass, errDetail string, retryAfter *time.Time) error
	MarkUnknownQuarantined(ctx context.Context, journalID, cageID int64, errClass, errDetail string) error
	CommitRefreshTx(ctx context.Context, in CommitRefreshTxInput) (newVersion int64, applied bool, err error)
}

// PostgresOAuthRefreshWALStore implements OAuthRefreshWALStore using PostgreSQL `*sql.DB`.
type PostgresOAuthRefreshWALStore struct {
	db *sql.DB
}

// NewPostgresOAuthRefreshWALStore creates a PostgreSQL-backed WAL journal store.
func NewPostgresOAuthRefreshWALStore(db *sql.DB) *PostgresOAuthRefreshWALStore {
	return &PostgresOAuthRefreshWALStore{db: db}
}

func (s *PostgresOAuthRefreshWALStore) LoadActiveCageForAccount(ctx context.Context, accountID int64) (int64, int64, error) {
	var cageID, credVer int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, credential_version
		  FROM account_cages
		 WHERE account_id = $1 AND deleted_at IS NULL
	`, accountID).Scan(&cageID, &credVer)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrCageNotFound
	}
	if err != nil {
		return 0, 0, err
	}
	return cageID, credVer, nil
}

func (s *PostgresOAuthRefreshWALStore) FindLatestByTokenFingerprint(ctx context.Context, platform, tokenFingerprint string) (*OAuthRefreshJournalEntry, error) {
	var e OAuthRefreshJournalEntry
	var newVer sql.NullInt64
	var newFP, errClass, errDetail sql.NullString
	var retryUntil sql.NullTime

	err := s.db.QueryRowContext(ctx, `
		SELECT id, account_id, cage_id, platform, token_fingerprint, attempt_id::text,
		       stage, base_credential_version, new_credential_version, new_token_fingerprint,
		       error_class, error_detail, retry_after_until, created_at, updated_at
		  FROM oauth_refresh_journal
		 WHERE platform = $1 AND token_fingerprint = $2
		 ORDER BY id DESC
		 LIMIT 1
	`, platform, tokenFingerprint).Scan(
		&e.ID, &e.AccountID, &e.CageID, &e.Platform, &e.TokenFingerprint, &e.AttemptID,
		&e.Stage, &e.BaseCredentialVersion, &newVer, &newFP,
		&errClass, &errDetail, &retryUntil, &e.CreatedAt, &e.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if newVer.Valid {
		v := newVer.Int64
		e.NewCredentialVersion = &v
	}
	e.NewTokenFingerprint = newFP.String
	e.ErrorClass = errClass.String
	e.ErrorDetail = errDetail.String
	if retryUntil.Valid {
		t := retryUntil.Time
		e.RetryAfterUntil = &t
	}
	return &e, nil
}

func (s *PostgresOAuthRefreshWALStore) InsertPending(ctx context.Context, entry *OAuthRefreshJournalEntry) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO oauth_refresh_journal (
			account_id, cage_id, platform, token_fingerprint, attempt_id,
			stage, base_credential_version
		) VALUES ($1, $2, $3, $4, $5::uuid, 'pending', $6)
		RETURNING id
	`, entry.AccountID, entry.CageID, entry.Platform, entry.TokenFingerprint, entry.AttemptID, entry.BaseCredentialVersion).Scan(&id)
	if err != nil {
		// Unique partial index violation (PG 23505) means another worker already owns pending/quarantined entry.
		if strings.Contains(err.Error(), "uq_oauth_rj_active_token") || strings.Contains(err.Error(), "23505") {
			return 0, fmt.Errorf("%w: %v", ErrRefreshInFlight, err)
		}
		return 0, err
	}
	return id, nil
}

func (s *PostgresOAuthRefreshWALStore) MarkPreSendAborted(ctx context.Context, journalID int64, errClass, errDetail string, retryAfter *time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE oauth_refresh_journal
		   SET stage = 'pre_send_aborted',
		       error_class = $2,
		       error_detail = $3,
		       retry_after_until = $4,
		       updated_at = NOW()
		 WHERE id = $1 AND stage = 'pending'
	`, journalID, errClass, errDetail, retryAfter)
	return err
}

func (s *PostgresOAuthRefreshWALStore) MarkUnknownQuarantined(ctx context.Context, journalID, cageID int64, errClass, errDetail string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		UPDATE oauth_refresh_journal
		   SET stage = 'unknown_quarantined',
		       error_class = $2,
		       error_detail = $3,
		       updated_at = NOW()
		 WHERE id = $1 AND stage = 'pending'
	`, journalID, errClass, errDetail); err != nil {
		return err
	}

	if cageID > 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE account_cages
			   SET gate_state = 'quarantined',
			       gate_epoch = gate_epoch + 1,
			       lease_expires_at = NULL,
			       last_error = $2
			 WHERE id = $1 AND deleted_at IS NULL
		`, cageID, "oauth_refresh_unknown_quarantined: "+errDetail); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// CommitRefreshTx atomically persists rotated credentials + account_cages.credential_version CAS
// + oauth_refresh_journal stage='committed' inside ONE PostgreSQL transaction.
func (s *PostgresOAuthRefreshWALStore) CommitRefreshTx(ctx context.Context, in CommitRefreshTxInput) (int64, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback() }()

	var newVersion int64
	err = tx.QueryRowContext(ctx, `
		UPDATE account_cages
		   SET credential_version = credential_version + 1,
		       updated_at = NOW()
		 WHERE id = $1 AND credential_version = $2 AND deleted_at IS NULL
		 RETURNING credential_version
	`, in.CageID, in.BaseCredentialVersion).Scan(&newVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("cas account_cages credential_version: %w", err)
	}

	credsJSON, err := json.Marshal(in.NewCredentials)
	if err != nil {
		return 0, false, fmt.Errorf("marshal refreshed credentials: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE accounts
		   SET credentials = $2::jsonb,
		       updated_at = NOW()
		 WHERE id = $1
	`, in.AccountID, string(credsJSON)); err != nil {
		return 0, false, fmt.Errorf("update account credentials in wal tx: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE oauth_refresh_journal
		   SET stage = 'committed',
		       new_credential_version = $2,
		       new_token_fingerprint = $3,
		       updated_at = NOW()
		 WHERE id = $1 AND stage = 'pending'
	`, in.JournalID, newVersion, nullableHex64(in.NewTokenFingerprint)); err != nil {
		return 0, false, fmt.Errorf("commit oauth_refresh_journal: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return newVersion, true, nil
}

func nullableHex64(v string) any {
	if len(v) == 64 {
		return v
	}
	return nil
}

// WALRefreshRequest describes one guarded OAuth token refresh attempt.
type WALRefreshRequest struct {
	AccountID    int64
	Platform     string
	ClientID     string
	RefreshToken string
}

// WALRefreshResult returns the outcome of a WAL-guarded refresh attempt.
type WALRefreshResult struct {
	AlreadyCommitted     bool
	Committed            bool
	JournalID            int64
	NewCredentialVersion int64
	NewCredentials       map[string]any
}

// WALRefreshFunc performs the actual single upstream OAuth refresh request using tracedCtx.
type WALRefreshFunc func(tracedCtx context.Context, tracker *RefreshTraceTracker) (map[string]any, error)

// BerthOAuthRefreshWAL coordinates rotating OAuth refresh tokens with a DB-backed
// Write-Ahead Log (`oauth_refresh_journal`), per-process singleflight, httptrace
// pre-connect vs post-connect ambiguity classification, and detached 10s transactional CAS commits.
type BerthOAuthRefreshWAL struct {
	store       OAuthRefreshWALStore
	cageService *BerthAccountCageService
	flight      singleflight.Group
	nowFn       func() time.Time
}

// NewBerthOAuthRefreshWAL creates a WAL refresh coordinator.
func NewBerthOAuthRefreshWAL(store OAuthRefreshWALStore, cageService *BerthAccountCageService) *BerthOAuthRefreshWAL {
	return &BerthOAuthRefreshWAL{
		store:       store,
		cageService: cageService,
		nowFn:       time.Now,
	}
}

func (w *BerthOAuthRefreshWAL) now() time.Time {
	if w != nil && w.nowFn != nil {
		return w.nowFn()
	}
	return time.Now()
}

// ExecuteRefresh executes fn strictly under per-process singleflight + DB WAL fencing.
func (w *BerthOAuthRefreshWAL) ExecuteRefresh(
	ctx context.Context,
	req WALRefreshRequest,
	fn WALRefreshFunc,
) (*WALRefreshResult, error) {
	if w == nil || w.store == nil {
		return nil, errors.New("oauth refresh WAL store is not configured")
	}
	if fn == nil {
		return nil, errors.New("oauth refresh callback is nil")
	}
	if req.AccountID <= 0 || strings.TrimSpace(req.RefreshToken) == "" {
		return nil, errors.New("account_id and refresh_token are required for WAL refresh")
	}

	flightKey := req.Platform + ":" + strconv.FormatInt(req.AccountID, 10)
	rawRes, err, _ := w.flight.Do(flightKey, func() (any, error) {
		return w.executeSingleFlight(ctx, req, fn)
	})
	if err != nil {
		return nil, err
	}
	return rawRes.(*WALRefreshResult), nil
}

func (w *BerthOAuthRefreshWAL) executeSingleFlight(
	ctx context.Context,
	req WALRefreshRequest,
	fn WALRefreshFunc,
) (*WALRefreshResult, error) {
	cageID, baseCredVer, err := w.store.LoadActiveCageForAccount(ctx, req.AccountID)
	if err != nil {
		return nil, err
	}

	tokenFP := ComputeRefreshTokenFingerprint(req.ClientID, req.RefreshToken)

	// Step 1: Consult WAL journal BEFORE dialing.
	latest, err := w.store.FindLatestByTokenFingerprint(ctx, req.Platform, tokenFP)
	if err != nil {
		return nil, fmt.Errorf("read oauth_refresh_journal: %w", err)
	}
	if latest != nil {
		switch latest.Stage {
		case RefreshJournalStageCommitted:
			// Distinguish retained non-rotating refresh tokens (e.g. Gemini/Google, where
			// upstream keeps returning the same refresh_token) from already-rotated ones.
			// When a single-use refresh token was already rotated away (NewTokenFingerprint != tokenFP),
			// late callers presenting the old token MUST follow the committed receipt and NEVER
			// re-dial upstream — even after credential_version has already advanced in the DB.
			retainedSameToken := latest.NewTokenFingerprint != "" &&
				latest.NewTokenFingerprint == tokenFP &&
				(latest.NewCredentialVersion == nil || *latest.NewCredentialVersion == baseCredVer)
			if !retainedSameToken {
				// Another worker already rotated this exact refresh_token; caller should reload DB.
				res := &WALRefreshResult{
					AlreadyCommitted: true,
					JournalID:        latest.ID,
				}
				if latest.NewCredentialVersion != nil {
					res.NewCredentialVersion = *latest.NewCredentialVersion
				}
				return res, nil
			}
		case RefreshJournalStageUnknownQuarantined:
			if latest.BaseCredentialVersion == baseCredVer {
				return nil, fmt.Errorf("%w: journal_id=%d", ErrRefreshOutcomeUnknownQuarantined, latest.ID)
			}
		case RefreshJournalStagePending:
			refTime := latest.UpdatedAt
			if refTime.IsZero() {
				refTime = latest.CreatedAt
			}
			if !refTime.IsZero() && w.now().Sub(refTime) > refreshWALStalePendingTimeout {
				// Abandoned pending WAL row (e.g. crashed worker process): transition safely
				// to unknown_quarantined instead of leaving the account permanently stuck in_flight.
				persistCtx, persistCancel := context.WithTimeout(context.WithoutCancel(ctx), refreshWALPersistTimeout)
				_ = w.store.MarkUnknownQuarantined(persistCtx, latest.ID, cageID, "stale_pending_abandoned", "pending refresh timed out without completion")
				persistCancel()
				if w.cageService != nil && cageID > 0 {
					w.cageService.LiveGate(cageID).Quarantine("oauth_refresh_stale_pending")
				}
				return nil, fmt.Errorf("%w: abandoned pending journal_id=%d", ErrRefreshOutcomeUnknownQuarantined, latest.ID)
			}
			return nil, fmt.Errorf("%w: journal_id=%d", ErrRefreshInFlight, latest.ID)
		case RefreshJournalStagePreSendAborted:
			if latest.RetryAfterUntil != nil && latest.RetryAfterUntil.After(w.now()) {
				return nil, fmt.Errorf("%w: until %s", ErrRefreshRateLimitedCooldown, latest.RetryAfterUntil.UTC().Format(time.RFC3339))
			}
		}
	}

	// Step 2: Persist stage='pending' BEFORE dialing (enforced by unique partial index).
	pendingEntry := &OAuthRefreshJournalEntry{
		AccountID:             req.AccountID,
		CageID:                cageID,
		Platform:              req.Platform,
		TokenFingerprint:      tokenFP,
		AttemptID:             uuid.NewString(),
		Stage:                 RefreshJournalStagePending,
		BaseCredentialVersion: baseCredVer,
	}
	journalID, err := w.store.InsertPending(ctx, pendingEntry)
	if err != nil {
		return nil, err
	}

	// Step 3: Execute upstream refresh with httptrace pre-connect vs post-connect tracking.
	tracedCtx, tracker := NewRefreshTraceTracker(ctx)
	newCreds, refreshErr := fn(tracedCtx, tracker)

	// Detached bounded persistence context (10s) so caller cancellation NEVER drops a rotated token
	// or leaves a journal row stuck in pending.
	persistBase := context.Background()
	if ctx != nil {
		persistBase = context.WithoutCancel(ctx)
	}
	persistCtx, persistCancel := context.WithTimeout(persistBase, refreshWALPersistTimeout)
	defer persistCancel()

	// Step 4A: Failure path — classify strictly!
	if refreshErr != nil {
		// Case 1: Clean non-rotating rate limit cooldown (e.g. HTTP 429/503 with Retry-After).
		var cooldownErr *RefreshCooldownError
		if errors.As(refreshErr, &cooldownErr) {
			wait := clampRefreshCooldown(cooldownErr.RetryAfter)
			until := w.now().Add(wait)
			_ = w.store.MarkPreSendAborted(persistCtx, journalID, "rate_limited", cooldownErr.Error(), &until)
			return nil, refreshErr
		}

		// Case 2: Transport-proven pre-connect dial error (TCP connect NEVER succeeded).
		if IsProvenPreConnectError(tracker, refreshErr) {
			_ = w.store.MarkPreSendAborted(persistCtx, journalID, "pre_send", refreshErr.Error(), nil)
			return nil, refreshErr
		}

		// Case 3: ALL post-connect or ambiguous errors -> unknown_quarantined (NEVER retry old RT!).
		_ = w.store.MarkUnknownQuarantined(persistCtx, journalID, cageID, "outcome_unknown", refreshErr.Error())
		if w.cageService != nil && cageID > 0 {
			w.cageService.LiveGate(cageID).Quarantine("oauth_refresh_unknown_quarantined")
		}
		return nil, fmt.Errorf("%w: %v", ErrRefreshOutcomeUnknownQuarantined, refreshErr)
	}

	// Step 4B: Success path — ALWAYS commit credentials + credential_version CAS + journal='committed'
	// inside a single transaction under context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second).
	if newCreds == nil {
		_ = w.store.MarkUnknownQuarantined(persistCtx, journalID, cageID, "outcome_unknown", "refresh returned nil credentials")
		if w.cageService != nil && cageID > 0 {
			w.cageService.LiveGate(cageID).Quarantine("oauth_refresh_nil_credentials")
		}
		return nil, fmt.Errorf("%w: empty credentials returned", ErrRefreshOutcomeUnknownQuarantined)
	}

	credsToCommit := shallowCopyMap(newCreds)
	credsToCommit["_token_version"] = w.now().UnixMilli()

	newRT, _ := credsToCommit["refresh_token"].(string)
	newFP := ""
	if strings.TrimSpace(newRT) != "" {
		newFP = ComputeRefreshTokenFingerprint(req.ClientID, newRT)
	}

	newVersion, applied, commitErr := w.store.CommitRefreshTx(persistCtx, CommitRefreshTxInput{
		JournalID:             journalID,
		AccountID:             req.AccountID,
		CageID:                cageID,
		BaseCredentialVersion: baseCredVer,
		NewCredentials:        credsToCommit,
		NewTokenFingerprint:   newFP,
	})
	if commitErr != nil {
		return nil, fmt.Errorf("wal commit refresh tx: %w", commitErr)
	}
	if !applied {
		return nil, ErrRefreshCredentialVersionConflict
	}

	return &WALRefreshResult{
		Committed:            true,
		JournalID:            journalID,
		NewCredentialVersion: newVersion,
		NewCredentials:       credsToCommit,
	}, nil
}

func clampRefreshCooldown(d time.Duration) time.Duration {
	if d < refreshWALMinCooldown {
		return refreshWALMinCooldown
	}
	if d > refreshWALMaxCooldown {
		return refreshWALMaxCooldown
	}
	return d
}
