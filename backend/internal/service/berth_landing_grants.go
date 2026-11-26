package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	infraerrors "github.com/jk-zhang-meta/berth/internal/pkg/errors"
	"github.com/jk-zhang-meta/berth/internal/pkg/edgeproto"
	"github.com/lib/pq"
)

const (
	GrantStatusPending        = "pending"
	GrantStatusActive         = "active"
	GrantStatusPaused         = "paused"
	GrantStatusRevoked        = "revoked"
	GrantStatusRejected       = "rejected"
	GrantStatusExpired        = "expired"
	GrantStatusQuotaExhausted = "quota_exhausted"

	ProxySourceTypeExternal          = "external_proxy"
	ProxySourceTypeEdgeLandingGrant  = "edge_landing_grant"
	ProxySourceTypeMarketplaceRental = "marketplace_rental"

	DefaultGrantSliceBytes int64 = 16 * 1024 * 1024 // 16 MiB disjoint slice cap (Codex Blocker #1.5)
)

var (
	ErrLandingGrantInvalid        = infraerrors.New(http.StatusBadRequest, "LANDING_GRANT_INVALID", "Invalid landing grant request")
	ErrLandingGrantNotFound       = infraerrors.New(http.StatusNotFound, "LANDING_GRANT_NOT_FOUND", "Landing grant not found")
	ErrLandingGrantForbidden      = infraerrors.New(http.StatusForbidden, "LANDING_GRANT_FORBIDDEN", "Landing grant access forbidden")
	ErrLandingGrantQuotaExhausted = infraerrors.New(http.StatusForbidden, "LANDING_GRANT_QUOTA_EXHAUSTED", "Landing grant or node byte quota exhausted")
	ErrLandingGrantExpired        = infraerrors.New(http.StatusForbidden, "LANDING_GRANT_EXPIRED", "Landing grant has expired")
	ErrLandingGrantInactive       = infraerrors.New(http.StatusForbidden, "LANDING_GRANT_INACTIVE", "Landing grant is not active")
	ErrLandingGrantPendingExists  = infraerrors.New(http.StatusConflict, "LANDING_GRANT_PENDING_EXISTS", "A pending application for this landing node already exists")
	ErrLandingGrantNotPending     = infraerrors.New(http.StatusBadRequest, "LANDING_GRANT_NOT_PENDING", "Landing grant is not in pending state")
)

// LandingNodeGrant maps to berth_landing_node_grants with redacted node/proxy summary.
type LandingNodeGrant struct {
	ID               int64      `json:"id"`
	NodeID           int64      `json:"node_id"`
	NodeName         string     `json:"node_name,omitempty"`
	NodeStatus       string     `json:"node_status,omitempty"`
	NodeExitIP       string     `json:"node_exit_ip,omitempty"` // populated for admin views only; redacted for users
	ExitCountryCode  string     `json:"exit_country_code,omitempty"`
	ExitTimezone     string     `json:"exit_timezone,omitempty"`
	ExitLocale       string     `json:"exit_locale,omitempty"`
	GranteeUserID    int64      `json:"grantee_user_id"`
	GranteeEmail     string     `json:"grantee_email,omitempty"`
	GranteeUsername  string     `json:"grantee_username,omitempty"`
	GrantedByAdminID *int64     `json:"granted_by_admin_id,omitempty"`
	ProxyID          *int64     `json:"proxy_id,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	MaxBytes         int64      `json:"max_bytes"`
	UsedBytes        int64      `json:"used_bytes"`
	ReservedBytes    int64      `json:"reserved_bytes"`
	RemainingBytes   int64      `json:"remaining_bytes"` // -1 if unlimited
	MaxAccounts      int        `json:"max_accounts"`
	MaxRPM           int        `json:"max_rpm"`
	MaxConcurrency   int        `json:"max_concurrency"`
	Status           string     `json:"status"`
	Notes            string     `json:"notes"`
	RequestReason    string     `json:"request_reason,omitempty"`
	ReviewNote       string     `json:"review_note,omitempty"`
	ReviewedAt       *time.Time `json:"reviewed_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// AvailableLandingNode is a strictly redacted landing node summary shown to normal users
// when applying for landing access (never exposes raw exit IP, public address, or keys).
type AvailableLandingNode struct {
	ID                int64  `json:"id"`
	Name              string `json:"name"`
	ExitCountryCode   string `json:"exit_country_code"`
	ExitTimezone      string `json:"exit_timezone"`
	ExitLocale        string `json:"exit_locale"`
	Status            string `json:"status"`
	HasActiveGrant    bool   `json:"has_active_grant"`
	HasPendingRequest bool   `json:"has_pending_request"`
}

// ApplyLandingGrantInput carries a normal user's application for a landing node.
type ApplyLandingGrantInput struct {
	NodeID        int64  `json:"node_id"`
	GranteeUserID int64  `json:"-"`
	RequestReason string `json:"request_reason"`
	MaxAccounts   int    `json:"max_accounts"`
	MaxBytes      int64  `json:"max_bytes"`
}

// ApproveLandingGrantInput carries admin parameters when approving a pending application.
type ApproveLandingGrantInput struct {
	GrantID        int64      `json:"-"`
	AdminID        int64      `json:"-"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	MaxBytes       *int64     `json:"max_bytes,omitempty"`
	MaxAccounts    *int       `json:"max_accounts,omitempty"`
	MaxRPM         *int       `json:"max_rpm,omitempty"`
	MaxConcurrency *int       `json:"max_concurrency,omitempty"`
	ReviewNote     string     `json:"review_note"`
	Notes          string     `json:"notes"`
}

func (g *LandingNodeGrant) computeRemaining() {
	if g.MaxBytes <= 0 {
		g.RemainingBytes = -1
		return
	}
	rem := g.MaxBytes - g.UsedBytes - g.ReservedBytes
	if rem < 0 {
		rem = 0
	}
	g.RemainingBytes = rem
}

// CreateLandingGrantInput carries admin creation inputs for a landing node grant.
type CreateLandingGrantInput struct {
	NodeID           int64      `json:"node_id"`
	GranteeUserID    int64      `json:"grantee_user_id"`
	GrantedByAdminID int64      `json:"-"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	MaxBytes         int64      `json:"max_bytes"`
	MaxAccounts      int        `json:"max_accounts"`
	MaxRPM           int        `json:"max_rpm"`
	MaxConcurrency   int        `json:"max_concurrency"`
	Notes            string     `json:"notes"`
}

// GrantSliceReservation is the atomic disjoint slice returned to a Landing node.
type GrantSliceReservation struct {
	SliceID             string     `json:"slice_id"`
	GrantID             int64      `json:"grant_id"`
	NodeID              int64      `json:"node_id"`
	GrantedBytes        int64      `json:"granted_bytes"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	GrantRemainingBytes int64      `json:"grant_remaining_bytes"` // -1 if unlimited
	NodeRemainingBytes  int64      `json:"node_remaining_bytes"`  // -1 if unlimited
}

// GrantUsageCommitResult reports the idempotent settlement result for a usage receipt.
type GrantUsageCommitResult struct {
	ReceiptID           string `json:"receipt_id"`
	GrantID             int64  `json:"grant_id"`
	Duplicate           bool   `json:"duplicate"`
	ChargedBytes        int64  `json:"charged_bytes"`
	GrantUsedBytes      int64  `json:"grant_used_bytes"`
	GrantRemainingBytes int64  `json:"grant_remaining_bytes"`
	Status              string `json:"status"`
}

// BerthLandingGrantStore abstracts transactional persistence for Admin Landing Grants.
type BerthLandingGrantStore interface {
	CreateGrant(ctx context.Context, in CreateLandingGrantInput) (*LandingNodeGrant, error)
	ApplyForLandingNode(ctx context.Context, in ApplyLandingGrantInput) (*LandingNodeGrant, error)
	CancelPendingApplication(ctx context.Context, grantID, userID int64) error
	ApproveGrant(ctx context.Context, in ApproveLandingGrantInput) (*LandingNodeGrant, error)
	RejectGrant(ctx context.Context, grantID, adminID int64, reviewNote string) (*LandingNodeGrant, error)
	ListAvailableLandingNodes(ctx context.Context, userID int64) ([]AvailableLandingNode, error)
	GetGrant(ctx context.Context, grantID int64) (*LandingNodeGrant, error)
	ListGrants(ctx context.Context, userIDFilter int64) ([]LandingNodeGrant, error)
	ListRevokedGrantIDs(ctx context.Context) ([]int64, error)
	RevokeGrant(ctx context.Context, grantID int64, reason string) (newRevSeq int64, err error)
	ReserveGrantByteSlice(ctx context.Context, grantID, nodeID, requestedBytes int64, now time.Time) (*GrantSliceReservation, error)
	CommitGrantUsageReceipt(ctx context.Context, receipt edgeproto.UsageReceipt) (*GrantUsageCommitResult, error)
}

// BerthLandingGrantService coordinates Admin Landing Node Grants, materialized
// user-bindable proxies rows, atomic disjoint byte-slice reservation, and
// idempotent usage settlement.
type BerthLandingGrantService struct {
	store          BerthLandingGrantStore
	onGrantRevoked func(ctx context.Context, grantID int64, newRevSeq int64)
}

// NewBerthLandingGrantService constructs a PostgreSQL-backed BerthLandingGrantService.
func NewBerthLandingGrantService(db *sql.DB) *BerthLandingGrantService {
	return &BerthLandingGrantService{store: &sqlLandingGrantStore{db: db}}
}

// NewBerthLandingGrantServiceWithStore constructs a service backed by a custom store.
func NewBerthLandingGrantServiceWithStore(store BerthLandingGrantStore) *BerthLandingGrantService {
	return &BerthLandingGrantService{store: store}
}

// SetOnGrantRevoked registers an optional hook notified after grant revocation bumps rev_seq.
func (s *BerthLandingGrantService) SetOnGrantRevoked(fn func(ctx context.Context, grantID int64, newRevSeq int64)) {
	s.onGrantRevoked = fn
}

func (s *BerthLandingGrantService) CreateGrant(ctx context.Context, in CreateLandingGrantInput) (*LandingNodeGrant, error) {
	if in.NodeID <= 0 || in.GranteeUserID <= 0 {
		return nil, fmt.Errorf("%w: node_id and grantee_user_id are required", ErrLandingGrantInvalid)
	}
	if in.MaxBytes < 0 || in.MaxRPM < 0 || in.MaxConcurrency < 0 {
		return nil, fmt.Errorf("%w: limits must be >= 0", ErrLandingGrantInvalid)
	}
	if in.MaxAccounts <= 0 {
		in.MaxAccounts = 1
	}
	in.Notes = strings.TrimSpace(in.Notes)
	return s.store.CreateGrant(ctx, in)
}

func (s *BerthLandingGrantService) ListAvailableLandingNodes(ctx context.Context, userID int64) ([]AvailableLandingNode, error) {
	if userID <= 0 {
		return nil, ErrLandingGrantForbidden
	}
	return s.store.ListAvailableLandingNodes(ctx, userID)
}

func (s *BerthLandingGrantService) ApplyForLandingNode(ctx context.Context, in ApplyLandingGrantInput) (*LandingNodeGrant, error) {
	if in.NodeID <= 0 || in.GranteeUserID <= 0 {
		return nil, fmt.Errorf("%w: node_id is required", ErrLandingGrantInvalid)
	}
	if in.MaxBytes < 0 {
		return nil, fmt.Errorf("%w: max_bytes must be >= 0", ErrLandingGrantInvalid)
	}
	if in.MaxAccounts <= 0 {
		in.MaxAccounts = 1
	}
	in.RequestReason = strings.TrimSpace(in.RequestReason)
	if len(in.RequestReason) > 1000 {
		in.RequestReason = in.RequestReason[:1000]
	}
	return s.store.ApplyForLandingNode(ctx, in)
}

func (s *BerthLandingGrantService) CancelPendingApplication(ctx context.Context, grantID, userID int64) error {
	if grantID <= 0 || userID <= 0 {
		return ErrLandingGrantInvalid
	}
	return s.store.CancelPendingApplication(ctx, grantID, userID)
}

func (s *BerthLandingGrantService) ApproveGrant(ctx context.Context, in ApproveLandingGrantInput) (*LandingNodeGrant, error) {
	if in.GrantID <= 0 || in.AdminID <= 0 {
		return nil, ErrLandingGrantInvalid
	}
	if in.MaxBytes != nil && *in.MaxBytes < 0 {
		return nil, fmt.Errorf("%w: max_bytes must be >= 0", ErrLandingGrantInvalid)
	}
	if in.MaxAccounts != nil && *in.MaxAccounts < 1 {
		return nil, fmt.Errorf("%w: max_accounts must be >= 1", ErrLandingGrantInvalid)
	}
	if in.MaxRPM != nil && *in.MaxRPM < 0 {
		return nil, fmt.Errorf("%w: max_rpm must be >= 0", ErrLandingGrantInvalid)
	}
	if in.MaxConcurrency != nil && *in.MaxConcurrency < 0 {
		return nil, fmt.Errorf("%w: max_concurrency must be >= 0", ErrLandingGrantInvalid)
	}
	in.ReviewNote = strings.TrimSpace(in.ReviewNote)
	in.Notes = strings.TrimSpace(in.Notes)
	return s.store.ApproveGrant(ctx, in)
}

func (s *BerthLandingGrantService) RejectGrant(ctx context.Context, grantID, adminID int64, reviewNote string) (*LandingNodeGrant, error) {
	if grantID <= 0 || adminID <= 0 {
		return nil, ErrLandingGrantInvalid
	}
	return s.store.RejectGrant(ctx, grantID, adminID, strings.TrimSpace(reviewNote))
}

func (s *BerthLandingGrantService) GetGrant(ctx context.Context, grantID int64) (*LandingNodeGrant, error) {
	if grantID <= 0 {
		return nil, ErrLandingGrantInvalid
	}
	return s.store.GetGrant(ctx, grantID)
}

func (s *BerthLandingGrantService) ListAdminGrants(ctx context.Context) ([]LandingNodeGrant, error) {
	return s.store.ListGrants(ctx, 0)
}

func (s *BerthLandingGrantService) ListUserGrants(ctx context.Context, userID int64) ([]LandingNodeGrant, error) {
	if userID <= 0 {
		return nil, ErrLandingGrantForbidden
	}
	return s.store.ListGrants(ctx, userID)
}

func (s *BerthLandingGrantService) ListRevokedGrantIDs(ctx context.Context) ([]int64, error) {
	return s.store.ListRevokedGrantIDs(ctx)
}

func (s *BerthLandingGrantService) RevokeGrant(ctx context.Context, grantID int64, reason string) (int64, error) {
	if grantID <= 0 {
		return 0, ErrLandingGrantInvalid
	}
	revSeq, err := s.store.RevokeGrant(ctx, grantID, strings.TrimSpace(reason))
	if err != nil {
		return 0, err
	}
	if s.onGrantRevoked != nil {
		s.onGrantRevoked(ctx, grantID, revSeq)
	}
	return revSeq, nil
}

// ReserveGrantByteSlice atomically reserves a disjoint byte slice against BOTH
// grant.max_bytes and node.max_bytes_month in a single transaction (Codex Blocker #1.5).
func (s *BerthLandingGrantService) ReserveGrantByteSlice(
	ctx context.Context,
	grantID, nodeID, requestedBytes int64,
	now time.Time,
) (*GrantSliceReservation, error) {
	if grantID <= 0 || nodeID <= 0 {
		return nil, ErrLandingGrantInvalid
	}
	if requestedBytes <= 0 || requestedBytes > DefaultGrantSliceBytes {
		requestedBytes = DefaultGrantSliceBytes
	}
	if now.IsZero() {
		now = time.Now()
	}
	return s.store.ReserveGrantByteSlice(ctx, grantID, nodeID, requestedBytes, now)
}

// CommitGrantUsageReceipt idempotently persists a Landing usage receipt keyed by receipt_id
// and settles reserved/used byte counters on both the grant and edge node.
func (s *BerthLandingGrantService) CommitGrantUsageReceipt(ctx context.Context, receipt edgeproto.UsageReceipt) (*GrantUsageCommitResult, error) {
	if strings.TrimSpace(receipt.ReceiptID) == "" || receipt.GrantID <= 0 || receipt.NodeID <= 0 {
		return nil, ErrLandingGrantInvalid
	}
	if receipt.IngressBytes < 0 || receipt.EgressBytes < 0 || receipt.TotalBytes < 0 {
		return nil, ErrLandingGrantInvalid
	}
	if receipt.TotalBytes == 0 {
		receipt.TotalBytes = receipt.IngressBytes + receipt.EgressBytes
	}
	return s.store.CommitGrantUsageReceipt(ctx, receipt)
}

// ---------- PostgreSQL BerthLandingGrantStore ----------

type sqlLandingGrantStore struct {
	db *sql.DB
}

func (s *sqlLandingGrantStore) CreateGrant(ctx context.Context, in CreateLandingGrantInput) (*LandingNodeGrant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// Lock & verify edge node carries landing role and is not suspended.
	var nodeName, status, exitIP, exitCC, exitTZ string
	var roles []string
	err = tx.QueryRowContext(ctx, `
		SELECT name, status, roles, exit_ip, exit_country_code, exit_timezone
		FROM berth_edge_nodes
		WHERE id = $1
		FOR UPDATE`, in.NodeID).Scan(&nodeName, &status, pq.Array(&roles), &exitIP, &exitCC, &exitTZ)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEdgeZoneNotFound
		}
		return nil, err
	}
	if status == EdgeNodeStatusSuspended {
		return nil, fmt.Errorf("%w: landing node %s is suspended", ErrLandingGrantInvalid, nodeName)
	}
	hasLanding := false
	for _, r := range roles {
		if r == EdgeRoleLanding || r == EdgeRoleCompat {
			hasLanding = true
			break
		}
	}
	if !hasLanding {
		return nil, fmt.Errorf("%w: node %s does not have landing role", ErrLandingGrantInvalid, nodeName)
	}

	// Materialize a redacted, credential-free user-bindable proxies projection.
	proxyName := fmt.Sprintf("edge-landing-%s-u%d", nodeName, in.GranteeUserID)
	if len(proxyName) > 100 {
		proxyName = proxyName[:100]
	}
	proxyHost := fmt.Sprintf("%s.edge.internal", nodeName)
	var proxyID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO proxies (
			name, protocol, host, port, username, password, status,
			max_accounts, max_rpm, max_concurrency,
			exit_ip, exit_country_code, exit_timezone, expires_at,
			edge_node_id, source_type
		) VALUES ($1, 'https', $2, 443, NULL, NULL, 'active', $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id`,
		proxyName, proxyHost, in.MaxAccounts, in.MaxRPM, in.MaxConcurrency,
		nullIfEmpty(exitIP), nullIfEmpty(exitCC), nullIfEmpty(exitTZ), in.ExpiresAt,
		in.NodeID, ProxySourceTypeEdgeLandingGrant,
	).Scan(&proxyID)
	if err != nil {
		return nil, err
	}

	var adminID sql.NullInt64
	if in.GrantedByAdminID > 0 {
		adminID = sql.NullInt64{Int64: in.GrantedByAdminID, Valid: true}
	}

	var grant LandingNodeGrant
	var retAdmin sql.NullInt64
	var retProxy sql.NullInt64
	var retExp sql.NullTime
	err = tx.QueryRowContext(ctx, `
		INSERT INTO berth_landing_node_grants (
			node_id, grantee_user_id, granted_by_admin_id, proxy_id,
			expires_at, max_bytes, max_accounts, max_rpm, max_concurrency, status, notes
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10)
		RETURNING id, node_id, grantee_user_id, granted_by_admin_id, proxy_id,
		          expires_at, max_bytes, used_bytes, reserved_bytes,
		          max_accounts, max_rpm, max_concurrency, status, notes, created_at, updated_at`,
		in.NodeID, in.GranteeUserID, adminID, proxyID,
		in.ExpiresAt, in.MaxBytes, in.MaxAccounts, in.MaxRPM, in.MaxConcurrency, in.Notes,
	).Scan(
		&grant.ID, &grant.NodeID, &grant.GranteeUserID, &retAdmin, &retProxy,
		&retExp, &grant.MaxBytes, &grant.UsedBytes, &grant.ReservedBytes,
		&grant.MaxAccounts, &grant.MaxRPM, &grant.MaxConcurrency, &grant.Status, &grant.Notes,
		&grant.CreatedAt, &grant.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `UPDATE proxies SET grant_id = $1, updated_at = NOW() WHERE id = $2`, grant.ID, proxyID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	if retAdmin.Valid {
		v := retAdmin.Int64
		grant.GrantedByAdminID = &v
	}
	if retProxy.Valid {
		v := retProxy.Int64
		grant.ProxyID = &v
	}
	if retExp.Valid {
		t := retExp.Time
		grant.ExpiresAt = &t
	}
	grant.NodeName = nodeName
	grant.ExitCountryCode = exitCC
	grant.ExitTimezone = exitTZ
	grant.computeRemaining()
	return &grant, nil
}

func scanLandingGrant(sc interface{ Scan(...any) error }, includeAdminFields bool) (*LandingNodeGrant, error) {
	var g LandingNodeGrant
	var adminID, proxyID sql.NullInt64
	var exp, revAt sql.NullTime
	var nodeExitIP, granteeEmail, granteeUsername sql.NullString
	err := sc.Scan(
		&g.ID, &g.NodeID, &g.NodeName, &g.NodeStatus, &nodeExitIP,
		&g.ExitCountryCode, &g.ExitTimezone, &g.ExitLocale,
		&g.GranteeUserID, &granteeEmail, &granteeUsername,
		&adminID, &proxyID,
		&exp, &g.MaxBytes, &g.UsedBytes, &g.ReservedBytes,
		&g.MaxAccounts, &g.MaxRPM, &g.MaxConcurrency, &g.Status, &g.Notes,
		&g.RequestReason, &g.ReviewNote, &revAt,
		&g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLandingGrantNotFound
		}
		return nil, err
	}
	if includeAdminFields {
		if nodeExitIP.Valid {
			g.NodeExitIP = nodeExitIP.String
		}
		if granteeEmail.Valid {
			g.GranteeEmail = granteeEmail.String
		}
		if granteeUsername.Valid {
			g.GranteeUsername = granteeUsername.String
		}
	}
	if adminID.Valid {
		v := adminID.Int64
		g.GrantedByAdminID = &v
	}
	if proxyID.Valid {
		v := proxyID.Int64
		g.ProxyID = &v
	}
	if exp.Valid {
		t := exp.Time
		g.ExpiresAt = &t
	}
	if revAt.Valid {
		t := revAt.Time
		g.ReviewedAt = &t
	}
	g.computeRemaining()
	return &g, nil
}

const landingGrantSelectSQL = `
	SELECT g.id, g.node_id, n.name, n.status, n.exit_ip,
	       n.exit_country_code, n.exit_timezone, n.exit_locale,
	       g.grantee_user_id, u.email, u.username,
	       g.granted_by_admin_id, g.proxy_id,
	       g.expires_at, g.max_bytes, g.used_bytes, g.reserved_bytes,
	       g.max_accounts, g.max_rpm, g.max_concurrency, g.status, g.notes,
	       g.request_reason, g.review_note, g.reviewed_at,
	       g.created_at, g.updated_at
	FROM berth_landing_node_grants g
	JOIN berth_edge_nodes n ON n.id = g.node_id
	LEFT JOIN users u ON u.id = g.grantee_user_id`

func (s *sqlLandingGrantStore) GetGrant(ctx context.Context, grantID int64) (*LandingNodeGrant, error) {
	row := s.db.QueryRowContext(ctx, landingGrantSelectSQL+` WHERE g.id = $1`, grantID)
	return scanLandingGrant(row, true)
}

func (s *sqlLandingGrantStore) ListGrants(ctx context.Context, userIDFilter int64) ([]LandingNodeGrant, error) {
	var rows *sql.Rows
	var err error
	includeAdminFields := userIDFilter <= 0
	if userIDFilter > 0 {
		rows, err = s.db.QueryContext(ctx, landingGrantSelectSQL+` WHERE g.grantee_user_id = $1 ORDER BY CASE WHEN g.status = 'pending' THEN 0 WHEN g.status = 'active' THEN 1 ELSE 2 END, g.id DESC`, userIDFilter)
	} else {
		rows, err = s.db.QueryContext(ctx, landingGrantSelectSQL+` ORDER BY CASE WHEN g.status = 'pending' THEN 0 WHEN g.status = 'active' THEN 1 ELSE 2 END, g.id DESC`)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]LandingNodeGrant, 0, 16)
	for rows.Next() {
		g, err := scanLandingGrant(rows, includeAdminFields)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

func (s *sqlLandingGrantStore) ListAvailableLandingNodes(ctx context.Context, userID int64) ([]AvailableLandingNode, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT n.id, n.name, n.exit_country_code, n.exit_timezone, n.exit_locale, n.status,
		       EXISTS (
		           SELECT 1 FROM berth_landing_node_grants g
		           WHERE g.node_id = n.id AND g.grantee_user_id = $1 AND g.status = 'active'
		             AND (g.expires_at IS NULL OR g.expires_at > NOW())
		       ) AS has_active,
		       EXISTS (
		           SELECT 1 FROM berth_landing_node_grants g
		           WHERE g.node_id = n.id AND g.grantee_user_id = $1 AND g.status = 'pending'
		       ) AS has_pending
		FROM berth_edge_nodes n
		WHERE ('landing' = ANY(n.roles) OR 'compat' = ANY(n.roles))
		  AND n.status <> 'suspended'
		ORDER BY CASE WHEN n.status = 'active' THEN 0 ELSE 1 END, n.exit_country_code ASC, n.name ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]AvailableLandingNode, 0, 16)
	for rows.Next() {
		var item AvailableLandingNode
		if err := rows.Scan(
			&item.ID, &item.Name, &item.ExitCountryCode, &item.ExitTimezone,
			&item.ExitLocale, &item.Status, &item.HasActiveGrant, &item.HasPendingRequest,
		); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *sqlLandingGrantStore) ApplyForLandingNode(ctx context.Context, in ApplyLandingGrantInput) (*LandingNodeGrant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var nodeName, status string
	var roles []string
	err = tx.QueryRowContext(ctx, `
		SELECT name, status, roles
		FROM berth_edge_nodes
		WHERE id = $1`, in.NodeID).Scan(&nodeName, &status, pq.Array(&roles))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEdgeZoneNotFound
		}
		return nil, err
	}
	if status == EdgeNodeStatusSuspended {
		return nil, fmt.Errorf("%w: landing node %s is suspended", ErrLandingGrantInvalid, nodeName)
	}
	hasLanding := false
	for _, r := range roles {
		if r == EdgeRoleLanding || r == EdgeRoleCompat {
			hasLanding = true
			break
		}
	}
	if !hasLanding {
		return nil, fmt.Errorf("%w: node %s does not have landing role", ErrLandingGrantInvalid, nodeName)
	}

	var exists int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(1) FROM berth_landing_node_grants
		WHERE grantee_user_id = $1 AND node_id = $2 AND status = 'pending'`,
		in.GranteeUserID, in.NodeID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists > 0 {
		return nil, ErrLandingGrantPendingExists
	}

	var grantID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO berth_landing_node_grants (
			node_id, grantee_user_id, granted_by_admin_id, proxy_id,
			max_bytes, max_accounts, max_rpm, max_concurrency,
			status, notes, request_reason
		) VALUES ($1, $2, NULL, NULL, $3, $4, 0, 0, 'pending', '', $5)
		RETURNING id`,
		in.NodeID, in.GranteeUserID, in.MaxBytes, in.MaxAccounts, in.RequestReason,
	).Scan(&grantID)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return nil, ErrLandingGrantPendingExists
		}
		return nil, err
	}

	row := tx.QueryRowContext(ctx, landingGrantSelectSQL+` WHERE g.id = $1`, grantID)
	created, err := scanLandingGrant(row, false)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return created, nil
}

func (s *sqlLandingGrantStore) CancelPendingApplication(ctx context.Context, grantID, userID int64) error {
	var ownerID int64
	var status string
	err := s.db.QueryRowContext(ctx, `
		SELECT grantee_user_id, status
		FROM berth_landing_node_grants
		WHERE id = $1`, grantID).Scan(&ownerID, &status)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrLandingGrantNotFound
		}
		return err
	}
	if ownerID != userID {
		return ErrLandingGrantForbidden
	}
	if status != GrantStatusPending {
		return ErrLandingGrantNotPending
	}
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM berth_landing_node_grants
		WHERE id = $1 AND grantee_user_id = $2 AND status = 'pending' AND proxy_id IS NULL`,
		grantID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrLandingGrantNotPending
	}
	return nil
}

func (s *sqlLandingGrantStore) ApproveGrant(ctx context.Context, in ApproveLandingGrantInput) (*LandingNodeGrant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var nodeID int64
	if err := tx.QueryRowContext(ctx, `SELECT node_id FROM berth_landing_node_grants WHERE id = $1`, in.GrantID).Scan(&nodeID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLandingGrantNotFound
		}
		return nil, err
	}

	// Lock hierarchy: berth_edge_nodes -> berth_landing_node_grants.
	var nodeName, nodeStatus, exitIP, exitCC, exitTZ string
	var roles []string
	err = tx.QueryRowContext(ctx, `
		SELECT name, status, roles, exit_ip, exit_country_code, exit_timezone
		FROM berth_edge_nodes
		WHERE id = $1
		FOR UPDATE`, nodeID).Scan(&nodeName, &nodeStatus, pq.Array(&roles), &exitIP, &exitCC, &exitTZ)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEdgeZoneNotFound
		}
		return nil, err
	}
	if nodeStatus == EdgeNodeStatusSuspended {
		return nil, fmt.Errorf("%w: landing node %s is suspended", ErrLandingGrantInvalid, nodeName)
	}

	var granteeUserID, curMaxBytes int64
	var curMaxAccounts, curMaxRPM, curMaxConc int
	var curStatus, curNotes string
	err = tx.QueryRowContext(ctx, `
		SELECT grantee_user_id, max_bytes, max_accounts, max_rpm, max_concurrency, status, notes
		FROM berth_landing_node_grants
		WHERE id = $1
		FOR UPDATE`, in.GrantID).Scan(
		&granteeUserID, &curMaxBytes, &curMaxAccounts, &curMaxRPM, &curMaxConc, &curStatus, &curNotes,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLandingGrantNotFound
		}
		return nil, err
	}
	if curStatus != GrantStatusPending {
		return nil, ErrLandingGrantNotPending
	}

	maxBytes := curMaxBytes
	if in.MaxBytes != nil {
		maxBytes = *in.MaxBytes
	}
	maxAccounts := curMaxAccounts
	if in.MaxAccounts != nil {
		maxAccounts = *in.MaxAccounts
	}
	if maxAccounts <= 0 {
		maxAccounts = 1
	}
	maxRPM := curMaxRPM
	if in.MaxRPM != nil {
		maxRPM = *in.MaxRPM
	}
	maxConc := curMaxConc
	if in.MaxConcurrency != nil {
		maxConc = *in.MaxConcurrency
	}
	notes := curNotes
	if in.Notes != "" {
		notes = in.Notes
	}

	// Materialize redacted, credential-free proxies row for this approved landing grant.
	proxyName := fmt.Sprintf("edge-landing-%s-u%d", nodeName, granteeUserID)
	if len(proxyName) > 100 {
		proxyName = proxyName[:100]
	}
	proxyHost := fmt.Sprintf("%s.edge.internal", nodeName)
	var proxyID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO proxies (
			name, protocol, host, port, username, password, status,
			max_accounts, max_rpm, max_concurrency,
			exit_ip, exit_country_code, exit_timezone, expires_at,
			edge_node_id, grant_id, source_type
		) VALUES ($1, 'https', $2, 443, NULL, NULL, 'active', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id`,
		proxyName, proxyHost, maxAccounts, maxRPM, maxConc,
		nullIfEmpty(exitIP), nullIfEmpty(exitCC), nullIfEmpty(exitTZ), in.ExpiresAt,
		nodeID, in.GrantID, ProxySourceTypeEdgeLandingGrant,
	).Scan(&proxyID)
	if err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE berth_landing_node_grants
		SET status = 'active',
		    granted_by_admin_id = $2,
		    proxy_id = $3,
		    expires_at = $4,
		    max_bytes = $5,
		    max_accounts = $6,
		    max_rpm = $7,
		    max_concurrency = $8,
		    notes = $9,
		    review_note = $10,
		    reviewed_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1`,
		in.GrantID, in.AdminID, proxyID, in.ExpiresAt,
		maxBytes, maxAccounts, maxRPM, maxConc, notes, in.ReviewNote,
	); err != nil {
		return nil, err
	}

	row := tx.QueryRowContext(ctx, landingGrantSelectSQL+` WHERE g.id = $1`, in.GrantID)
	approved, err := scanLandingGrant(row, true)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return approved, nil
}

func (s *sqlLandingGrantStore) RejectGrant(ctx context.Context, grantID, adminID int64, reviewNote string) (*LandingNodeGrant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var curStatus string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM berth_landing_node_grants WHERE id = $1 FOR UPDATE`, grantID).Scan(&curStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLandingGrantNotFound
		}
		return nil, err
	}
	if curStatus != GrantStatusPending {
		return nil, ErrLandingGrantNotPending
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE berth_landing_node_grants
		SET status = 'rejected',
		    granted_by_admin_id = $2,
		    review_note = $3,
		    reviewed_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1`, grantID, adminID, reviewNote); err != nil {
		return nil, err
	}

	row := tx.QueryRowContext(ctx, landingGrantSelectSQL+` WHERE g.id = $1`, grantID)
	rejected, err := scanLandingGrant(row, true)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return rejected, nil
}

func (s *sqlLandingGrantStore) ListRevokedGrantIDs(ctx context.Context) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id FROM berth_landing_node_grants
		WHERE status IN ('revoked', 'expired', 'quota_exhausted', 'paused')
		ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]int64, 0, 16)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *sqlLandingGrantStore) RevokeGrant(ctx context.Context, grantID int64, reason string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	// Lock grant first to find node_id, then lock node -> grant cleanly, or read node_id first.
	var nodeID int64
	err = tx.QueryRowContext(ctx, `SELECT node_id FROM berth_landing_node_grants WHERE id = $1`, grantID).Scan(&nodeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrLandingGrantNotFound
		}
		return 0, err
	}

	// Lock hierarchy: berth_edge_nodes -> berth_landing_node_grants.
	var nodeReserved int64
	if err := tx.QueryRowContext(ctx, `SELECT reserved_bytes_month FROM berth_edge_nodes WHERE id = $1 FOR UPDATE`, nodeID).Scan(&nodeReserved); err != nil {
		return 0, err
	}

	var proxyID sql.NullInt64
	var grantReserved int64
	var curNotes string
	err = tx.QueryRowContext(ctx, `
		SELECT proxy_id, reserved_bytes, notes
		FROM berth_landing_node_grants
		WHERE id = $1
		FOR UPDATE`, grantID).Scan(&proxyID, &grantReserved, &curNotes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrLandingGrantNotFound
		}
		return 0, err
	}

	nextNotes := curNotes
	if reason != "" {
		if nextNotes != "" {
			nextNotes += " | "
		}
		nextNotes += "revoked: " + reason
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE berth_landing_node_grants
		SET status = 'revoked', reserved_bytes = 0, notes = $2, updated_at = NOW()
		WHERE id = $1`, grantID, nextNotes); err != nil {
		return 0, err
	}

	if grantReserved > 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE berth_edge_nodes
			SET reserved_bytes_month = GREATEST(0, reserved_bytes_month - $2), updated_at = NOW()
			WHERE id = $1`, nodeID, grantReserved); err != nil {
			return 0, err
		}
	}

	if proxyID.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE proxies SET status = 'disabled', updated_at = NOW() WHERE id = $1`, proxyID.Int64); err != nil {
			return 0, err
		}
	}

	var revSeq int64
	if err := tx.QueryRowContext(ctx, `
		UPDATE berth_edge_revocation_state
		SET rev_seq = rev_seq + 1, updated_at = NOW()
		WHERE id = 1
		RETURNING rev_seq`).Scan(&revSeq); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return revSeq, nil
}

func (s *sqlLandingGrantStore) ReserveGrantByteSlice(
	ctx context.Context,
	grantID, nodeID, requestedBytes int64,
	now time.Time,
) (*GrantSliceReservation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// Strict lock order: berth_edge_nodes -> berth_landing_node_grants.
	var nodeStatus string
	var nodeMax, nodeUsed, nodeRes int64
	err = tx.QueryRowContext(ctx, `
		SELECT status, max_bytes_month, used_bytes_month, reserved_bytes_month
		FROM berth_edge_nodes
		WHERE id = $1
		FOR UPDATE`, nodeID).Scan(&nodeStatus, &nodeMax, &nodeUsed, &nodeRes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEdgeZoneNotFound
		}
		return nil, err
	}
	if nodeStatus != EdgeNodeStatusActive {
		return nil, ErrLandingGrantInactive
	}

	var gNodeID, gMax, gUsed, gRes int64
	var gStatus string
	var gExp sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT node_id, status, expires_at, max_bytes, used_bytes, reserved_bytes
		FROM berth_landing_node_grants
		WHERE id = $1
		FOR UPDATE`, grantID).Scan(&gNodeID, &gStatus, &gExp, &gMax, &gUsed, &gRes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLandingGrantNotFound
		}
		return nil, err
	}
	if gNodeID != nodeID {
		return nil, ErrLandingGrantForbidden
	}
	if gStatus != GrantStatusActive {
		return nil, ErrLandingGrantInactive
	}
	if gExp.Valid && !now.Before(gExp.Time) {
		_, _ = tx.ExecContext(ctx, `UPDATE berth_landing_node_grants SET status = 'expired', updated_at = NOW() WHERE id = $1`, grantID)
		_ = tx.Commit()
		return nil, ErrLandingGrantExpired
	}

	slice := requestedBytes
	if slice > DefaultGrantSliceBytes {
		slice = DefaultGrantSliceBytes
	}

	var grantRemBefore int64 = -1
	if gMax > 0 {
		grantRemBefore = gMax - gUsed - gRes
		if grantRemBefore <= 0 {
			if gUsed >= gMax {
				_, _ = tx.ExecContext(ctx, `UPDATE berth_landing_node_grants SET status = 'quota_exhausted', updated_at = NOW() WHERE id = $1`, grantID)
				_ = tx.Commit()
			}
			return nil, ErrLandingGrantQuotaExhausted
		}
		if slice > grantRemBefore {
			slice = grantRemBefore
		}
	}

	var nodeRemBefore int64 = -1
	if nodeMax > 0 {
		nodeRemBefore = nodeMax - nodeUsed - nodeRes
		if nodeRemBefore <= 0 {
			return nil, ErrLandingGrantQuotaExhausted
		}
		if slice > nodeRemBefore {
			slice = nodeRemBefore
		}
	}

	if slice <= 0 {
		return nil, ErrLandingGrantQuotaExhausted
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE berth_landing_node_grants
		SET reserved_bytes = reserved_bytes + $2, updated_at = NOW()
		WHERE id = $1`, grantID, slice); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE berth_edge_nodes
		SET reserved_bytes_month = reserved_bytes_month + $2, updated_at = NOW()
		WHERE id = $1`, nodeID, slice); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	res := &GrantSliceReservation{
		SliceID:             uuid.NewString(),
		GrantID:             grantID,
		NodeID:              nodeID,
		GrantedBytes:        slice,
		GrantRemainingBytes: -1,
		NodeRemainingBytes:  -1,
	}
	if gExp.Valid {
		t := gExp.Time
		res.ExpiresAt = &t
	}
	if grantRemBefore >= 0 {
		res.GrantRemainingBytes = grantRemBefore - slice
	}
	if nodeRemBefore >= 0 {
		res.NodeRemainingBytes = nodeRemBefore - slice
	}
	return res, nil
}

func (s *sqlLandingGrantStore) CommitGrantUsageReceipt(ctx context.Context, receipt edgeproto.UsageReceipt) (*GrantUsageCommitResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// Idempotent insert keyed by receipt_id UNIQUE.
	var leaseUUID any
	if _, parseErr := uuid.Parse(receipt.LeaseID); parseErr == nil {
		leaseUUID = receipt.LeaseID
	}
	var acctID sql.NullInt64
	if receipt.AccountID > 0 {
		acctID = sql.NullInt64{Int64: receipt.AccountID, Valid: true}
	}

	var insertedID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO berth_landing_node_grant_usage (
			receipt_id, grant_id, node_id, lease_id, account_id,
			ingress_bytes, egress_bytes, total_bytes, request_count, ttft_ms, status_code
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (receipt_id) DO NOTHING
		RETURNING id`,
		receipt.ReceiptID, receipt.GrantID, receipt.NodeID, leaseUUID, acctID,
		receipt.IngressBytes, receipt.EgressBytes, receipt.TotalBytes,
		receipt.RequestCount, receipt.TTFTMs, receipt.StatusCode,
	).Scan(&insertedID)
	if errors.Is(err, sql.ErrNoRows) {
		// Duplicate receipt replay: idempotently return success without double-charging!
		var gMax, gUsed, gRes int64
		var gStatus string
		_ = tx.QueryRowContext(ctx, `
			SELECT max_bytes, used_bytes, reserved_bytes, status
			FROM berth_landing_node_grants WHERE id = $1`, receipt.GrantID).Scan(&gMax, &gUsed, &gRes, &gStatus)
		_ = tx.Commit()
		rem := int64(-1)
		if gMax > 0 {
			rem = clampNonNegativeInt64(gMax - gUsed - gRes)
		}
		return &GrantUsageCommitResult{
			ReceiptID:           receipt.ReceiptID,
			GrantID:             receipt.GrantID,
			Duplicate:           true,
			ChargedBytes:        0,
			GrantUsedBytes:      gUsed,
			GrantRemainingBytes: rem,
			Status:              gStatus,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	// Lock hierarchy: berth_edge_nodes -> berth_landing_node_grants.
	if _, err := tx.ExecContext(ctx, `
		UPDATE berth_edge_nodes
		SET used_bytes_month = used_bytes_month + $2,
		    reserved_bytes_month = GREATEST(0, reserved_bytes_month - $2),
		    updated_at = NOW()
		WHERE id = $1`, receipt.NodeID, receipt.TotalBytes); err != nil {
		return nil, err
	}

	var gMax, gUsed, gRes int64
	var gStatus string
	err = tx.QueryRowContext(ctx, `
		UPDATE berth_landing_node_grants
		SET used_bytes = used_bytes + $2,
		    reserved_bytes = GREATEST(0, reserved_bytes - $2),
		    status = CASE
		        WHEN status = 'active' AND max_bytes > 0 AND (used_bytes + $2) >= max_bytes THEN 'quota_exhausted'
		        ELSE status
		    END,
		    updated_at = NOW()
		WHERE id = $1
		RETURNING max_bytes, used_bytes, reserved_bytes, status`,
		receipt.GrantID, receipt.TotalBytes,
	).Scan(&gMax, &gUsed, &gRes, &gStatus)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	rem := int64(-1)
	if gMax > 0 {
		rem = clampNonNegativeInt64(gMax - gUsed - gRes)
	}
	return &GrantUsageCommitResult{
		ReceiptID:           receipt.ReceiptID,
		GrantID:             receipt.GrantID,
		Duplicate:           false,
		ChargedBytes:        receipt.TotalBytes,
		GrantUsedBytes:      gUsed,
		GrantRemainingBytes: rem,
		Status:              gStatus,
	}, nil
}

func clampNonNegativeInt64(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

func nullIfEmpty(s string) sql.NullString {
	if strings.TrimSpace(s) == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// ---------- In-Memory BerthLandingGrantStore (for unit/E2E tests) ----------

type MemoryProxyProjection struct {
	ID             int64
	Name           string
	EdgeNodeID     int64
	GrantID        int64
	SourceType     string
	Status         string
	MaxAccounts    int
	MaxRPM         int
	MaxConcurrency int
}

type MemoryLandingGrantStore struct {
	mu           sync.Mutex
	zones        *MemoryZoneStore
	revSeqPtr    *int64
	nextGrantID  int64
	nextProxyID  int64
	grants       map[int64]*LandingNodeGrant
	proxies      map[int64]*MemoryProxyProjection
	seenReceipts map[string]edgeproto.UsageReceipt
}

func NewMemoryLandingGrantStore(zones *MemoryZoneStore, revSeqPtr *int64) *MemoryLandingGrantStore {
	if revSeqPtr == nil {
		v := int64(1)
		revSeqPtr = &v
	}
	return &MemoryLandingGrantStore{
		zones:        zones,
		revSeqPtr:    revSeqPtr,
		grants:       make(map[int64]*LandingNodeGrant),
		proxies:      make(map[int64]*MemoryProxyProjection),
		seenReceipts: make(map[string]edgeproto.UsageReceipt),
	}
}

func (m *MemoryLandingGrantStore) Proxies() []MemoryProxyProjection {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MemoryProxyProjection, 0, len(m.proxies))
	for _, p := range m.proxies {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *MemoryLandingGrantStore) CreateGrant(ctx context.Context, in CreateLandingGrantInput) (*LandingNodeGrant, error) {
	node, err := m.zones.GetNode(ctx, in.NodeID)
	if err != nil {
		return nil, err
	}
	if !node.HasRole(EdgeRoleLanding) && !node.HasRole(EdgeRoleCompat) {
		return nil, ErrLandingGrantInvalid
	}
	if node.Status == EdgeNodeStatusSuspended {
		return nil, ErrLandingGrantInvalid
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextGrantID++
	m.nextProxyID++
	pid := m.nextProxyID
	gid := m.nextGrantID
	now := time.Now()

	m.proxies[pid] = &MemoryProxyProjection{
		ID:             pid,
		Name:           fmt.Sprintf("edge-landing-%s-u%d", node.Name, in.GranteeUserID),
		EdgeNodeID:     node.ID,
		GrantID:        gid,
		SourceType:     ProxySourceTypeEdgeLandingGrant,
		Status:         "active",
		MaxAccounts:    in.MaxAccounts,
		MaxRPM:         in.MaxRPM,
		MaxConcurrency: in.MaxConcurrency,
	}

	g := &LandingNodeGrant{
		ID:              gid,
		NodeID:          node.ID,
		NodeName:        node.Name,
		ExitCountryCode: node.ExitCountryCode,
		ExitTimezone:    node.ExitTimezone,
		GranteeUserID:   in.GranteeUserID,
		ProxyID:         &pid,
		ExpiresAt:       in.ExpiresAt,
		MaxBytes:        in.MaxBytes,
		MaxAccounts:     in.MaxAccounts,
		MaxRPM:          in.MaxRPM,
		MaxConcurrency:  in.MaxConcurrency,
		Status:          GrantStatusActive,
		Notes:           in.Notes,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if in.GrantedByAdminID > 0 {
		aid := in.GrantedByAdminID
		g.GrantedByAdminID = &aid
	}
	g.computeRemaining()
	m.grants[gid] = g
	cp := *g
	return &cp, nil
}

func (m *MemoryLandingGrantStore) ListAvailableLandingNodes(ctx context.Context, userID int64) ([]AvailableLandingNode, error) {
	nodes, err := m.zones.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	out := make([]AvailableLandingNode, 0, len(nodes))
	for _, n := range nodes {
		if (!n.HasRole(EdgeRoleLanding) && !n.HasRole(EdgeRoleCompat)) || n.Status == EdgeNodeStatusSuspended {
			continue
		}
		var hasActive, hasPending bool
		for _, g := range m.grants {
			if g.NodeID != n.ID || g.GranteeUserID != userID {
				continue
			}
			if g.Status == GrantStatusActive && (g.ExpiresAt == nil || g.ExpiresAt.After(now)) {
				hasActive = true
			}
			if g.Status == GrantStatusPending {
				hasPending = true
			}
		}
		out = append(out, AvailableLandingNode{
			ID:                n.ID,
			Name:              n.Name,
			ExitCountryCode:   n.ExitCountryCode,
			ExitTimezone:      n.ExitTimezone,
			ExitLocale:        n.ExitLocale,
			Status:            n.Status,
			HasActiveGrant:    hasActive,
			HasPendingRequest: hasPending,
		})
	}
	return out, nil
}

func (m *MemoryLandingGrantStore) ApplyForLandingNode(ctx context.Context, in ApplyLandingGrantInput) (*LandingNodeGrant, error) {
	node, err := m.zones.GetNode(ctx, in.NodeID)
	if err != nil {
		return nil, err
	}
	if (!node.HasRole(EdgeRoleLanding) && !node.HasRole(EdgeRoleCompat)) || node.Status == EdgeNodeStatusSuspended {
		return nil, ErrLandingGrantInvalid
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range m.grants {
		if g.GranteeUserID == in.GranteeUserID && g.NodeID == in.NodeID && g.Status == GrantStatusPending {
			return nil, ErrLandingGrantPendingExists
		}
	}
	m.nextGrantID++
	gid := m.nextGrantID
	now := time.Now()
	g := &LandingNodeGrant{
		ID:              gid,
		NodeID:          node.ID,
		NodeName:        node.Name,
		NodeStatus:      node.Status,
		ExitCountryCode: node.ExitCountryCode,
		ExitTimezone:    node.ExitTimezone,
		ExitLocale:      node.ExitLocale,
		GranteeUserID:   in.GranteeUserID,
		MaxBytes:        in.MaxBytes,
		MaxAccounts:     in.MaxAccounts,
		Status:          GrantStatusPending,
		RequestReason:   in.RequestReason,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	g.computeRemaining()
	m.grants[gid] = g
	cp := *g
	return &cp, nil
}

func (m *MemoryLandingGrantStore) CancelPendingApplication(_ context.Context, grantID, userID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[grantID]
	if !ok {
		return ErrLandingGrantNotFound
	}
	if g.GranteeUserID != userID {
		return ErrLandingGrantForbidden
	}
	if g.Status != GrantStatusPending {
		return ErrLandingGrantNotPending
	}
	delete(m.grants, grantID)
	return nil
}

func (m *MemoryLandingGrantStore) ApproveGrant(ctx context.Context, in ApproveLandingGrantInput) (*LandingNodeGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[in.GrantID]
	if !ok {
		return nil, ErrLandingGrantNotFound
	}
	if g.Status != GrantStatusPending {
		return nil, ErrLandingGrantNotPending
	}
	node, err := m.zones.GetNode(ctx, g.NodeID)
	if err != nil {
		return nil, err
	}
	if node.Status == EdgeNodeStatusSuspended {
		return nil, ErrLandingGrantInvalid
	}

	if in.MaxBytes != nil {
		g.MaxBytes = *in.MaxBytes
	}
	if in.MaxAccounts != nil {
		g.MaxAccounts = *in.MaxAccounts
	}
	if g.MaxAccounts <= 0 {
		g.MaxAccounts = 1
	}
	if in.MaxRPM != nil {
		g.MaxRPM = *in.MaxRPM
	}
	if in.MaxConcurrency != nil {
		g.MaxConcurrency = *in.MaxConcurrency
	}
	if in.Notes != "" {
		g.Notes = in.Notes
	}
	g.ExpiresAt = in.ExpiresAt
	g.ReviewNote = in.ReviewNote
	now := time.Now()
	g.ReviewedAt = &now
	g.UpdatedAt = now
	aid := in.AdminID
	g.GrantedByAdminID = &aid

	m.nextProxyID++
	pid := m.nextProxyID
	m.proxies[pid] = &MemoryProxyProjection{
		ID:             pid,
		Name:           fmt.Sprintf("edge-landing-%s-u%d", node.Name, g.GranteeUserID),
		EdgeNodeID:     node.ID,
		GrantID:        g.ID,
		SourceType:     ProxySourceTypeEdgeLandingGrant,
		Status:         "active",
		MaxAccounts:    g.MaxAccounts,
		MaxRPM:         g.MaxRPM,
		MaxConcurrency: g.MaxConcurrency,
	}
	g.ProxyID = &pid
	g.Status = GrantStatusActive
	g.computeRemaining()
	cp := *g
	return &cp, nil
}

func (m *MemoryLandingGrantStore) RejectGrant(_ context.Context, grantID, adminID int64, reviewNote string) (*LandingNodeGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[grantID]
	if !ok {
		return nil, ErrLandingGrantNotFound
	}
	if g.Status != GrantStatusPending {
		return nil, ErrLandingGrantNotPending
	}
	now := time.Now()
	aid := adminID
	g.GrantedByAdminID = &aid
	g.Status = GrantStatusRejected
	g.ReviewNote = reviewNote
	g.ReviewedAt = &now
	g.UpdatedAt = now
	g.computeRemaining()
	cp := *g
	return &cp, nil
}

func (m *MemoryLandingGrantStore) GetGrant(_ context.Context, grantID int64) (*LandingNodeGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[grantID]
	if !ok {
		return nil, ErrLandingGrantNotFound
	}
	cp := *g
	cp.computeRemaining()
	return &cp, nil
}

func (m *MemoryLandingGrantStore) ListGrants(_ context.Context, userIDFilter int64) ([]LandingNodeGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LandingNodeGrant, 0, len(m.grants))
	for _, g := range m.grants {
		if userIDFilter > 0 && g.GranteeUserID != userIDFilter {
			continue
		}
		cp := *g
		cp.computeRemaining()
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

func (m *MemoryLandingGrantStore) ListRevokedGrantIDs(_ context.Context) ([]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]int64, 0)
	for _, g := range m.grants {
		if g.Status == GrantStatusRevoked || g.Status == GrantStatusExpired || g.Status == GrantStatusQuotaExhausted || g.Status == GrantStatusPaused {
			out = append(out, g.ID)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (m *MemoryLandingGrantStore) RevokeGrant(_ context.Context, grantID int64, reason string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[grantID]
	if !ok {
		return 0, ErrLandingGrantNotFound
	}
	m.zones.mu.Lock()
	if n, ok := m.zones.nodes[g.NodeID]; ok {
		n.ReservedBytesMonth = clampNonNegativeInt64(n.ReservedBytesMonth - g.ReservedBytes)
		m.zones.nodes[g.NodeID] = n
	}
	m.zones.mu.Unlock()

	g.Status = GrantStatusRevoked
	g.ReservedBytes = 0
	if reason != "" {
		g.Notes = strings.TrimSpace(g.Notes + " revoked:" + reason)
	}
	g.UpdatedAt = time.Now()
	g.computeRemaining()
	if g.ProxyID != nil {
		if p, ok := m.proxies[*g.ProxyID]; ok {
			p.Status = "disabled"
		}
	}
	*m.revSeqPtr++
	return *m.revSeqPtr, nil
}

func (m *MemoryLandingGrantStore) ReserveGrantByteSlice(_ context.Context, grantID, nodeID, requestedBytes int64, now time.Time) (*GrantSliceReservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[grantID]
	if !ok {
		return nil, ErrLandingGrantNotFound
	}
	if g.NodeID != nodeID {
		return nil, ErrLandingGrantForbidden
	}
	if g.Status != GrantStatusActive {
		return nil, ErrLandingGrantInactive
	}
	if g.ExpiresAt != nil && !now.Before(*g.ExpiresAt) {
		g.Status = GrantStatusExpired
		return nil, ErrLandingGrantExpired
	}

	m.zones.mu.Lock()
	defer m.zones.mu.Unlock()
	n, ok := m.zones.nodes[nodeID]
	if !ok {
		return nil, ErrEdgeZoneNotFound
	}
	if n.Status != EdgeNodeStatusActive {
		return nil, ErrLandingGrantInactive
	}

	slice := requestedBytes
	if slice > DefaultGrantSliceBytes {
		slice = DefaultGrantSliceBytes
	}

	grantRemBefore := int64(-1)
	if g.MaxBytes > 0 {
		grantRemBefore = g.MaxBytes - g.UsedBytes - g.ReservedBytes
		if grantRemBefore <= 0 {
			if g.UsedBytes >= g.MaxBytes {
				g.Status = GrantStatusQuotaExhausted
			}
			return nil, ErrLandingGrantQuotaExhausted
		}
		if slice > grantRemBefore {
			slice = grantRemBefore
		}
	}

	nodeRemBefore := int64(-1)
	if n.MaxBytesMonth > 0 {
		nodeRemBefore = n.MaxBytesMonth - n.UsedBytesMonth - n.ReservedBytesMonth
		if nodeRemBefore <= 0 {
			return nil, ErrLandingGrantQuotaExhausted
		}
		if slice > nodeRemBefore {
			slice = nodeRemBefore
		}
	}

	g.ReservedBytes += slice
	g.computeRemaining()
	n.ReservedBytesMonth += slice
	m.zones.nodes[nodeID] = n

	res := &GrantSliceReservation{
		SliceID:             uuid.NewString(),
		GrantID:             grantID,
		NodeID:              nodeID,
		GrantedBytes:        slice,
		ExpiresAt:           g.ExpiresAt,
		GrantRemainingBytes: -1,
		NodeRemainingBytes:  -1,
	}
	if grantRemBefore >= 0 {
		res.GrantRemainingBytes = grantRemBefore - slice
	}
	if nodeRemBefore >= 0 {
		res.NodeRemainingBytes = nodeRemBefore - slice
	}
	return res, nil
}

func (m *MemoryLandingGrantStore) CommitGrantUsageReceipt(_ context.Context, receipt edgeproto.UsageReceipt) (*GrantUsageCommitResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[receipt.GrantID]
	if !ok {
		return nil, ErrLandingGrantNotFound
	}
	if _, dup := m.seenReceipts[receipt.ReceiptID]; dup {
		g.computeRemaining()
		return &GrantUsageCommitResult{
			ReceiptID:           receipt.ReceiptID,
			GrantID:             receipt.GrantID,
			Duplicate:           true,
			ChargedBytes:        0,
			GrantUsedBytes:      g.UsedBytes,
			GrantRemainingBytes: g.RemainingBytes,
			Status:              g.Status,
		}, nil
	}

	m.seenReceipts[receipt.ReceiptID] = receipt
	g.UsedBytes += receipt.TotalBytes
	g.ReservedBytes = clampNonNegativeInt64(g.ReservedBytes - receipt.TotalBytes)
	if g.Status == GrantStatusActive && g.MaxBytes > 0 && g.UsedBytes >= g.MaxBytes {
		g.Status = GrantStatusQuotaExhausted
	}
	g.computeRemaining()

	m.zones.mu.Lock()
	if n, ok := m.zones.nodes[receipt.NodeID]; ok {
		n.UsedBytesMonth += receipt.TotalBytes
		n.ReservedBytesMonth = clampNonNegativeInt64(n.ReservedBytesMonth - receipt.TotalBytes)
		m.zones.nodes[receipt.NodeID] = n
	}
	m.zones.mu.Unlock()

	return &GrantUsageCommitResult{
		ReceiptID:           receipt.ReceiptID,
		GrantID:             receipt.GrantID,
		Duplicate:           false,
		ChargedBytes:        receipt.TotalBytes,
		GrantUsedBytes:      g.UsedBytes,
		GrantRemainingBytes: g.RemainingBytes,
		Status:              g.Status,
	}, nil
}
