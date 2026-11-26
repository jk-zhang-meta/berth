-- Migration 258: Berth Landing Node Application & Admin Approval Workflow
-- Extends berth_landing_node_grants with pending/rejected lifecycle statuses and
-- user-request / admin-review audit fields.

ALTER TABLE berth_landing_node_grants
    ADD COLUMN IF NOT EXISTS request_reason TEXT NOT NULL DEFAULT '';

ALTER TABLE berth_landing_node_grants
    ADD COLUMN IF NOT EXISTS review_note TEXT NOT NULL DEFAULT '';

ALTER TABLE berth_landing_node_grants
    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;

ALTER TABLE berth_landing_node_grants
    DROP CONSTRAINT IF EXISTS berth_landing_node_grants_status_check;

ALTER TABLE berth_landing_node_grants
    ADD CONSTRAINT berth_landing_node_grants_status_check
    CHECK (status IN ('pending', 'active', 'paused', 'revoked', 'rejected', 'expired', 'quota_exhausted'));

CREATE UNIQUE INDEX IF NOT EXISTS berth_landing_node_grants_pending_uniq
    ON berth_landing_node_grants (grantee_user_id, node_id)
    WHERE status = 'pending';
