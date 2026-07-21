-- IAM owns account lifecycle. CMS receives a narrow enforcement mirror only.
ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_users_suspended_at
    ON users(suspended_at)
    WHERE suspended_at IS NOT NULL;
