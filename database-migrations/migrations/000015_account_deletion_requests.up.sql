CREATE TABLE account_deletion_requests (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL UNIQUE,
    tenant_id VARCHAR(64) NOT NULL,
    confirmation_email VARCHAR(255) NOT NULL,
    status VARCHAR(24) NOT NULL CHECK (status IN ('queued', 'processing', 'completed', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_account_deletion_requests_status ON account_deletion_requests(status, created_at);
