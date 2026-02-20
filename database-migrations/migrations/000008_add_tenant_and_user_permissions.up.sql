ALTER TABLE users
ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64);

UPDATE users
SET tenant_id = 'default'
WHERE tenant_id IS NULL OR tenant_id = '';

ALTER TABLE users
ALTER COLUMN tenant_id SET DEFAULT 'default';

ALTER TABLE users
ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);

CREATE TABLE IF NOT EXISTS user_permissions (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, permission_id)
);
