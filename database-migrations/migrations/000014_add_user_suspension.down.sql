DROP INDEX IF EXISTS idx_users_suspended_at;
ALTER TABLE users DROP COLUMN IF EXISTS suspended_at;
