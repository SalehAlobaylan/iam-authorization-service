-- A rollback cannot safely restore new digest-only links. Drop them rather than
-- fabricating raw credentials, then restore the prior non-null legacy shape.
DELETE FROM email_verifications WHERE token IS NULL;
DELETE FROM password_resets WHERE token IS NULL;

ALTER TABLE email_verifications DROP CONSTRAINT IF EXISTS email_verifications_token_material_check;
ALTER TABLE password_resets DROP CONSTRAINT IF EXISTS password_resets_token_material_check;
DROP INDEX IF EXISTS idx_email_verifications_token_digest;
DROP INDEX IF EXISTS idx_password_resets_token_digest;
ALTER TABLE email_verifications DROP COLUMN IF EXISTS token_digest;
ALTER TABLE password_resets DROP COLUMN IF EXISTS token_digest;
ALTER TABLE email_verifications ALTER COLUMN token SET NOT NULL;
ALTER TABLE password_resets ALTER COLUMN token SET NOT NULL;
