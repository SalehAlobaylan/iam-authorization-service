-- New verification and password-reset credentials are stored only as SHA-256
-- digests. The legacy raw token columns remain temporarily nullable/readable so
-- links issued before this migration can expire naturally (24h / 1h).
ALTER TABLE email_verifications ADD COLUMN IF NOT EXISTS token_digest VARCHAR(64);
ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS token_digest VARCHAR(64);

ALTER TABLE email_verifications ALTER COLUMN token DROP NOT NULL;
ALTER TABLE password_resets ALTER COLUMN token DROP NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_email_verifications_token_digest
    ON email_verifications(token_digest)
    WHERE token_digest IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_password_resets_token_digest
    ON password_resets(token_digest)
    WHERE token_digest IS NOT NULL;

ALTER TABLE email_verifications
    ADD CONSTRAINT email_verifications_token_material_check
    CHECK (token_digest IS NOT NULL OR token IS NOT NULL);
ALTER TABLE password_resets
    ADD CONSTRAINT password_resets_token_material_check
    CHECK (token_digest IS NOT NULL OR token IS NOT NULL);
