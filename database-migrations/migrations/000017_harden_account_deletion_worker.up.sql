-- Persist resumable deletion lifecycle checkpoints. They prevent a retry from
-- replaying completed irreversible work and let a stale worker lease recover.
ALTER TABLE account_deletion_requests
    ADD COLUMN IF NOT EXISTS processing_started_at TIMESTAMPTZ;
ALTER TABLE account_deletion_requests
    ADD COLUMN IF NOT EXISTS product_data_deleted_at TIMESTAMPTZ;
ALTER TABLE account_deletion_requests
    ADD COLUMN IF NOT EXISTS iam_user_deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_account_deletion_requests_processing_lease
    ON account_deletion_requests(status, processing_started_at);
