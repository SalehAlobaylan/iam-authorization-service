DROP INDEX IF EXISTS idx_account_deletion_requests_processing_lease;
ALTER TABLE account_deletion_requests DROP COLUMN IF EXISTS iam_user_deleted_at;
ALTER TABLE account_deletion_requests DROP COLUMN IF EXISTS product_data_deleted_at;
ALTER TABLE account_deletion_requests DROP COLUMN IF EXISTS processing_started_at;
