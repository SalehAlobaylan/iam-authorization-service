-- Deliberately non-destructive. CMS and IAM may share these physical tables;
-- retirement is a separately approved manual operation after all consumers
-- have stopped using the identity/fence contract.
SELECT 'database identity and writer-fence retirement is manual-only';
