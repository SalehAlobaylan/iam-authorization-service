-- Durable migration ownership is retained across rollback. Removing this row
-- could silently resume account-deletion claims while a database is sealed.
SELECT 1;
