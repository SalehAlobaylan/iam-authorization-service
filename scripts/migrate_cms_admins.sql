-- migrate_cms_admins.sql
--
-- One-time migration script to copy CMS admin_users into IAM's users table.
-- Both tables are in the same PostgreSQL database.
--
-- Prerequisites:
--   - IAM migrations 000001-000011 have been applied
--   - IAM seed has run (roles exist)
--
-- Usage:
--   psql $DATABASE_URL -f scripts/migrate_cms_admins.sql
--
-- This script is idempotent: it skips users whose email already exists in IAM.

BEGIN;

-- 1. Insert CMS admin_users into IAM users table
INSERT INTO users (id, username, email, tenant_id, password, email_verified, email_verified_at, created_at, updated_at)
SELECT
    au.public_id,                                  -- Use CMS public_id as IAM user id
    LOWER(SPLIT_PART(au.email, '@', 1)),           -- Derive username from email
    LOWER(au.email),
    COALESCE(NULLIF(au.tenant_id, ''), 'default'),
    au.password_hash,                               -- bcrypt hashes are compatible
    TRUE,                                           -- Mark as verified (existing admins)
    NOW(),
    au.created_at,
    au.updated_at
FROM admin_users au
WHERE au.is_active = TRUE
  AND NOT EXISTS (
    SELECT 1 FROM users u WHERE LOWER(u.email) = LOWER(au.email)
  );

-- 2. Assign IAM roles based on CMS role field
-- Map CMS role -> IAM role (admin->admin, manager->manager, editor->editor, etc.)
INSERT INTO user_roles (user_id, role_id, assigned_at)
SELECT
    u.id,
    r.id,
    NOW()
FROM admin_users au
JOIN users u ON LOWER(u.email) = LOWER(au.email)
JOIN roles r ON LOWER(r.name) = LOWER(au.role)
WHERE NOT EXISTS (
    SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id AND ur.role_id = r.id
);

-- 3. Map CMS permissions (text[]) to IAM permission assignments
-- CMS stores permissions like 'content:read', 'source:write' in a text array.
-- IAM stores them as rows in user_permissions referencing the permissions table.
INSERT INTO user_permissions (user_id, permission_id, assigned_at)
SELECT DISTINCT
    u.id,
    p.id,
    NOW()
FROM admin_users au
JOIN users u ON LOWER(u.email) = LOWER(au.email)
CROSS JOIN LATERAL UNNEST(au.permissions) AS perm_str
JOIN permissions p ON (LOWER(p.resource) || ':' || LOWER(p.action)) = LOWER(perm_str)
WHERE au.permissions IS NOT NULL
  AND array_length(au.permissions, 1) > 0
  AND NOT EXISTS (
    SELECT 1 FROM user_permissions up WHERE up.user_id = u.id AND up.permission_id = p.id
  );

COMMIT;

-- Summary
SELECT 'Migration complete' AS status,
       (SELECT COUNT(*) FROM users) AS total_iam_users,
       (SELECT COUNT(*) FROM admin_users WHERE is_active = TRUE) AS total_cms_admins;
