-- Seed baseline RBAC data.
-- Safe to run multiple times.

INSERT INTO roles (id, name, description)
VALUES
  ('11111111-1111-1111-1111-111111111111', 'user', 'Regular user with basic permissions'),
  ('22222222-2222-2222-2222-222222222222', 'admin', 'Administrator with full access')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (id, resource, action, description)
VALUES
  ('33333333-3333-3333-3333-333333333331', 'profile', 'read', 'View user profile'),
  ('33333333-3333-3333-3333-333333333332', 'profile', 'write', 'Update user profile'),
  ('44444444-4444-4444-4444-444444444441', 'user', 'read', 'View users'),
  ('44444444-4444-4444-4444-444444444442', 'user', 'write', 'Update users'),
  ('44444444-4444-4444-4444-444444444443', 'user', 'delete', 'Delete users'),
  ('55555555-5555-5555-5555-555555555551', 'task', 'read', 'View tasks'),
  ('55555555-5555-5555-5555-555555555552', 'task', 'write', 'Create/Update tasks'),
  ('55555555-5555-5555-5555-555555555553', 'task', 'delete', 'Delete tasks')
ON CONFLICT (resource, action) DO NOTHING;

-- user role: profile(read/write), task(read/write)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON
  (p.resource = 'profile' AND p.action IN ('read', 'write'))
  OR
  (p.resource = 'task' AND p.action IN ('read', 'write'))
WHERE r.name = 'user'
ON CONFLICT DO NOTHING;

-- admin role: all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

-- Ensure default admin user has admin role if user exists.
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u
JOIN roles r ON r.name = 'admin'
WHERE u.email = 'admin@gmail.com'
ON CONFLICT DO NOTHING;
