-- Media Sources uses the same source-delete capability as the broader Sources
-- console. Managers already manage sources; grant the explicit destructive
-- permission required by CMS's DELETE /admin/sources/:id route.
INSERT INTO role_permissions (role_id, permission_id, assigned_at)
SELECT roles.id, permissions.id, CURRENT_TIMESTAMP
FROM roles
JOIN permissions ON permissions.resource = 'source' AND permissions.action = 'delete'
WHERE roles.name = 'manager'
ON CONFLICT (role_id, permission_id) DO NOTHING;
