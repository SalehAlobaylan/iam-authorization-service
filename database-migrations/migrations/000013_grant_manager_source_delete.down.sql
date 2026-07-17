DELETE FROM role_permissions
USING roles, permissions
WHERE role_permissions.role_id = roles.id
  AND role_permissions.permission_id = permissions.id
  AND roles.name = 'manager'
  AND permissions.resource = 'source'
  AND permissions.action = 'delete';
