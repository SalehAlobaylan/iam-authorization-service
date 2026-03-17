-- Remove Wahb-specific permissions
DELETE FROM role_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE resource IN ('feed', 'aggregation')
    UNION
    SELECT id FROM permissions WHERE resource = 'content' AND action = 'publish'
);
DELETE FROM user_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE resource IN ('feed', 'aggregation')
    UNION
    SELECT id FROM permissions WHERE resource = 'content' AND action = 'publish'
);
DELETE FROM permissions WHERE resource IN ('feed', 'aggregation');
DELETE FROM permissions WHERE resource = 'content' AND action = 'publish';

-- Remove editor role
DELETE FROM role_permissions WHERE role_id = '22222222-2222-2222-2222-222222222223';
DELETE FROM user_roles WHERE role_id = '22222222-2222-2222-2222-222222222223';
DELETE FROM roles WHERE id = '22222222-2222-2222-2222-222222222223';
