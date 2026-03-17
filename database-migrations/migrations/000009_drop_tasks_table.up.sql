-- Drop the tasks table (Taskify remnant, no longer used in Wahb)
DROP TABLE IF EXISTS tasks;

-- Clean up stale task and CRM permissions
DELETE FROM role_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE resource IN ('task', 'crm')
);
DELETE FROM user_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE resource IN ('task', 'crm')
);
DELETE FROM permissions WHERE resource IN ('task', 'crm');
