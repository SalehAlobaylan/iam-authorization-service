-- Add Wahb-specific permissions
INSERT INTO permissions (id, resource, action, description, created_at, updated_at)
VALUES
    ('99999999-9999-9999-9999-999999999994', 'content', 'publish', 'Publish content items', NOW(), NOW()),
    ('cccccccc-cccc-cccc-cccc-ccccccccccc1', 'feed', 'read', 'View feeds', NOW(), NOW()),
    ('cccccccc-cccc-cccc-cccc-ccccccccccc2', 'feed', 'manage', 'Manage feed configuration', NOW(), NOW()),
    ('dddddddd-dddd-dddd-dddd-ddddddddddd1', 'aggregation', 'read', 'View aggregation jobs', NOW(), NOW()),
    ('dddddddd-dddd-dddd-dddd-ddddddddddd2', 'aggregation', 'manage', 'Manage aggregation jobs', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Add editor role
INSERT INTO roles (id, name, description, created_at, updated_at)
VALUES ('22222222-2222-2222-2222-222222222223', 'editor', 'Content editor with publishing permissions', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;
