-- Revoke the credential that was previously published with the demo console.
DELETE FROM sessions
WHERE user_id IN (
  SELECT id FROM users WHERE id = 'usr_demo_admin' OR email = 'admin@sentinel.local'
);

UPDATE users
SET password_hash = NULL,
    auth_provider = 'oidc',
    status = 'disabled',
    display_name = 'Disabled bootstrap owner'
WHERE id = 'usr_demo_admin' OR email = 'admin@sentinel.local';
