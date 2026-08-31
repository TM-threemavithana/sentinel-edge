INSERT OR IGNORE INTO workspaces (id, name, slug, plan, retention_days)
VALUES ('ws_demo', 'Acme AI Platform', 'acme-ai', 'enterprise', 30);

INSERT OR IGNORE INTO users (id, email, display_name, password_hash, auth_provider)
VALUES (
  'usr_demo_admin',
  'bootstrap-disabled@sentinel.invalid',
  'Disabled bootstrap owner',
  NULL,
  'oidc'
);

-- Defense in depth for databases that previously received the demo credential.
UPDATE users
SET email = 'bootstrap-disabled@sentinel.invalid',
    display_name = 'Disabled bootstrap owner',
    password_hash = NULL,
    auth_provider = 'oidc',
    status = 'disabled'
WHERE id = 'usr_demo_admin';

INSERT OR IGNORE INTO memberships (workspace_id, user_id, role)
VALUES ('ws_demo', 'usr_demo_admin', 'admin');

INSERT OR IGNORE INTO upstreams (
  id, workspace_id, name, base_url, timeout_ms, status, created_by
) VALUES (
  'ups_echo', 'ws_demo', 'Safe echo service', 'https://httpbin.org', 15000, 'active', 'usr_demo_admin'
);

INSERT OR IGNORE INTO policies (
  id, workspace_id, name, description, priority, action, conditions_json,
  rate_limit_json, enabled, created_by
) VALUES
  (
    'pol_prompt_injection', 'ws_demo', 'Block prompt injection',
    'Reject high-confidence attempts to override or reveal model instructions.',
    10, 'block',
    '[{"field":"threat","operator":"equals","value":"prompt_injection"}]',
    NULL, 1, 'usr_demo_admin'
  ),
  (
    'pol_critical_threats', 'ws_demo', 'Block critical application threats',
    'Reject SQL injection, SSRF, and secret exfiltration indicators.',
    20, 'block',
    '[{"field":"severity","operator":"at_least","value":"critical"}]',
    NULL, 1, 'usr_demo_admin'
  ),
  (
    'pol_chat_rate', 'ws_demo', 'Chat completion budget',
    'Limit each API key to 120 chat completion requests per minute.',
    100, 'allow',
    '[{"field":"path","operator":"starts_with","value":"/v1/chat"}]',
    '{"requests":120,"windowSeconds":60,"keyBy":"api_key"}', 1, 'usr_demo_admin'
  );

INSERT OR IGNORE INTO audit_events (
  id, workspace_id, actor_type, actor_id, action, resource_type, resource_id, metadata_json
) VALUES (
  'aud_seed', 'ws_demo', 'system', NULL, 'workspace.seeded', 'workspace', 'ws_demo',
  '{"source":"seed/seed.sql"}'
);
