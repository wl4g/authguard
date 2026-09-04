-- =============================================================================
-- Authguard authorization schema
--
-- This initialization DDL intentionally uses the SQL subset shared by SQLite
-- and PostgreSQL. Backend-specific concurrency control lives in each storage
-- adapter; the authorization schema itself has one canonical definition.
-- =============================================================================

CREATE TABLE IF NOT EXISTS iam_policy (
  id TEXT PRIMARY KEY CHECK (TRIM(id) <> ''),
  name TEXT NOT NULL CHECK (TRIM(name) <> ''),
  description TEXT NOT NULL DEFAULT '',
  revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_iam_policy_singleton
  ON iam_policy ((1));

CREATE TABLE IF NOT EXISTS iam_principal (
  id TEXT PRIMARY KEY CHECK (TRIM(id) <> ''),
  issuer TEXT NOT NULL CHECK (TRIM(issuer) <> ''),
  external_id TEXT NOT NULL CHECK (TRIM(external_id) <> ''),
  kind TEXT NOT NULL CHECK (kind IN ('USER', 'WORKLOAD', 'GROUP')),
  display_name TEXT NOT NULL CHECK (TRIM(display_name) <> ''),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISABLED')),
  attributes JSON NOT NULL DEFAULT '{}',
  last_seen_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (issuer, external_id)
);

CREATE INDEX IF NOT EXISTS idx_iam_principal_display_name_prefix
  ON iam_principal (LOWER(display_name));

CREATE INDEX IF NOT EXISTS idx_iam_principal_external_id_prefix
  ON iam_principal (LOWER(external_id));

CREATE TABLE IF NOT EXISTS iam_action (
  policy_id TEXT NOT NULL REFERENCES iam_policy(id) ON DELETE CASCADE,
  identifier TEXT NOT NULL CHECK (TRIM(identifier) <> ''),
  description TEXT NOT NULL DEFAULT '',
  route_matchers JSON NOT NULL DEFAULT '[]',
  PRIMARY KEY (policy_id, identifier)
);

CREATE TABLE IF NOT EXISTS iam_role (
  policy_id TEXT NOT NULL REFERENCES iam_policy(id) ON DELETE CASCADE,
  id TEXT NOT NULL CHECK (TRIM(id) <> ''),
  name TEXT NOT NULL CHECK (TRIM(name) <> ''),
  description TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (policy_id, id),
  UNIQUE (policy_id, name)
);

CREATE TABLE IF NOT EXISTS iam_role_action (
  policy_id TEXT NOT NULL,
  role_id TEXT NOT NULL,
  action_identifier TEXT NOT NULL,
  PRIMARY KEY (policy_id, role_id, action_identifier),
  FOREIGN KEY (policy_id, role_id)
    REFERENCES iam_role(policy_id, id) ON DELETE CASCADE,
  FOREIGN KEY (policy_id, action_identifier)
    REFERENCES iam_action(policy_id, identifier) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS iam_role_binding (
  policy_id TEXT NOT NULL,
  id TEXT NOT NULL CHECK (TRIM(id) <> ''),
  principal_id TEXT NOT NULL REFERENCES iam_principal(id) ON DELETE RESTRICT,
  role_id TEXT NOT NULL,
  effect TEXT NOT NULL CHECK (effect IN ('ALLOW', 'DENY')),
  resource_urn TEXT NOT NULL CHECK (TRIM(resource_urn) LIKE 'urn:iam:%'),
  conditions JSON NOT NULL DEFAULT '{}',
  PRIMARY KEY (policy_id, id),
  FOREIGN KEY (policy_id, role_id)
    REFERENCES iam_role(policy_id, id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_iam_role_binding_principal
  ON iam_role_binding (principal_id, policy_id);

CREATE INDEX IF NOT EXISTS idx_iam_role_binding_role
  ON iam_role_binding (policy_id, role_id);

CREATE INDEX IF NOT EXISTS idx_iam_role_binding_resource
  ON iam_role_binding (policy_id, resource_urn);
