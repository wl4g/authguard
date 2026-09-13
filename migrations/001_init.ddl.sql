-- =============================================================================
-- AuthGuard canonical IAM schema
--
-- AuthN and AuthZ are independently deployable services over one logical IAM
-- datastore. This file is the only authoritative schema definition. Table
-- ownership is still explicit: AuthN owns iam_principal_identity; AuthZ owns
-- role/action/binding data; iam_principal is their shared aggregate root.
-- The SQL subset is accepted by both SQLite and PostgreSQL.
-- =============================================================================

CREATE TABLE IF NOT EXISTS iam_principal (
  id TEXT PRIMARY KEY CHECK (TRIM(id) <> ''),
  kind TEXT NOT NULL CHECK (kind IN ('USER', 'WORKLOAD', 'GROUP')),
  display_name TEXT NOT NULL CHECK (TRIM(display_name) <> ''),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISABLED')),
  authorization_state JSON NOT NULL DEFAULT '{}',
  last_seen_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_iam_principal_display_name_prefix
  ON iam_principal (LOWER(display_name));

CREATE TABLE IF NOT EXISTS iam_principal_identity (
  principal_id TEXT NOT NULL REFERENCES iam_principal(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (TRIM(provider) <> ''),
  issuer TEXT NOT NULL CHECK (TRIM(issuer) <> ''),
  subject TEXT NOT NULL CHECK (TRIM(subject) <> ''),
  claims JSON NOT NULL DEFAULT '{}',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_authenticated_at TIMESTAMP,
  PRIMARY KEY (principal_id, provider, issuer, subject),
  UNIQUE (provider, issuer, subject)
);

CREATE INDEX IF NOT EXISTS idx_iam_principal_identity_principal
  ON iam_principal_identity (principal_id);

CREATE TABLE IF NOT EXISTS iam_authn_flow (
  state_hash TEXT PRIMARY KEY CHECK (TRIM(state_hash) <> ''),
  provider TEXT NOT NULL CHECK (TRIM(provider) <> ''),
  return_uri TEXT NOT NULL DEFAULT '',
  nonce TEXT,
  pkce_verifier TEXT,
  expires_at_epoch_seconds BIGINT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_iam_authn_flow_expiry
  ON iam_authn_flow (expires_at_epoch_seconds);

CREATE TABLE IF NOT EXISTS iam_action (
  identifier TEXT NOT NULL CHECK (TRIM(identifier) <> ''),
  description TEXT NOT NULL DEFAULT '',
  route_matchers JSON NOT NULL DEFAULT '[]',
  PRIMARY KEY (identifier)
);

CREATE TABLE IF NOT EXISTS iam_role (
  id TEXT NOT NULL CHECK (TRIM(id) <> ''),
  name TEXT NOT NULL CHECK (TRIM(name) <> ''),
  description TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (id),
  UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS iam_role_action (
  role_id TEXT NOT NULL,
  action_identifier TEXT NOT NULL,
  PRIMARY KEY (role_id, action_identifier),
  FOREIGN KEY (role_id) REFERENCES iam_role(id) ON DELETE CASCADE,
  FOREIGN KEY (action_identifier) REFERENCES iam_action(identifier) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS iam_role_binding (
  id TEXT NOT NULL CHECK (TRIM(id) <> ''),
  principal_id TEXT NOT NULL REFERENCES iam_principal(id) ON DELETE RESTRICT,
  role_id TEXT NOT NULL,
  effect TEXT NOT NULL CHECK (effect IN ('ALLOW', 'DENY')),
  resource_urn TEXT NOT NULL CHECK (TRIM(resource_urn) LIKE 'urn:iam:%'),
  conditions JSON NOT NULL DEFAULT '{}',
  PRIMARY KEY (id),
  FOREIGN KEY (role_id) REFERENCES iam_role(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_iam_role_binding_principal
  ON iam_role_binding (principal_id);

CREATE INDEX IF NOT EXISTS idx_iam_role_binding_role
  ON iam_role_binding (role_id);

CREATE INDEX IF NOT EXISTS idx_iam_role_binding_resource
  ON iam_role_binding (resource_urn);
