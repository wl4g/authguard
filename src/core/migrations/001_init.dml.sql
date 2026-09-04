-- Initialize the single active authorization aggregate without replacing
-- existing state. This statement is idempotent in both SQLite and PostgreSQL.

INSERT INTO iam_policy(id, name, description, revision)
VALUES ('default', 'Default authorization policy', '', 0)
ON CONFLICT(id) DO NOTHING;
