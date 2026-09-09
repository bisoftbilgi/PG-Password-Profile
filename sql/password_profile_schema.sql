-- password_profile core schema objects
-- Executed automatically during CREATE EXTENSION via extension_sql_file!

-- The control file pins installation to this schema. PostgreSQL creates it
-- when absent, but can also reuse a pre-existing schema. Refuse an untrusted
-- owner instead of installing SECURITY-sensitive objects into a namespace
-- another role controls.
DO $password_profile_schema_owner$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_namespace
         WHERE nspname = 'password_profile'
           AND nspowner = CURRENT_USER::pg_catalog.regrole
    ) THEN
        RAISE EXCEPTION
            'password_profile schema must be owned by the extension installer';
    END IF;
END
$password_profile_schema_owner$;

CREATE TABLE password_profile.login_attempts (
    username TEXT PRIMARY KEY,
    fail_count INT DEFAULT 0,
    last_fail TIMESTAMPTZ DEFAULT now(),
    lockout_until TIMESTAMPTZ
);

CREATE TABLE password_profile.password_history (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    changed_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_pwd_history_user
    ON password_profile.password_history (username, changed_at DESC);

CREATE TABLE password_profile.password_expiry (
    username TEXT PRIMARY KEY,
    last_changed TIMESTAMPTZ DEFAULT now(),
    must_change_by TIMESTAMPTZ,
    grace_logins_remaining INT DEFAULT 0
);

CREATE TABLE password_profile.blacklist (
    password TEXT PRIMARY KEY,
    added_at TIMESTAMPTZ DEFAULT now(),
    reason TEXT
);

-- Idempotency ledger for durable auth-event replay.  The worker inserts the
-- receipt in the same transaction as the event's state change.  Rows are
-- removed only after the corresponding journal batch has been durably deleted.
CREATE TABLE password_profile.auth_event_receipts (
    event_id BYTEA PRIMARY KEY CHECK (octet_length(event_id) = 16),
    processed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
