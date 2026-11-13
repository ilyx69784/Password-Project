-- Original (v1) HASHY schema + seed, used to test migrations.

CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    account_type TEXT NOT NULL,
    password_age_days INTEGER NOT NULL DEFAULT 0 CHECK (password_age_days >= 0),
    hash_string TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))
);
CREATE TABLE IF NOT EXISTS password_policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    min_length INTEGER NOT NULL,
    require_complexity INTEGER NOT NULL,
    max_age_days INTEGER NOT NULL,
    lockout_threshold INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS breached_hashes (hash_string TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS audit_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    accounts_checked INTEGER NOT NULL,
    critical_count INTEGER NOT NULL,
    warning_count INTEGER NOT NULL,
    compliant_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    account_type TEXT NOT NULL,
    hash_algorithm TEXT NOT NULL,
    age_days INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    status TEXT NOT NULL,
    issues TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_results_run_id ON audit_results(run_id);
CREATE TABLE IF NOT EXISTS strength_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    entropy REAL NOT NULL,
    rating TEXT NOT NULL,
    compliant INTEGER NOT NULL,
    checks_passed INTEGER NOT NULL,
    checks_total INTEGER NOT NULL
);

INSERT INTO password_policy VALUES (1, 8, 1, 90, 5);
INSERT INTO accounts (username, account_type, password_age_days, hash_string, enabled) VALUES
 ('admin_ivan', 'Administrator', 120, '32ED87BDF5FAC7728E709E306CE449F7', 1),
 ('anna.manager', 'Standard User', 15, '$2b$12$eImiTXuWVxfM37uY4JANjQ==.xyz...', 1),
 ('service_sql', 'Service Account', 365, '32ED87BDF5FAC7728E709E306CE449F7', 1),
 ('guest_user', 'Standard User', 5, '$6$saltsalt$vJ1...', 1);
INSERT INTO breached_hashes VALUES ('32ED87BDF5FAC7728E709E306CE449F7');
INSERT INTO audit_runs (created_at, accounts_checked, critical_count, warning_count, compliant_count)
 VALUES ('2026-10-15T23:11:06+05:00', 4, 2, 0, 2);
INSERT INTO audit_results (run_id, username, account_type, hash_algorithm, age_days, risk_score, status, issues) VALUES
 (1, 'admin_ivan', 'Administrator', 'NTLM (Legacy, unsalted)', 120, 100, '🔴 Critical', 'x'),
 (1, 'anna.manager', 'Standard User', 'bcrypt (Modern, salted)', 15, 0, '🟢 Compliant', 'No issues'),
 (1, 'service_sql', 'Service Account', 'NTLM (Legacy, unsalted)', 365, 100, '🔴 Critical', 'x'),
 (1, 'guest_user', 'Standard User', 'SHA-512 (Linux, salted)', 5, 0, '🟢 Compliant', 'No issues');
INSERT INTO strength_checks (created_at, entropy, rating, compliant, checks_passed, checks_total)
 VALUES ('2026-10-15T23:06:21+05:00', 76.15, 'Moderate', 1, 5, 5);
