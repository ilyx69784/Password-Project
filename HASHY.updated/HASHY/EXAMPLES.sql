-- Open data/auditor.db with a SQLite client (DB Browser for SQLite or the VS Code
-- SQLite extension). Run SELECT queries only; edit data through the app.

-- 1. Accounts (hash_format = source-declared algorithm for 32-hex values)
SELECT id, username, account_type, password_age_days, hash_format, enabled,
       substr(hash_string, 1, 6) || '…' AS hash_preview
FROM accounts;

-- 2. The single password policy used by the audit AND the strength checker
SELECT * FROM password_policy;

-- 3. Breach data: algorithm-aware, every row has a documented source
SELECT algorithm, source, COUNT(*) AS entries
FROM breach_entries GROUP BY algorithm, source;

-- 4. Recent scans (newest first)
SELECT id, created_at, accounts_checked, critical_count, warning_count,
       compliant_count, inactive_count, ROUND(avg_risk, 1) AS avg_risk
FROM audit_runs ORDER BY id DESC;

-- 5. Saved details + remediation for the newest scan
SELECT username, hash_algorithm, risk_score, status, issue_codes, issues
FROM audit_results
WHERE run_id = (SELECT MAX(id) FROM audit_runs)
ORDER BY risk_score DESC;

-- 6. Risk trend: per-account change between the two newest scans
WITH latest AS (SELECT MAX(id) AS id FROM audit_runs),
     prev   AS (SELECT MAX(id) AS id FROM audit_runs WHERE id < (SELECT id FROM latest))
SELECT n.username, o.risk_score AS previous, n.risk_score AS current,
       n.risk_score - o.risk_score AS delta
FROM audit_results n
LEFT JOIN audit_results o ON o.username = n.username AND o.run_id = (SELECT id FROM prev)
WHERE n.run_id = (SELECT id FROM latest);

-- 7. Password strength evaluations (NO plaintext passwords)
SELECT id, created_at, ROUND(entropy, 2) AS entropy, rating, compliant,
       checks_passed, checks_total
FROM strength_checks ORDER BY id DESC;

-- 8. Schema version (PRAGMA user_version) and integrity
PRAGMA user_version;
PRAGMA integrity_check;
