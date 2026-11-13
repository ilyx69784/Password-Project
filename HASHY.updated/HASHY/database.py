"""SQLite persistence for HASHY.

Data protection rules:
- The RUNTIME database lives in data/auditor.db (override: HASHY_DB env var)
  and is never shipped. Sample data lives in sample_data.py and is only used
  to seed a new runtime database.
- Plaintext passwords are never stored. Hash strings are never exported to
  CSV and are masked in the GUI.
- Schema changes go through numbered migrations (PRAGMA user_version). An
  existing database is backed up automatically before it is migrated.
"""
from contextlib import contextmanager
import csv
from datetime import datetime
import os
from pathlib import Path
import re
import shutil
import sqlite3

from models import DECLARABLE_FORMATS, AccountType, SystemPolicy, TrafficLight
import sample_data

APP_DIR = Path(__file__).resolve().parent
RUNTIME_DIR = APP_DIR / "data"
DEFAULT_DB_PATH = Path(os.environ.get("HASHY_DB", RUNTIME_DIR / "auditor.db"))
LEGACY_DB_PATH = APP_DIR / "auditor.db"   # location used by the original build
SCHEMA_VERSION = 2
BREACH_ALGORITHMS = ("NTLM", "MD5")
_HEX32 = re.compile(r"^[0-9A-Fa-f]{32}$")


def _now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def mask_hash(value: str) -> str:
    """Display form of a hash: enough to tell records apart, not to reuse."""
    if not value:
        return "(empty)"
    return f"{value[:6]}…[{len(value)} chars]"


def safe_csv_cell(value):
    """Neutralise spreadsheet formula injection in exported text."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _restrict_permissions(path: Path, mode: int):
    if os.name == "posix":
        try:
            os.chmod(path, mode)
        except OSError:
            pass


# ----------------------------------------------------------------------
# Schema: v1 is the original project's schema, unchanged, so old databases
# and new ones follow exactly the same migration path.
# ----------------------------------------------------------------------
SCHEMA_V1 = """
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
"""

_ACCOUNT_TYPES_SQL = ", ".join(f"'{t.value}'" for t in AccountType)
_FORMATS_SQL = ", ".join(f"'{f}'" for f in DECLARABLE_FORMATS)


def _migrate_v1_to_v2(conn):
    ex = conn.execute
    # accounts: declared source format + validation triggers (SQLite cannot
    # add CHECK constraints with ALTER TABLE).
    ex("ALTER TABLE accounts ADD COLUMN hash_format TEXT NOT NULL DEFAULT ''")
    for op in ("INSERT", "UPDATE"):
        ex(f"""
            CREATE TRIGGER IF NOT EXISTS accounts_validate_{op.lower()}
            BEFORE {op} ON accounts
            WHEN NEW.account_type NOT IN ({_ACCOUNT_TYPES_SQL})
              OR NEW.hash_format NOT IN ({_FORMATS_SQL})
              OR length(trim(NEW.username)) = 0
            BEGIN SELECT RAISE(ABORT, 'invalid account_type, hash_format or username'); END
        """)
    # Truncated placeholders from the original seed -> format-valid synthetic
    # values. User-entered hashes are left untouched.
    for placeholder, kind in sample_data.LEGACY_PLACEHOLDERS.items():
        ex("UPDATE accounts SET hash_string = ? WHERE hash_string = ?",
           (sample_data.synthetic_crypt(kind), placeholder))
    # Legacy AD sample accounts store NTLM: declare it.
    ex("UPDATE accounts SET hash_format = 'NTLM' WHERE hash_string = ?",
       (sample_data.LEGACY_SAMPLE_NTLM,))

    # password_policy: one source of truth for audit + strength checker.
    ex("ALTER TABLE password_policy ADD COLUMN max_length INTEGER NOT NULL DEFAULT 64")
    ex("ALTER TABLE password_policy ADD COLUMN min_entropy_bits REAL NOT NULL DEFAULT 60")
    # Legacy conflict: policy said 8, checker enforced 12. Keep the stricter.
    ex("UPDATE password_policy SET min_length = MAX(min_length, 12)")

    # breach data: algorithm-aware, with provenance.
    ex("""
        CREATE TABLE breach_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash_value TEXT NOT NULL,
            algorithm TEXT NOT NULL CHECK (algorithm IN ('NTLM', 'MD5')),
            source TEXT NOT NULL,
            added_at TEXT NOT NULL,
            UNIQUE (hash_value, algorithm)
        )
    """)
    for (value,) in ex("SELECT hash_string FROM breached_hashes").fetchall():
        if _HEX32.match(value):
            source = (sample_data.LEGACY_BREACH_SOURCE
                      if value.upper() == sample_data.LEGACY_SAMPLE_NTLM
                      else "Migrated from legacy breached_hashes (assumed NTLM)")
            ex("INSERT OR IGNORE INTO breach_entries (hash_value, algorithm, source, added_at) "
               "VALUES (?, 'NTLM', ?, ?)", (value.upper(), source, _now()))
    ex("DROP TABLE breached_hashes")
    import strength_checker  # documented, reproducible sample entries
    ex_many = conn.executemany
    ex_many("INSERT OR IGNORE INTO breach_entries (hash_value, algorithm, source, added_at) "
            "VALUES (?, ?, ?, ?)",
            [(h, alg, src, _now()) for h, alg, src in
             sample_data.sample_breach_entries(strength_checker.COMMON_PASSWORDS)])

    # audit history: inactive accounts, average risk, issue codes, remediation.
    ex("ALTER TABLE audit_runs ADD COLUMN inactive_count INTEGER NOT NULL DEFAULT 0")
    ex("ALTER TABLE audit_runs ADD COLUMN avg_risk REAL")
    ex("ALTER TABLE audit_results ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
    ex("ALTER TABLE audit_results ADD COLUMN issue_codes TEXT NOT NULL DEFAULT ''")
    ex("ALTER TABLE audit_results ADD COLUMN remediation TEXT NOT NULL DEFAULT ''")
    ex("""UPDATE audit_runs SET avg_risk =
          (SELECT AVG(risk_score) FROM audit_results WHERE run_id = audit_runs.id)""")

    ex("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")


MIGRATIONS = {1: _migrate_v1_to_v2}   # from_version -> function


class Database:
    def __init__(self, path=None):
        if path is None:
            path = DEFAULT_DB_PATH
            self._adopt_legacy_db(Path(path))
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir = self.path.parent / "backups"
        self.initialize()

    @staticmethod
    def _adopt_legacy_db(target: Path):
        """Copy an old auditor.db (beside main.py) into data/ once, so scan
        history survives the move to a separate runtime location."""
        if not target.exists() and LEGACY_DB_PATH.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(LEGACY_DB_PATH, target)

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Creation, migration, seeding
    # ------------------------------------------------------------------
    def schema_version(self):
        with self.connect() as conn:
            return conn.execute("PRAGMA user_version").fetchone()[0]

    def initialize(self):
        fresh = not self.path.exists() or self.path.stat().st_size == 0
        with self.connect() as conn:
            conn.executescript(SCHEMA_V1)
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                conn.execute("PRAGMA user_version = 1")
                version = 1
        _restrict_permissions(self.path, 0o600)

        if version < SCHEMA_VERSION and not fresh:
            self.backup(label=f"pre-migration-v{SCHEMA_VERSION}")
        while version < SCHEMA_VERSION:
            self._apply_migration(version)
            version += 1
        if fresh:
            self._seed()

    def _apply_migration(self, from_version):
        conn = sqlite3.connect(str(self.path), isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            MIGRATIONS[from_version](conn)
            conn.execute(f"PRAGMA user_version = {from_version + 1}")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def _seed(self, conn=None):
        import strength_checker  # local import avoids a cycle at module load
        own = conn is None
        ctx = self.connect() if own else None
        conn = ctx.__enter__() if own else conn
        try:
            p = sample_data.SAMPLE_POLICY
            conn.execute("""
                INSERT OR REPLACE INTO password_policy (id, min_length, require_complexity,
                    max_age_days, lockout_threshold, max_length, min_entropy_bits)
                VALUES (1, ?, ?, ?, ?, ?, ?)""",
                (p["min_length"], p["require_complexity"], p["max_age_days"],
                 p["lockout_threshold"], p["max_length"], p["min_entropy_bits"]))
            conn.executemany("""
                INSERT INTO accounts (username, account_type, password_age_days,
                                      hash_string, hash_format, enabled)
                VALUES (?, ?, ?, ?, ?, ?)""",
                [(u, t.value, a, h, f, e) for u, t, a, h, f, e in sample_data.SAMPLE_ACCOUNTS])
            conn.executemany("""
                INSERT OR IGNORE INTO breach_entries (hash_value, algorithm, source, added_at)
                VALUES (?, ?, ?, ?)""",
                [(h, alg, src, _now()) for h, alg, src in
                 sample_data.sample_breach_entries(strength_checker.COMMON_PASSWORDS)])
        finally:
            if own:
                ctx.__exit__(None, None, None)

    def reset_to_sample(self):
        """Back up, then replace accounts/policy/breach data with the sample.
        Audit and strength history are kept."""
        backup = self.backup(label="pre-reset")
        with self.connect() as conn:
            conn.execute("DELETE FROM accounts")
            conn.execute("DELETE FROM breach_entries")
            conn.execute("DELETE FROM password_policy")
            self._seed(conn)
        return backup

    # ------------------------------------------------------------------
    # Backup, restore, integrity
    # ------------------------------------------------------------------
    def backup(self, dest=None, label="manual"):
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        _restrict_permissions(self.backup_dir, 0o700)
        if dest is None:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
            dest = self.backup_dir / f"auditor-{label}-{stamp}.db"
        dest = Path(dest)
        src = sqlite3.connect(str(self.path))
        dst = sqlite3.connect(str(dest))
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        _restrict_permissions(dest, 0o600)
        return dest

    def restore(self, backup_path):
        """Replace the runtime DB with a backup (current DB is backed up first)."""
        backup_path = Path(backup_path)
        check = sqlite3.connect(str(backup_path))
        try:
            if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Backup failed integrity_check; not restored")
        finally:
            check.close()
        safety = self.backup(label="pre-restore")
        src = sqlite3.connect(str(backup_path))
        dst = sqlite3.connect(str(self.path))
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        self.initialize()   # migrates an older backup if needed
        return safety

    def integrity_report(self):
        with self.connect() as conn:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            fk = conn.execute("PRAGMA foreign_key_check").fetchall()
            counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                      for t in ("accounts", "breach_entries", "audit_runs",
                                "audit_results", "strength_checks")}
            version = conn.execute("PRAGMA user_version").fetchone()[0]
        backups = sorted(self.backup_dir.glob("*.db")) if self.backup_dir.exists() else []
        return {"integrity_check": integrity, "foreign_key_violations": len(fk),
                "schema_version": version, "row_counts": counts,
                "backups": len(backups),
                "latest_backup": backups[-1].name if backups else None}

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------
    def get_setting(self, key, default=None):
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key, value):
        with self.connect() as conn:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                         (key, str(value)))

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------
    def get_accounts(self):
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT username, account_type, password_age_days, hash_string,
                       hash_format, enabled
                FROM accounts ORDER BY id""").fetchall()
        return [{
            "username": r["username"],
            "type": AccountType(r["account_type"]),
            "password_age_days": r["password_age_days"],
            "hash_string": r["hash_string"],
            "hash_format": r["hash_format"],
            "enabled": bool(r["enabled"]),
        } for r in rows]

    def add_account(self, username, account_type, password_age_days, hash_string,
                    enabled=True, hash_format=""):
        username = username.strip()
        if not username:
            raise ValueError("Username cannot be empty")
        try:
            age = int(password_age_days)
        except (TypeError, ValueError):
            raise ValueError("Password age must be a whole number of days")
        if age < 0:
            raise ValueError("Password age cannot be negative")
        if not isinstance(account_type, AccountType):
            account_type = AccountType(account_type)
        if hash_format not in DECLARABLE_FORMATS:
            raise ValueError(f"hash_format must be one of {sorted(DECLARABLE_FORMATS)}")
        with self.connect() as conn:
            conn.execute("""
                INSERT INTO accounts (username, account_type, password_age_days,
                                      hash_string, hash_format, enabled)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (username, account_type.value, age, hash_string.strip(), hash_format,
                 int(enabled)))

    def delete_account(self, username):
        with self.connect() as conn:
            conn.execute("DELETE FROM accounts WHERE username = ?", (username,))

    def set_account_enabled(self, username, enabled):
        with self.connect() as conn:
            conn.execute("UPDATE accounts SET enabled = ? WHERE username = ?",
                         (int(bool(enabled)), username))

    # ------------------------------------------------------------------
    # Policy (single source of truth)
    # ------------------------------------------------------------------
    def get_policy(self):
        with self.connect() as conn:
            row = conn.execute("""
                SELECT min_length, require_complexity, max_age_days, lockout_threshold,
                       max_length, min_entropy_bits
                FROM password_policy WHERE id = 1""").fetchone()
        if row is None:
            raise RuntimeError("Password policy is missing in the database")
        return SystemPolicy(
            min_length=row["min_length"],
            require_complexity=bool(row["require_complexity"]),
            max_age_days=row["max_age_days"],
            lockout_threshold=row["lockout_threshold"],
            max_length=row["max_length"],
            min_entropy_bits=row["min_entropy_bits"],
        )

    def update_policy(self, policy: SystemPolicy):
        if not 1 <= policy.min_length <= policy.max_length:
            raise ValueError("Require 1 <= min_length <= max_length")
        if policy.max_length < 64:
            raise ValueError("max_length below 64 conflicts with NIST SP 800-63B-4 (allow >= 64)")
        if policy.max_age_days < 1 or policy.lockout_threshold < 0 or policy.min_entropy_bits < 0:
            raise ValueError("Age must be >= 1; lockout and entropy must be >= 0")
        with self.connect() as conn:
            conn.execute("""
                UPDATE password_policy SET min_length = ?, require_complexity = ?,
                    max_age_days = ?, lockout_threshold = ?, max_length = ?,
                    min_entropy_bits = ? WHERE id = 1""",
                (policy.min_length, int(policy.require_complexity), policy.max_age_days,
                 policy.lockout_threshold, policy.max_length, policy.min_entropy_bits))

    # ------------------------------------------------------------------
    # Breach data (algorithm-aware, documented)
    # ------------------------------------------------------------------
    def get_breached_hashes(self):
        """{algorithm: {normalized hash values}} for the auditor."""
        with self.connect() as conn:
            rows = conn.execute("SELECT hash_value, algorithm FROM breach_entries").fetchall()
        data = {alg: set() for alg in BREACH_ALGORITHMS}
        for r in rows:
            data[r["algorithm"]].add(r["hash_value"].upper())
        return data

    def get_breach_summary(self):
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT algorithm, source, COUNT(*) AS entries, MIN(added_at) AS first_added
                FROM breach_entries GROUP BY algorithm, source
                ORDER BY algorithm, source""").fetchall()
        return [dict(r) for r in rows]

    def add_breach_entry(self, hash_value, algorithm, source):
        algorithm = algorithm.upper()
        if algorithm not in BREACH_ALGORITHMS:
            raise ValueError(f"Algorithm must be one of {BREACH_ALGORITHMS}")
        if not _HEX32.match(hash_value):
            raise ValueError("NTLM/MD5 values must be 32 hexadecimal characters")
        if not source.strip():
            raise ValueError("A source (provenance) is required")
        with self.connect() as conn:
            cur = conn.execute("""
                INSERT OR IGNORE INTO breach_entries (hash_value, algorithm, source, added_at)
                VALUES (?, ?, ?, ?)""", (hash_value.upper(), algorithm, source.strip(), _now()))
            return cur.rowcount == 1

    def import_breach_file(self, path, algorithm, source):
        """Import one hash per line; 'HASH' or 'HASH:COUNT' (HIBP Pwned
        Passwords format). Returns (added, duplicates, rejected)."""
        algorithm = algorithm.upper()
        if algorithm not in BREACH_ALGORITHMS:
            raise ValueError(f"Algorithm must be one of {BREACH_ALGORITHMS}")
        if not source.strip():
            raise ValueError("A source (provenance) is required")
        added = dup = rejected = 0
        batch = []
        stamp = _now()
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                value = line.strip().split(":", 1)[0]
                if not value or value.startswith("#"):
                    continue
                if not _HEX32.match(value):
                    rejected += 1
                    continue
                batch.append((value.upper(), algorithm, source.strip(), stamp))
        with self.connect() as conn:
            before = conn.execute("SELECT COUNT(*) FROM breach_entries").fetchone()[0]
            conn.executemany("""
                INSERT OR IGNORE INTO breach_entries (hash_value, algorithm, source, added_at)
                VALUES (?, ?, ?, ?)""", batch)
            after = conn.execute("SELECT COUNT(*) FROM breach_entries").fetchone()[0]
        added = after - before
        dup = len(batch) - added
        return added, dup, rejected

    # ------------------------------------------------------------------
    # Audit runs, history, trends
    # ------------------------------------------------------------------
    def save_audit(self, results):
        """Save a scan and each user's result atomically; return the run ID."""
        def count(light):
            return sum(1 for r in results if r["status"] == light.value)
        active = [r["risk_score"] for r in results if r.get("enabled", True)]
        avg = sum(active) / len(active) if active else None
        with self.connect() as conn:
            cur = conn.execute("""
                INSERT INTO audit_runs (created_at, accounts_checked, critical_count,
                    warning_count, compliant_count, inactive_count, avg_risk)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (_now(), len(results), count(TrafficLight.RED), count(TrafficLight.YELLOW),
                 count(TrafficLight.GREEN), count(TrafficLight.INACTIVE), avg))
            run_id = cur.lastrowid
            conn.executemany("""
                INSERT INTO audit_results (run_id, username, account_type, hash_algorithm,
                    age_days, risk_score, status, issues, enabled, issue_codes, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(run_id, r["username"], r["type"], r["algo"], r["age"], r["risk_score"],
                  r["status"], r["issues"], int(r.get("enabled", True)),
                  ",".join(r.get("issue_codes", [])), r.get("remediation", ""))
                 for r in results])
        return run_id

    def get_audit_runs(self, limit=100):
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM audit_runs ORDER BY id DESC LIMIT ?",
                                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_audit_results(self, run_id):
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT username, account_type, hash_algorithm, age_days, risk_score,
                       status, issues, enabled, issue_codes, remediation
                FROM audit_results WHERE run_id = ? ORDER BY id""", (run_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_previous_run_id(self, run_id):
        with self.connect() as conn:
            row = conn.execute("SELECT MAX(id) FROM audit_runs WHERE id < ?",
                               (run_id,)).fetchone()
        return row[0]

    def compare_runs(self, run_id, previous_id=None):
        """Per-account risk change between two runs (default: the run before)."""
        previous_id = previous_id or self.get_previous_run_id(run_id)
        current = {r["username"]: r for r in self.get_audit_results(run_id)}
        before = {r["username"]: r for r in self.get_audit_results(previous_id)} if previous_id else {}
        rows = []
        for name in sorted(set(current) | set(before)):
            new, old = current.get(name), before.get(name)
            if new and not old:
                change, delta = "New account", None
            elif old and not new:
                change, delta = "Removed", None
            else:
                delta = new["risk_score"] - old["risk_score"]
                change = "Improved" if delta < 0 else "Worse" if delta > 0 else "Unchanged"
                if new["status"] != old["status"] and delta == 0:
                    change = "Status changed"
            rows.append({
                "username": name,
                "previous_risk": old["risk_score"] if old else None,
                "current_risk": new["risk_score"] if new else None,
                "delta": delta,
                "previous_status": old["status"] if old else "",
                "current_status": new["status"] if new else "",
                "change": change,
            })
        return previous_id, rows

    def get_trend(self, limit=20):
        """Oldest -> newest run summaries for charting."""
        runs = self.get_audit_runs(limit)
        return list(reversed(runs))

    def export_run_csv(self, run_id, path):
        """Export one saved run. Hash strings are never exported."""
        rows = self.get_audit_results(run_id)
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["Run", "Username", "Account Type", "Hash Algorithm", "Age (Days)",
                        "Enabled", "Risk Score", "Status", "Issue Codes", "Issues",
                        "Remediation"])
            for r in rows:
                w.writerow([run_id] + [safe_csv_cell(v) for v in (
                    r["username"], r["account_type"], r["hash_algorithm"], r["age_days"],
                    "Yes" if r["enabled"] else "No", r["risk_score"], r["status"],
                    r["issue_codes"], r["issues"].replace("\n", " | "),
                    r["remediation"].replace("\n", " | "))])
        return len(rows)

    # ------------------------------------------------------------------
    # Strength checks (metadata only)
    # ------------------------------------------------------------------
    def save_strength_check(self, entropy, rating, compliant, checks_passed, checks_total):
        """Save only a numerical summary. NEVER save typed passwords."""
        with self.connect() as conn:
            conn.execute("""
                INSERT INTO strength_checks (created_at, entropy, rating, compliant,
                    checks_passed, checks_total) VALUES (?, ?, ?, ?, ?, ?)""",
                (_now(), entropy, rating, int(compliant), checks_passed, checks_total))

    def get_strength_checks(self, limit=100):
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM strength_checks ORDER BY id DESC LIMIT ?",
                                (limit,)).fetchall()
        return [dict(r) for r in rows]
