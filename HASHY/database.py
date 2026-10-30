# database.py
"""
SQLite persistence for the educational password security auditor (HASHY).
Stores accounts, policies, breached hashes, and scan run history.
"""
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import sqlite3

from models import AccountType, SystemPolicy

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "auditor.db"

class Database:
    def __init__(self, path=DEFAULT_DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

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

    def initialize(self):
        first_creation = not self.path.exists()
        with self.connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    account_type TEXT NOT NULL,
                    password_age_days INTEGER NOT NULL DEFAULT 0
                        CHECK (password_age_days >= 0),
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
                CREATE TABLE IF NOT EXISTS breached_hashes (
                    hash_string TEXT PRIMARY KEY
                );
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
                CREATE INDEX IF NOT EXISTS ix_audit_results_run_id
                    ON audit_results(run_id);
                CREATE TABLE IF NOT EXISTS strength_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    entropy REAL NOT NULL,
                    rating TEXT NOT NULL,
                    compliant INTEGER NOT NULL,
                    checks_passed INTEGER NOT NULL,
                    checks_total INTEGER NOT NULL
                );
            """)
            if first_creation:
                conn.execute("""
                    INSERT INTO password_policy (
                        id, min_length, require_complexity, max_age_days, lockout_threshold
                    ) VALUES (1, 8, 1, 90, 5)
                """)
                conn.executemany("""
                    INSERT INTO accounts (username, account_type, password_age_days,
                                          hash_string, enabled) VALUES (?, ?, ?, ?, ?)
                """, [
                    ("admin_ivan", AccountType.ADMIN.value, 120,
                     "32ED87BDF5FAC7728E709E306CE449F7", 1),
                    ("anna.manager", AccountType.STANDARD.value, 15,
                     "$2b$12$eImiTXuWVxfM37uY4JANjQ==.xyz...", 1),
                    ("service_sql", AccountType.SERVICE.value, 365,
                     "32ED87BDF5FAC7728E709E306CE449F7", 1),
                    ("guest_user", AccountType.STANDARD.value, 5,
                     "$6$saltsalt$vJ1...", 1),
                ])
                conn.execute(
                    "INSERT INTO breached_hashes (hash_string) VALUES (?)",
                    ("32ED87BDF5FAC7728E709E306CE449F7",),
                )

    def get_accounts(self):
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT username, account_type, password_age_days, hash_string, enabled
                FROM accounts ORDER BY id
            """).fetchall()
        return [
            {
                "username": row["username"],
                "type": AccountType(row["account_type"]),
                "password_age_days": row["password_age_days"],
                "hash_string": row["hash_string"],
                "enabled": bool(row["enabled"]),
            }
            for row in rows
        ]

    def add_account(self, username, account_type, password_age_days, hash_string, enabled=True):
        username = username.strip()
        if not username:
            raise ValueError("Username cannot be empty")
        age = int(password_age_days)
        if age < 0:
            raise ValueError("Password age cannot be negative")
        if not isinstance(account_type, AccountType):
            account_type = AccountType(account_type)
        with self.connect() as conn:
            conn.execute("""
                INSERT INTO accounts (username, account_type, password_age_days,
                                      hash_string, enabled) VALUES (?, ?, ?, ?, ?)
            """, (username, account_type.value, age, hash_string, int(enabled)))

    def delete_account(self, username):
        with self.connect() as conn:
            conn.execute("DELETE FROM accounts WHERE username = ?", (username,))

    def get_policy(self):
        with self.connect() as conn:
            row = conn.execute("""
                SELECT min_length, require_complexity, max_age_days, lockout_threshold
                FROM password_policy WHERE id = 1
            """).fetchone()
        if row is None:
            raise RuntimeError("Password policy is missing in the database")
        return SystemPolicy(
            min_length=row["min_length"],
            require_complexity=bool(row["require_complexity"]),
            max_age_days=row["max_age_days"],
            lockout_threshold=row["lockout_threshold"],
        )

    def get_breached_hashes(self):
        with self.connect() as conn:
            rows = conn.execute("SELECT hash_string FROM breached_hashes").fetchall()
        return {row["hash_string"].upper() for row in rows}

    def save_audit(self, results):
        def count_status(prefix):
            return sum(1 for r in results if r["status"].endswith(prefix))

        with self.connect() as conn:
            cursor = conn.execute("""
                INSERT INTO audit_runs (created_at, accounts_checked,
                                        critical_count, warning_count, compliant_count)
                VALUES (?, ?, ?, ?, ?)
            """, (
                datetime.now().astimezone().isoformat(timespec="seconds"),
                len(results),
                count_status("Critical"),
                count_status("Warning"),
                count_status("Compliant"),
            ))
            run_id = cursor.lastrowid
            conn.executemany("""
                INSERT INTO audit_results (
                    run_id, username, account_type, hash_algorithm, age_days,
                    risk_score, status, issues
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (run_id, r["username"], r["type"], r["algo"], r["age"],
                 r["risk_score"], r["status"], r["issues"])
                for r in results
            ])
        return run_id

    def get_audit_runs(self, limit=100):
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT * FROM audit_runs ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(row) for row in rows]

    def get_audit_results(self, run_id):
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT username, account_type, hash_algorithm, age_days,
                       risk_score, status, issues
                FROM audit_results WHERE run_id = ? ORDER BY id
            """, (run_id,)).fetchall()
        return [dict(row) for row in rows]

    def save_strength_check(self, entropy, rating, compliant, checks_passed, checks_total):
        with self.connect() as conn:
            conn.execute("""
                INSERT INTO strength_checks (
                    created_at, entropy, rating, compliant, checks_passed, checks_total
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().astimezone().isoformat(timespec="seconds"),
                entropy, rating, int(compliant), checks_passed, checks_total,
            ))

    def get_strength_checks(self, limit=100):
        with self.connect() as conn:
            rows = conn.execute("""
                SELECT * FROM strength_checks ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(row) for row in rows]