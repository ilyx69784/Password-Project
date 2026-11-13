"""Integration tests: migrations, data protection, breach data, history."""
import csv
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from auditor import SecurityAuditor
from connector import DataSourceConnector
from database import SCHEMA_VERSION, Database, safe_csv_cell
from models import AccountType, SystemPolicy

FIXTURE = Path(__file__).parent / "fixtures" / "legacy_v1.sql"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)

    def scan(self, db):
        c = DataSourceConnector(db)
        res = SecurityAuditor(c.fetch_compromised_hashes()).run_audit(
            c.fetch_accounts(), c.get_system_policy())
        return res, db.save_audit(res)


class MigrationTests(Base):
    def make_legacy(self):
        path = self.root / "legacy.db"
        with closing(sqlite3.connect(path)) as conn:
            conn.executescript(FIXTURE.read_text(encoding="utf-8"))
        return path

    def test_legacy_db_migrates_and_keeps_history(self):
        db = Database(self.make_legacy())
        self.assertEqual(db.schema_version(), SCHEMA_VERSION)
        self.assertEqual(len(db.get_audit_runs()), 1)
        self.assertEqual(len(db.get_strength_checks()), 1)
        self.assertAlmostEqual(db.get_audit_runs()[0]["avg_risk"], 50.0)
        self.assertEqual(db.get_policy().min_length, 12)        # stricter of 8 / 12
        self.assertTrue(any(p.name.startswith("auditor-pre-migration")
                            for p in db.backup_dir.glob("*.db")))

    def test_migrated_seed_audits_like_fresh_seed(self):
        db = Database(self.make_legacy())
        res, _ = self.scan(db)
        by = {r["username"]: r for r in res}
        self.assertEqual(by["anna.manager"]["status"], "🟢 Compliant")   # placeholder fixed
        self.assertIn("PASSWORD_REUSE", by["service_sql"]["issue_codes"])
        self.assertIn("BREACHED", by["admin_ivan"]["issue_codes"])

    def test_migration_is_idempotent(self):
        path = self.make_legacy()
        Database(path)
        Database(path)                                         # second open: no-op
        self.assertEqual(Database(path).schema_version(), SCHEMA_VERSION)

    def test_fresh_db_is_seeded_once(self):
        path = self.root / "fresh.db"
        Database(path)
        self.assertEqual(len(Database(path).get_accounts()), 4)


class ProtectionTests(Base):
    def test_triggers_reject_invalid_account_type_and_format(self):
        db = Database(self.root / "t.db")
        with self.assertRaises(sqlite3.IntegrityError), db.connect() as conn:
            conn.execute("INSERT INTO accounts (username, account_type) VALUES ('x', 'Root')")
        with self.assertRaises(ValueError):
            db.add_account("y", AccountType.STANDARD, 1, "abc", hash_format="SHA1")
        with self.assertRaises(ValueError):
            db.add_account("z", AccountType.STANDARD, "ten", "abc")

    def test_backup_and_restore_roundtrip(self):
        db = Database(self.root / "t.db")
        backup = db.backup()
        db.delete_account("admin_ivan")
        self.assertEqual(len(db.get_accounts()), 3)
        safety = db.restore(backup)
        self.assertEqual(len(db.get_accounts()), 4)
        self.assertTrue(safety.exists())
        self.assertEqual(db.integrity_report()["integrity_check"], "ok")

    def test_restore_rejects_corrupt_file(self):
        db = Database(self.root / "t.db")
        bad = self.root / "bad.db"
        bad.write_bytes(b"not a database" * 100)
        with self.assertRaises((sqlite3.DatabaseError, ValueError)):
            db.restore(bad)
        self.assertEqual(len(db.get_accounts()), 4)

    def test_run_export_has_no_hashes_and_neutralises_formulas(self):
        db = Database(self.root / "t.db")
        db.add_account("=HYPERLINK(\"x\")", AccountType.STANDARD, 1, "")
        _, run_id = self.scan(db)
        out = self.root / "run.csv"
        db.export_run_csv(run_id, out)
        text = out.read_text(encoding="utf-8-sig")
        for acc in db.get_accounts():
            if acc["hash_string"]:
                self.assertNotIn(acc["hash_string"], text)
        with out.open(encoding="utf-8-sig") as fh:
            rows = list(csv.reader(fh, delimiter=";"))
        self.assertTrue(any(r[1].startswith("'=") for r in rows[1:]))
        self.assertEqual(safe_csv_cell("@cmd"), "'@cmd")

    def test_policy_validation(self):
        db = Database(self.root / "t.db")
        bad = SystemPolicy(min_length=20, require_complexity=False, max_age_days=90,
                           lockout_threshold=5, max_length=10)
        with self.assertRaises(ValueError):
            db.update_policy(bad)


class BreachAndHistoryTests(Base):
    def test_breach_entries_are_documented(self):
        db = Database(self.root / "t.db")
        summary = db.get_breach_summary()
        self.assertTrue(all(row["source"] for row in summary))
        self.assertEqual({row["algorithm"] for row in summary}, {"NTLM", "MD5"})

    def test_import_hibp_format(self):
        db = Database(self.root / "t.db")
        f = self.root / "list.txt"
        f.write_text("# comment\n" + "A" * 32 + ":12\n" + "b" * 32 + "\nnot-a-hash\n"
                     + "A" * 32 + "\n")
        added, dup, rejected = db.import_breach_file(f, "NTLM", "Unit test list")
        self.assertEqual((added, dup, rejected), (2, 1, 1))
        with self.assertRaises(ValueError):
            db.import_breach_file(f, "NTLM", "   ")
        with self.assertRaises(ValueError):
            db.import_breach_file(f, "SHA1", "x")

    def test_compare_runs_and_trend(self):
        db = Database(self.root / "t.db")
        _, first = self.scan(db)
        db.delete_account("guest_user")
        db.add_account("new_user", AccountType.STANDARD, 200, "")
        db.set_account_enabled("admin_ivan", False)
        _, second = self.scan(db)
        prev, rows = db.compare_runs(second)
        self.assertEqual(prev, first)
        change = {r["username"]: r["change"] for r in rows}
        self.assertEqual(change["guest_user"], "Removed")
        self.assertEqual(change["new_user"], "New account")
        self.assertEqual(db.get_audit_runs()[0]["inactive_count"], 1)
        self.assertEqual([r["id"] for r in db.get_trend()], [first, second])

    def test_settings_roundtrip(self):
        db = Database(self.root / "t.db")
        db.set_setting("theme", "light")
        self.assertEqual(Database(self.root / "t.db").get_setting("theme"), "light")


if __name__ == "__main__":
    unittest.main()
