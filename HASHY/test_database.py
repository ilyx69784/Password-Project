"""Integration tests for SQLite persistence. Run: python -m unittest -v"""
import sqlite3
from pathlib import Path
import tempfile
import unittest

from auditor import SecurityAuditor
from connector import DataSourceConnector
from database import Database
from models import AccountType


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "test.db"
        self.db = Database(self.path)

    def test_initial_data_and_policy(self):
        connector = DataSourceConnector(self.db)
        accounts = connector.fetch_accounts()
        self.assertEqual(len(accounts), 4)
        self.assertEqual(connector.get_system_policy().max_age_days, 90)
        self.assertTrue(connector.fetch_compromised_hashes())
        self.assertIsInstance(accounts[0]["type"], AccountType)

    def test_scan_saved_after_reopening(self):
        connector = DataSourceConnector(self.db)
        auditor = SecurityAuditor(connector.fetch_compromised_hashes())
        results = auditor.run_audit(connector.fetch_accounts(), connector.get_system_policy())
        run_id = self.db.save_audit(results)
        reopened = Database(self.path)
        self.assertEqual(len(reopened.get_accounts()), 4)
        self.assertEqual(reopened.get_audit_runs()[0]["id"], run_id)
        self.assertEqual(len(reopened.get_audit_results(run_id)), 4)
        self.assertEqual(reopened.get_audit_runs()[0]["critical_count"], 2)
        self.assertEqual(reopened.get_audit_runs()[0]["compliant_count"], 2)

    def test_accounts_can_be_added_and_deleted(self):
        self.db.add_account("temporary_demo", AccountType.STANDARD, 3, "$6$example$123")
        self.assertEqual(len(self.db.get_accounts()), 5)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.add_account("temporary_demo", AccountType.STANDARD, 3, "$6$example$123")
        self.db.delete_account("temporary_demo")
        self.assertEqual(len(self.db.get_accounts()), 4)

    def test_strength_check_does_not_store_password(self):
        self.db.save_strength_check(70.1, "Moderate", True, 5, 5)
        self.assertEqual(len(self.db.get_strength_checks()), 1)
        with sqlite3.connect(self.path) as conn:
            columns = [row[1] for row in conn.execute("PRAGMA table_info(strength_checks)")]
        self.assertNotIn("password", columns)
        self.assertNotIn("hash_string", columns)


if __name__ == "__main__":
    unittest.main()
