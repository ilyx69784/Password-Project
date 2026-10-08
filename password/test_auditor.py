# test_auditor.py
"""
Модульные тесты для модуля auditor.py с использованием стандартной библиотеки unittest.
"""
import unittest
from models import SystemPolicy, AccountRecord, AccountType, HashType
from auditor import SecurityAuditor

class TestSecurityAuditor(unittest.TestCase):
    def setUp(self):
        self.breached_db = {"32ED87BDF5FAC7728E709E306CE449F7"}
        self.auditor = SecurityAuditor(compromised_hashes=self.breached_db)
        self.policy = SystemPolicy(min_length=12, require_complexity=True, max_age_days=90, lockout_threshold=5)

    def test_detect_hash_algorithm(self):
        self.assertEqual(self.auditor.detect_hash_algorithm("32ED87BDF5FAC7728E709E306CE449F7"), HashType.NTLM)
        self.assertEqual(self.auditor.detect_hash_algorithm("$2b$12$fakehash"), HashType.BCRYPT)
        self.assertEqual(self.auditor.detect_hash_algorithm("$6$saltsalt$fakehash"), HashType.SHA512_CRYPT)
        self.assertEqual(self.auditor.detect_hash_algorithm("invalid"), HashType.UNKNOWN)

    def test_is_breached(self):
        self.assertTrue(self.auditor.is_breached("32ED87BDF5FAC7728E709E306CE449F7"))
        self.assertFalse(self.auditor.is_breached("A1B2C3D4E5F678901234567890ABCDEF"))

    def test_run_audit_risk_scoring(self):
        accounts = [
            AccountRecord("admin_test", AccountType.ADMIN, 120, "32ED87BDF5FAC7728E709E306CE449F7", True)
        ]
        results = self.auditor.run_audit(accounts, self.policy)
        self.assertEqual(len(results), 1)
        # У администратора с просроченным, скомпрометированным NTLM-хэшем риск должен быть максимальным (100)
        self.assertEqual(results[0].risk_score, 100.0)
        self.assertEqual(results[0].status, "🔴 Критично")

if __name__ == "__main__":
    unittest.main()