"""Unit tests for hash interpretation, reuse/breach logic and risk scoring."""
import unittest

from auditor import CRITICAL_THRESHOLD, SecurityAuditor
from hashing import md4, md5_hex, ntlm_hex
from models import AccountType, HashType, SystemPolicy, TrafficLight
from sample_data import synthetic_crypt

POLICY = SystemPolicy(min_length=12, require_complexity=False, max_age_days=90,
                      lockout_threshold=5)
NTLM_PW = ntlm_hex("password")
BCRYPT = synthetic_crypt("bcrypt")
SHA512 = synthetic_crypt("sha512")


def acc(name, h, age=0, fmt="", enabled=True, kind=AccountType.STANDARD):
    return {"username": name, "type": kind, "password_age_days": age, "hash_string": h,
            "hash_format": fmt, "enabled": enabled}


class ReferenceHashTests(unittest.TestCase):
    def test_md4_rfc1320_vectors(self):
        self.assertEqual(md4(b"").hex(), "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(md4(b"abc").hex(), "a448017aaf21d8525fc10ae87aa6729d")

    def test_known_ntlm_and_md5(self):
        self.assertEqual(ntlm_hex("password"), "8846F7EAEE8FB117AD06BDD830B7586C")
        self.assertEqual(md5_hex("password"), "5F4DCC3B5AA765D61D8327DEB882CF99")


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.a = SecurityAuditor({})

    def test_32hex_is_ambiguous_unless_declared(self):
        self.assertEqual(self.a.detect_hash_algorithm(NTLM_PW), HashType.UNSALTED_32HEX)
        self.assertEqual(self.a.detect_hash_algorithm(NTLM_PW, "NTLM"), HashType.NTLM)
        self.assertEqual(self.a.detect_hash_algorithm(NTLM_PW, "MD5"), HashType.MD5)

    def test_valid_salted_formats(self):
        self.assertEqual(self.a.detect_hash_algorithm(BCRYPT), HashType.BCRYPT)
        self.assertEqual(self.a.detect_hash_algorithm(SHA512), HashType.SHA512_CRYPT)
        self.assertEqual(self.a.detect_hash_algorithm("$1$abcdefgh$" + "a" * 22),
                         HashType.MD5_CRYPT)
        self.assertEqual(self.a.detect_hash_algorithm("$5$salt$" + "b" * 43),
                         HashType.SHA256_CRYPT)

    def test_truncated_legacy_placeholders_are_malformed(self):
        for h in ("$2b$12$eImiTXuWVxfM37uY4JANjQ==.xyz...", "$6$saltsalt$vJ1...", "$6$x$123"):
            self.assertEqual(self.a.detect_hash_algorithm(h), HashType.MALFORMED, h)

    def test_empty_and_unknown(self):
        self.assertEqual(self.a.detect_hash_algorithm(""), HashType.EMPTY)
        self.assertEqual(self.a.detect_hash_algorithm("hello"), HashType.UNKNOWN)
        self.assertEqual(self.a.detect_hash_algorithm("A" * 31), HashType.UNKNOWN)


class ReuseAndBreachTests(unittest.TestCase):
    def test_unsalted_reuse_detected_case_insensitively(self):
        res = SecurityAuditor({}).run_audit(
            [acc("a", NTLM_PW, fmt="NTLM"), acc("b", NTLM_PW.lower(), fmt="NTLM")], POLICY)
        for r in res:
            self.assertIn("PASSWORD_REUSE", r["issue_codes"])

    def test_different_salted_hashes_never_claim_reuse(self):
        res = SecurityAuditor({}).run_audit(
            [acc("a", synthetic_crypt("sha512")), acc("b", synthetic_crypt("sha512"))], POLICY)
        for r in res:
            self.assertNotIn("PASSWORD_REUSE", r["issue_codes"])
            self.assertEqual(r["status"], TrafficLight.GREEN.value)

    def test_identical_salted_string_is_a_copied_record(self):
        res = SecurityAuditor({}).run_audit([acc("a", SHA512), acc("b", SHA512)], POLICY)
        for r in res:
            self.assertIn("DUPLICATE_SALTED_RECORD", r["issue_codes"])
            self.assertNotIn("PASSWORD_REUSE", r["issue_codes"])

    def test_breach_match_is_algorithm_aware(self):
        auditor = SecurityAuditor({"NTLM": set(), "MD5": {NTLM_PW}})
        declared_ntlm = auditor.run_audit([acc("a", NTLM_PW, fmt="NTLM")], POLICY)[0]
        self.assertNotIn("BREACHED", declared_ntlm["issue_codes"])
        declared_md5 = auditor.run_audit([acc("a", NTLM_PW, fmt="MD5")], POLICY)[0]
        self.assertIn("BREACHED", declared_md5["issue_codes"])

    def test_ambiguous_value_checks_both_algorithms(self):
        r = SecurityAuditor({"NTLM": {NTLM_PW}}).run_audit([acc("a", NTLM_PW)], POLICY)[0]
        self.assertIn("BREACHED", r["issue_codes"])
        self.assertIn("AMBIGUOUS_FORMAT", r["issue_codes"])

    def test_crypt_strings_match_case_sensitively(self):
        auditor = SecurityAuditor({"SHA512_CRYPT": {SHA512}})
        self.assertTrue(auditor.is_breached(SHA512, HashType.SHA512_CRYPT))
        self.assertFalse(auditor.is_breached(SHA512.swapcase(), HashType.SHA512_CRYPT))

    def test_legacy_flat_set_input_still_supported(self):
        r = SecurityAuditor({NTLM_PW}).run_audit([acc("a", NTLM_PW, fmt="NTLM")], POLICY)[0]
        self.assertIn("BREACHED", r["issue_codes"])


class ScoringBoundaryTests(unittest.TestCase):
    def run_one(self, account, breaches=None):
        return SecurityAuditor(breaches or {}).run_audit([account], POLICY)[0]

    def test_age_boundary(self):
        self.assertNotIn("EXPIRED", self.run_one(acc("a", SHA512, age=90))["issue_codes"])
        self.assertIn("EXPIRED", self.run_one(acc("a", SHA512, age=91))["issue_codes"])

    def test_warning_below_threshold(self):
        r = self.run_one(acc("a", NTLM_PW, fmt="NTLM", age=91))   # 30 + 20
        self.assertEqual(r["risk_score"], 50)
        self.assertEqual(r["status"], TrafficLight.RED.value)
        r = self.run_one(acc("a", NTLM_PW, fmt="NTLM"))           # 30
        self.assertEqual(r["risk_score"], 30)
        self.assertLess(r["risk_score"], CRITICAL_THRESHOLD)
        self.assertEqual(r["status"], TrafficLight.YELLOW.value)

    def test_score_is_capped(self):
        r = self.run_one(acc("a", NTLM_PW, fmt="NTLM", age=400), {"NTLM": {NTLM_PW}})
        self.assertEqual(r["risk_score"], 100)

    def test_unassessable_hash_is_never_compliant(self):
        r = self.run_one(acc("a", "$6$saltsalt$vJ1..."))
        self.assertEqual(r["status"], TrafficLight.YELLOW.value)
        self.assertIn("UNASSESSABLE_HASH", r["issue_codes"])

    def test_disabled_account_reported_as_inactive(self):
        r = self.run_one(acc("a", NTLM_PW, fmt="NTLM", enabled=False))
        self.assertEqual(r["status"], TrafficLight.INACTIVE.value)
        self.assertEqual(r["risk_score"], 30)           # risk still visible
        self.assertIn("INACTIVE_ACCOUNT", r["issue_codes"])

    def test_every_finding_has_remediation(self):
        r = self.run_one(acc("a", NTLM_PW, fmt="NTLM", age=200), {"NTLM": {NTLM_PW}})
        for code in r["issue_codes"]:
            self.assertIn(f"[{code}]", r["remediation"])
        self.assertEqual(self.run_one(acc("b", BCRYPT))["remediation"], "No action required.")


if __name__ == "__main__":
    unittest.main()
