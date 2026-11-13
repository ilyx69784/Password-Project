"""Unit tests for the password strength engine and policy unification."""
import math
import string
import unittest

import strength_checker as sc
from models import SystemPolicy


def policy(**kw):
    base = dict(min_length=12, require_complexity=False, max_age_days=90,
                lockout_threshold=5, max_length=64, min_entropy_bits=60.0)
    base.update(kw)
    return SystemPolicy(**base)


class EntropyTests(unittest.TestCase):
    def test_empty_and_pools(self):
        self.assertEqual(sc.calculate_entropy(""), 0.0)
        self.assertAlmostEqual(sc.calculate_entropy("abcd"), 4 * math.log2(26))
        self.assertAlmostEqual(sc.calculate_entropy("aB1!"),
                               4 * math.log2(26 + 26 + 10 + len(string.punctuation)))
        self.assertEqual(sc.calculate_entropy("ÄÖÜ"), 0.0)   # outside counted pools

    def test_rating_boundaries(self):
        self.assertEqual(sc.entropy_rating(39.99), "Very Weak")
        self.assertEqual(sc.entropy_rating(40), "Weak")
        self.assertEqual(sc.entropy_rating(60), "Moderate")
        self.assertEqual(sc.entropy_rating(80), "Strong")
        self.assertEqual(sc.entropy_rating(100), "Very Strong")

    def test_deck_example_password123(self):
        entropy, results, ok = sc.audit_password("Password123")
        self.assertAlmostEqual(entropy, 65.5, places=1)
        policy_fails = [r for r in results if r["kind"] == "policy" and not r["passed"]]
        self.assertEqual(len(policy_fails), 3)   # length, blocklist, pattern
        self.assertFalse(ok)


class LengthAndPolicyTests(unittest.TestCase):
    def test_length_boundaries_follow_policy(self):
        p = policy(min_length=12, max_length=64)
        self.assertFalse(sc.length_check("a" * 11, p)[0])
        self.assertTrue(sc.length_check("a" * 12, p)[0])
        self.assertTrue(sc.length_check("a" * 64, p)[0])
        self.assertFalse(sc.length_check("a" * 65, p)[0])

    def test_policy_change_changes_verdict(self):
        pw = "Tr7#vq9!Lm2z"                       # 12 chars, strong charset
        self.assertTrue(sc.audit_password(pw, policy(min_length=12))[2])
        self.assertFalse(sc.audit_password(pw, policy(min_length=16))[2])

    def test_entropy_threshold_from_policy(self):
        pw = "kqzvxwjmtrpl"                       # 12 lowercase = 56.4 bits
        self.assertFalse(sc.audit_password(pw, policy(min_entropy_bits=60))[2])
        self.assertTrue(sc.audit_password(pw, policy(min_entropy_bits=50))[2])

    def test_composition_only_when_enabled(self):
        names = lambda p: [r["name"] for r in sc.audit_password("kqzvxwjmtrplhs", p)[1]]
        self.assertNotIn("Composition Rule (org policy)", names(policy()))
        self.assertIn("Composition Rule (org policy)", names(policy(require_complexity=True)))

    def test_nist_row_is_reference_only(self):
        pw = "Tr7#vq9!Lm2z"                       # meets policy, < 15 chars
        _, results, ok = sc.audit_password(pw)
        nist = [r for r in results if r["kind"] == "reference"][0]
        self.assertFalse(nist["passed"])
        self.assertTrue(ok)

    def test_nist_subset_boundaries(self):
        self.assertFalse(sc.nist_check("x" * 14)[0])
        self.assertTrue(sc.nist_check("correct horse b")[0])     # 15 chars
        self.assertFalse(sc.nist_check("y" * 65)[0])


class PatternTests(unittest.TestCase):
    def test_patterns(self):
        self.assertFalse(sc.pattern_check("myQWERTYpass")[0])
        self.assertFalse(sc.pattern_check("abcaaab")[0])
        self.assertTrue(sc.pattern_check("abcaab")[0])
        self.assertFalse(sc.pattern_check("x45678y")[0])
        self.assertTrue(sc.pattern_check("x4567y")[0])

    def test_blocklist_is_case_insensitive(self):
        self.assertFalse(sc.dictionary_check("PassWord")[0])


if __name__ == "__main__":
    unittest.main()
