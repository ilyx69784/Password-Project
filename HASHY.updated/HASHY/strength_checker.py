# strength_checker.py
"""
Password strength engine (entropy, blocklist, patterns, NIST subset).

All thresholds come from the SystemPolicy stored in SQLite, the same object
the account audit uses, so there is one source of truth. When no policy is
passed (e.g. in unit tests) DEFAULT_POLICY is used.

Scope note: "NIST SP 800-63B-4 subset" checks only the single-factor length
floor, the 64-character ceiling and the local blocklist. It is NOT a
compliance assessment of the standard.
"""
import math
import string
from typing import Dict, List, Optional, Tuple

from models import SystemPolicy

COMMON_PASSWORDS = {
    "password", "password123", "123456", "12345678", "123456789",
    "qwerty", "qwerty123", "qwertyuiop", "admin", "admin123",
    "administrator", "welcome", "welcome123", "letmein", "monkey",
    "dragon", "football", "iloveyou", "abc123", "111111", "000000",
    "123123", "passw0rd",
}

# NIST SP 800-63B-4, section 3.1.1.2 (final, 2025).
NIST_SINGLE_FACTOR_MIN = 15
NIST_MULTI_FACTOR_MIN = 8
NIST_MIN_ALLOWED_MAX = 64

DEFAULT_POLICY = SystemPolicy(min_length=12, require_complexity=False, max_age_days=90,
                              lockout_threshold=5, max_length=64, min_entropy_bits=60.0)

# Backwards-compatible module constants (mirror DEFAULT_POLICY).
ENTROPY_THRESHOLD = DEFAULT_POLICY.min_entropy_bits
MIN_LENGTH = DEFAULT_POLICY.min_length
MAX_LENGTH = DEFAULT_POLICY.max_length


def calculate_entropy(password: str) -> float:
    """Charset-based estimate: length * log2(pool size). It assumes random
    characters, so it overrates human-chosen passwords; the blocklist and
    pattern checks compensate."""
    if not password:
        return 0.0
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)
    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def entropy_rating(entropy: float) -> str:
    if entropy < 40:
        return "Very Weak"
    elif entropy < 60:
        return "Weak"
    elif entropy < 80:
        return "Moderate"
    elif entropy < 100:
        return "Strong"
    return "Very Strong"


def dictionary_check(password: str) -> Tuple[bool, str]:
    if password.lower() in COMMON_PASSWORDS:
        return False, "Password found in the common password blocklist."
    return True, "Password not found in the blocklist."


def length_check(password: str, policy: SystemPolicy = DEFAULT_POLICY) -> Tuple[bool, str]:
    if len(password) < policy.min_length:
        return False, f"Password is shorter than {policy.min_length} characters (policy)."
    if len(password) > policy.max_length:
        return False, f"Password exceeds {policy.max_length} characters (policy)."
    return True, f"Length {len(password)} is within policy ({policy.min_length}-{policy.max_length})."


def pattern_check(password: str) -> Tuple[bool, str]:
    password_lower = password.lower()
    weak_patterns = ["password", "qwerty", "admin", "welcome",
                     "letmein", "123456", "abcdef", "iloveyou"]
    for pattern in weak_patterns:
        if pattern in password_lower:
            return False, f"Weak pattern detected: '{pattern}'."
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            return False, "Repeated character pattern detected."
    for sequence in ["12345", "23456", "34567", "45678", "56789"]:
        if sequence in password:
            return False, "Sequential number pattern detected."
    return True, "No obvious weak patterns detected."


def composition_check(password: str) -> Tuple[bool, str]:
    """Organizational rule (AD-style: 3 of 4 character classes).
    NIST SP 800-63B-4 says verifiers SHALL NOT impose this; it only runs when
    the stored policy enables require_complexity."""
    classes = sum([
        any(c in string.ascii_lowercase for c in password),
        any(c in string.ascii_uppercase for c in password),
        any(c in string.digits for c in password),
        any(c in string.punctuation for c in password),
    ])
    if classes >= 3:
        return True, f"{classes} of 4 character classes present (org rule)."
    return False, f"Only {classes} of 4 character classes; policy requires 3 (org rule)."


def nist_check(password: str, entropy: float = 0.0) -> Tuple[bool, str]:
    """Subset of NIST SP 800-63B-4 section 3.1.1.2 for a password used as the
    ONLY factor: >= 15 characters, <= 64 accepted, not on the blocklist.
    `entropy` is accepted for backwards compatibility and is not a NIST rule."""
    if len(password) < NIST_SINGLE_FACTOR_MIN:
        return False, f"Under NIST single-factor minimum {NIST_SINGLE_FACTOR_MIN} (8 only with MFA)."
    if len(password) > NIST_MIN_ALLOWED_MAX:
        return False, f"Longer than {NIST_MIN_ALLOWED_MAX}; acceptable to NIST only if the system allows it."
    if password.lower() in COMMON_PASSWORDS:
        return False, "Password appears in the blocklist."
    return True, "Meets the checked NIST subset (length + blocklist). Not a certification."


def audit_password(password: str, policy: Optional[SystemPolicy] = None
                   ) -> Tuple[float, List[Dict], bool]:
    """Run all checks. Returns (entropy, check results, overall compliant)."""
    policy = policy or DEFAULT_POLICY
    entropy = calculate_entropy(password)
    results = []

    def add(name, outcome, kind="policy"):
        results.append({"name": name, "passed": outcome[0], "message": outcome[1],
                        "kind": kind})

    add("Password Length (policy)", length_check(password, policy))
    add("Blocklist Check", dictionary_check(password))
    add("Weak Pattern Check", pattern_check(password))
    entropy_ok = entropy >= policy.min_entropy_bits
    add("Entropy Estimate (policy)", (entropy_ok,
        f"Estimated {entropy:.2f} bits (policy threshold {policy.min_entropy_bits:g})."))
    if policy.require_complexity:
        add("Composition Rule (org policy)", composition_check(password))
    # Reference only: reported, but the verdict follows the stored policy.
    add("NIST SP 800-63B-4 subset (reference)", nist_check(password, entropy), kind="reference")

    compliant = all(r["passed"] for r in results if r["kind"] == "policy")
    return entropy, results, compliant
