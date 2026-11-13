# sample_data.py
"""
Synthetic sample data, kept separate from the runtime database.

The runtime database (data/auditor.db) is created from this module on first
start and is never committed. Nothing here is a real credential:
- crypt-style strings are format-valid placeholders generated from a fixed
  seed; they are not hashes of any password.
- breach entries are DERIVED, reproducibly, from strength_checker's
  COMMON_PASSWORDS list (NTLM and MD5 of each entry), plus the original
  project's sample NTLM value.
"""
import random
import string

from hashing import md5_hex, ntlm_hex
from models import AccountType

CRYPT_ALPHABET = "./" + string.digits + string.ascii_uppercase + string.ascii_lowercase
LEGACY_SAMPLE_NTLM = "32ED87BDF5FAC7728E709E306CE449F7"

# Placeholders from the original seed, which are truncated and therefore
# malformed. Migration replaces ONLY these exact strings.
LEGACY_PLACEHOLDERS = {
    "$2b$12$eImiTXuWVxfM37uY4JANjQ==.xyz...": "bcrypt",
    "$6$saltsalt$vJ1...": "sha512",
}


def synthetic_crypt(kind: str, rng: random.Random = None) -> str:
    """Return a structurally valid but meaningless crypt string."""
    rng = rng or random.SystemRandom()
    pick = lambda n: "".join(rng.choice(CRYPT_ALPHABET) for _ in range(n))
    if kind == "bcrypt":
        return "$2b$12$" + pick(53)
    if kind == "sha512":
        return "$6$" + pick(16) + "$" + pick(86)
    raise ValueError(kind)


_rng = random.Random(20261112)
SAMPLE_BCRYPT = synthetic_crypt("bcrypt", _rng)
SAMPLE_SHA512 = synthetic_crypt("sha512", _rng)

SAMPLE_POLICY = {
    # One source of truth for the audit AND the strength checker.
    "min_length": 12,          # stricter of the two legacy rules (8 vs 12)
    "max_length": 64,          # NIST SP 800-63B-4: allow at least 64
    "require_complexity": 0,   # NIST SP 800-63B-4 forbids composition rules
    "max_age_days": 90,        # organizational rule kept from the original project
    "lockout_threshold": 5,
    "min_entropy_bits": 60.0,
}

# (username, type, age, hash, declared hash_format, enabled)
SAMPLE_ACCOUNTS = [
    ("admin_ivan", AccountType.ADMIN, 120, LEGACY_SAMPLE_NTLM, "NTLM", 1),
    ("anna.manager", AccountType.STANDARD, 15, SAMPLE_BCRYPT, "", 1),
    ("service_sql", AccountType.SERVICE, 365, LEGACY_SAMPLE_NTLM, "NTLM", 1),
    ("guest_user", AccountType.STANDARD, 5, SAMPLE_SHA512, "", 1),
]

LEGACY_BREACH_SOURCE = "Original project sample NTLM value (preimage not documented)"
DERIVED_BREACH_SOURCE = "Derived: {alg} of strength_checker.COMMON_PASSWORDS (reproducible)"


def sample_breach_entries(common_passwords):
    """Yield (hash_value, algorithm, source) tuples."""
    yield LEGACY_SAMPLE_NTLM, "NTLM", LEGACY_BREACH_SOURCE
    for pw in sorted(common_passwords):
        yield ntlm_hex(pw), "NTLM", DERIVED_BREACH_SOURCE.format(alg="NTLM")
        yield md5_hex(pw), "MD5", DERIVED_BREACH_SOURCE.format(alg="MD5")
