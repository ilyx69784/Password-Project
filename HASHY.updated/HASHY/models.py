# models.py
"""
Data structures shared by the connector, the auditor, the database and the GUI.
"""
from dataclasses import dataclass
from enum import Enum


class TrafficLight(Enum):
    GREEN = "🟢 Compliant"
    YELLOW = "🟡 Warning"
    RED = "🔴 Critical"
    # Disabled accounts are still analysed (dormant credentials can be
    # re-enabled), but they are reported separately from active risk.
    INACTIVE = "⚪ Inactive"


class AccountType(Enum):
    STANDARD = "Standard User"
    ADMIN = "Administrator"
    SERVICE = "Service Account"


class HashType(Enum):
    # Unsalted formats: identical password -> identical hash on every system.
    NTLM = "NTLM (unsalted, declared)"
    MD5 = "MD5 (unsalted, declared)"
    UNSALTED_32HEX = "32-hex unsalted (NTLM or MD5, ambiguous)"
    # Salted crypt(3)-style formats.
    MD5_CRYPT = "MD5-crypt $1$ (salted, obsolete)"
    SHA256_CRYPT = "SHA-256-crypt $5$ (salted)"
    SHA512_CRYPT = "SHA-512-crypt $6$ (salted)"
    BCRYPT = "bcrypt $2*$ (salted, adaptive)"
    YESCRYPT = "yescrypt $y$ (salted, memory-hard)"
    ARGON2 = "Argon2 (salted, memory-hard)"
    # Data-quality outcomes.
    MALFORMED = "Malformed (known prefix, invalid structure)"
    EMPTY = "No hash recorded"
    UNKNOWN = "Unknown format"


UNSALTED_TYPES = {HashType.NTLM, HashType.MD5, HashType.UNSALTED_32HEX}
SALTED_TYPES = {
    HashType.MD5_CRYPT, HashType.SHA256_CRYPT, HashType.SHA512_CRYPT,
    HashType.BCRYPT, HashType.YESCRYPT, HashType.ARGON2,
}
WEAK_TYPES = UNSALTED_TYPES | {HashType.MD5_CRYPT}
UNASSESSABLE_TYPES = {HashType.MALFORMED, HashType.EMPTY, HashType.UNKNOWN}

# Values allowed in accounts.hash_format (declared by the source system).
DECLARABLE_FORMATS = {"": None, "NTLM": HashType.NTLM, "MD5": HashType.MD5}


@dataclass
class SystemPolicy:
    """The single password policy used by BOTH the account audit and the
    interactive strength checker. Stored in SQLite (password_policy)."""
    min_length: int
    require_complexity: bool
    max_age_days: int
    lockout_threshold: int
    max_length: int = 64
    min_entropy_bits: float = 60.0
