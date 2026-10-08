# models.py
"""
Data structures module using dataclasses and enums.
"""
from enum import Enum
from dataclasses import dataclass

class TrafficLight(Enum):
    GREEN = "🟢 Compliant"
    YELLOW = "🟡 Warning"
    RED = "🔴 Critical"

class AccountType(Enum):
    STANDARD = "Standard User"
    ADMIN = "Administrator"
    SERVICE = "Service Account"

class HashType(Enum):
    NTLM = "NTLM (Legacy, unsalted)"
    BCRYPT = "bcrypt (Modern, salted)"
    SHA512_CRYPT = "SHA-512 (Linux, salted)"
    UNKNOWN = "Unknown algorithm"

@dataclass
class SystemPolicy:
    min_length: int
    require_complexity: bool
    max_age_days: int
    lockout_threshold: int

@dataclass
class AccountRecord:
    username: str
    type: AccountType
    password_age_days: int
    hash_string: str
    enabled: bool = True

@dataclass
class AuditResultItem:
    username: str
    type: str
    algo: str
    age: int
    risk_score: float
    status: str
    issues: str