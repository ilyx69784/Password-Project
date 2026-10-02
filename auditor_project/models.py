# models.py
"""
Data structures module.
Contains enums and classes used to standardize data passed between
the connector, the auditor, and the GUI.
"""
from enum import Enum
from dataclasses import dataclass
from typing import Optional

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
    """Structure describing the system's current password policy."""
    min_length: int
    require_complexity: bool
    max_age_days: int
    lockout_threshold: int
