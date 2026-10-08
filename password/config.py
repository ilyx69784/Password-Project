# config.py
"""
Centralized configuration file.
Contains system limits, risk weights, and standard dictionaries.
"""
from typing import Set

MIN_LENGTH: int = 12
MAX_LENGTH: int = 64
ENTROPY_THRESHOLD: float = 60.0  # bits

# Risk score weights
RISK_WEIGHTS = {
    "NTLM": 30.0,
    "REUSE": 40.0,
    "BREACHED": 50.0,
    "EXPIRED": 20.0,
}

# Risk multipliers based on account type
ACCOUNT_TYPE_MULTIPLIERS = {
    "Administrator": 1.5,
    "Service Account": 1.3,
    "Standard User": 1.0,
}

# Base set of popular weak passwords
DEFAULT_COMMON_PASSWORDS: Set[str] = {
    "password", "password123", "123456", "12345678", "123456789",
    "qwerty", "qwerty123", "qwertyuiop", "admin", "admin123",
    "administrator", "welcome", "welcome123", "letmein", "monkey",
    "dragon", "football", "iloveyou", "abc123", "111111", "000000"
}