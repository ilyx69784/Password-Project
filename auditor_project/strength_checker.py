# strength_checker.py
"""
Password strength engine (entropy, dictionary, patterns, NIST SP 800-63B).

Reusable library version of the original standalone CLI script, with all
I/O (input()/print()) removed so it can be called from a GUI (main.py) or
any other interface.
"""
import math
import string
from typing import List, Dict, Tuple

COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "admin",
    "admin123",
    "administrator",
    "welcome",
    "welcome123",
    "letmein",
    "monkey",
    "dragon",
    "football",
    "iloveyou",
    "abc123",
    "111111",
    "000000",
    "123123",
    "passw0rd",
}

ENTROPY_THRESHOLD = 60  # bits, threshold for Entropy Check and NIST Check
MIN_LENGTH = 12
MAX_LENGTH = 64


def calculate_entropy(password: str) -> float:
    """Entropy = length * log2(character_set_size)."""
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
    else:
        return "Very Strong"


def dictionary_check(password: str) -> Tuple[bool, str]:
    if password.lower() in COMMON_PASSWORDS:
        return False, "Password found in the common password dictionary."
    return True, "Password not found in the dictionary."


def length_check(password: str) -> Tuple[bool, str]:
    if len(password) < MIN_LENGTH:
        return False, f"Password is shorter than {MIN_LENGTH} characters."
    if len(password) > MAX_LENGTH:
        return False, f"Password exceeds {MAX_LENGTH} characters."
    return True, "Password length is acceptable."


def pattern_check(password: str) -> Tuple[bool, str]:
    password_lower = password.lower()

    weak_patterns = [
        "password", "qwerty", "admin", "welcome",
        "letmein", "123456", "abcdef", "iloveyou",
    ]
    for pattern in weak_patterns:
        if pattern in password_lower:
            return False, f"Weak pattern detected: '{pattern}'."

    # Repeated characters (aaa, 111, etc.)
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            return False, "Repeated character pattern detected."

    # Sequential numbers
    sequential_numbers = ["12345", "23456", "34567", "45678", "56789"]
    for sequence in sequential_numbers:
        if sequence in password:
            return False, "Sequential number pattern detected."

    return True, "No obvious weak patterns detected."


def nist_check(password: str, entropy: float) -> Tuple[bool, str]:
    """
    Simplified, educational implementation inspired by NIST SP 800-63B.
    This is NOT a complete implementation of the standard.
    """
    if len(password) < MIN_LENGTH:
        return False, "Does not meet the configured minimum length."
    if password.lower() in COMMON_PASSWORDS:
        return False, "Password appears in the blocklist."
    if entropy < ENTROPY_THRESHOLD:
        return False, "Estimated entropy is below the configured threshold."
    return True, "Password passes the configured NIST-style checks."


def audit_password(password: str) -> Tuple[float, List[Dict], bool]:
    """
    Runs the password through all checks.
    Returns: (entropy, list of check results, overall compliant)
    """
    entropy = calculate_entropy(password)
    results = []

    passed, message = length_check(password)
    results.append({"name": "Password Length", "passed": passed, "message": message})

    passed, message = dictionary_check(password)
    results.append({"name": "Dictionary Check", "passed": passed, "message": message})

    passed, message = pattern_check(password)
    results.append({"name": "Weak Pattern Check", "passed": passed, "message": message})

    entropy_passed = entropy >= ENTROPY_THRESHOLD
    results.append({
        "name": "Entropy Check",
        "passed": entropy_passed,
        "message": f"Entropy: {entropy:.2f} bits (threshold {ENTROPY_THRESHOLD}).",
    })

    passed, message = nist_check(password, entropy)
    results.append({"name": "NIST SP 800-63B Check", "passed": passed, "message": message})

    compliant = all(r["passed"] for r in results)
    return entropy, results, compliant
