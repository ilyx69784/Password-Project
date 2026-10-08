# strength_checker.py
"""
Password strength verification engine: entropy, alphabets, patterns, l33t-speak, and dictionaries.
"""
import math
import string
import logging
from typing import List, Dict, Tuple, Set
import config

logger = logging.getLogger(__name__)

class PasswordStrengthChecker:
    def __init__(self, custom_dictionary: Set[str] = None):
        self.dictionary = config.DEFAULT_COMMON_PASSWORDS.copy()
        if custom_dictionary:
            self.dictionary.update(p.lower() for p in custom_dictionary)

    def calculate_entropy(self, password: str) -> Tuple[float, Dict[str, any]]:
        if not password:
            return 0.0, {"lower": False, "upper": False, "digits": False, "symbols": False, "size": 0}

        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digits = any(c in string.digits for c in password)
        has_symbols = any(c in string.punctuation for c in password)

        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digits: charset_size += 10
        if has_symbols: charset_size += len(string.punctuation)

        charset_info = {
            "lower": has_lower,
            "upper": has_upper,
            "digits": has_digits,
            "symbols": has_symbols,
            "size": charset_size
        }

        if charset_size == 0:
            return 0.0, charset_info

        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2), charset_info

    def entropy_rating(self, entropy: float) -> str:
        if entropy < 40: return "Very Weak"
        elif entropy < 60: return "Weak"
        elif entropy < 80: return "Moderate"
        elif entropy < 100: return "Strong"
        else: return "Very Strong"

    def dictionary_check(self, password: str) -> Tuple[bool, str]:
        if password.lower() in self.dictionary:
            return False, "Password found in the dictionary."
        return True, "Password not found in dictionaries."

    def length_check(self, password: str) -> Tuple[bool, str]:
        if len(password) < config.MIN_LENGTH:
            return False, f"Length is less than {config.MIN_LENGTH} characters."
        if len(password) > config.MAX_LENGTH:
            return False, f"Length exceeds {config.MAX_LENGTH} characters."
        return True, "Length is acceptable."

    def pattern_check(self, password: str) -> Tuple[bool, str]:
        pwd_lower = password.lower()
        
        # Normalize l33t-speak
        leet_map = {'@': 'a', '0': 'o', '1': 'i', '3': 'e', '$': 's', '!': 'i'}
        normalized_pwd = "".join(leet_map.get(c, c) for c in pwd_lower)

        patterns = ["qwerty", "asdfgh", "zxcvbn", "123456", "password", "admin", "welcome"]
        for pat in patterns:
            if pat in pwd_lower or pat in normalized_pwd:
                return False, f"Weak pattern or l33t-speak detected: '{pat}'."

        for i in range(len(password) - 2):
            if password[i] == password[i + 1] == password[i + 2]:
                return False, "Repeating consecutive characters found."

        seq_nums = ["12345", "23456", "34567", "45678", "56789"]
        for seq in seq_nums:
            if seq in password:
                return False, "Sequential number pattern detected."

        return True, "No weak patterns detected."

    def nist_check(self, password: str, entropy: float) -> Tuple[bool, str]:
        if len(password) < config.MIN_LENGTH:
            return False, "Does not meet NIST minimum length."
        if password.lower() in self.dictionary:
            return False, "Password is in the NIST blocklist."
        if entropy < config.ENTROPY_THRESHOLD:
            return False, f"Entropy is below the NIST threshold ({config.ENTROPY_THRESHOLD} bits)."
        return True, "Complies with NIST SP 800-63B."

    def audit_password(self, password: str) -> Tuple[float, Dict, List[Dict], bool]:
        entropy, charset_info = self.calculate_entropy(password)
        results = []

        p_len, m_len = self.length_check(password)
        results.append({"name": "Length Check", "passed": p_len, "message": m_len})

        p_dict, m_dict = self.dictionary_check(password)
        results.append({"name": "Dictionary Check", "passed": p_dict, "message": m_dict})

        p_pat, m_pat = self.pattern_check(password)
        results.append({"name": "Patterns & l33t-speak", "passed": p_pat, "message": m_pat})

        ent_passed = entropy >= config.ENTROPY_THRESHOLD
        results.append({
            "name": "Entropy Check",
            "passed": ent_passed,
            "message": f"Entropy: {entropy:.2f} bits (charset size: {charset_info['size']})."
        })

        p_nist, m_nist = self.nist_check(password, entropy)
        results.append({"name": "NIST Standard Check", "passed": p_nist, "message": m_nist})

        compliant = all(r["passed"] for r in results)
        return entropy, charset_info, results, compliant