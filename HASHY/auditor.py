# auditor.py
"""
Core audit module.
Analyzes password hashing algorithms, cross-checks them against breach
databases, and verifies compliance with system policies.
"""
from typing import List, Dict, Any
from models import TrafficLight, AccountType, HashType, SystemPolicy

class SecurityAuditor:
    def __init__(self, compromised_hashes: set):
        self.compromised_hashes = compromised_hashes

    def detect_hash_algorithm(self, hash_string: str) -> HashType:
        """Detects the hash type from its signature."""
        if not hash_string:
            return HashType.UNKNOWN

        if hash_string.startswith("$2"):
            return HashType.BCRYPT
        elif hash_string.startswith("$6$"):
            return HashType.SHA512_CRYPT
        elif len(hash_string) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_string):
            return HashType.NTLM

        return HashType.UNKNOWN

    def is_breached(self, hash_string: str) -> bool:
        """Checks the hash against the breach database."""
        return hash_string.upper() in self.compromised_hashes

    def run_audit(self, accounts: list, policy: SystemPolicy) -> List[Dict[str, Any]]:
        results = []
        hash_counts = {}
        for acc in accounts:
            h = acc.get("hash_string", "")
            if h: hash_counts[h] = hash_counts.get(h, 0) + 1

        for acc in accounts:
            username = acc["username"]
            h_str = acc.get("hash_string", "")
            algo = self.detect_hash_algorithm(h_str)
            age = acc.get("password_age_days", 0)

            issues = []
            risk = 0

            if algo == HashType.NTLM:
                issues.append("Weak algorithm (NTLM is unsalted, vulnerable to Pass-the-Hash)")
                risk += 30

            if h_str and hash_counts.get(h_str, 0) > 1:
                issues.append(f"Password reused ({hash_counts[h_str]} accounts share this hash)")
                risk += 40

            if self.is_breached(h_str):
                issues.append("Hash found in breach database (compromised)")
                risk += 50

            if age > policy.max_age_days:
                issues.append(f"Password expired ({age} days, maximum {policy.max_age_days})")
                risk += 20

            if risk >= 50:
                status = TrafficLight.RED
            elif risk > 0:
                status = TrafficLight.YELLOW
            else:
                status = TrafficLight.GREEN

            results.append({
                "username": username,
                "type": acc["type"].value,
                "algo": algo.value,
                "age": age,
                "risk_score": min(risk, 100),
                "status": status.value,
                "issues": "\n".join(issues) if issues else "No issues"
            })

        return results