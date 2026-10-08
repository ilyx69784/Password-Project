# auditor.py
"""
Hash audit engine supporting weighted risk scoring and hash normalization.
"""
import logging
from typing import List, Set
from models import TrafficLight, HashType, SystemPolicy, AuditResultItem, AccountRecord
import config

logger = logging.getLogger(__name__)

class SecurityAuditor:
    def __init__(self, compromised_hashes: Set[str]):
        self.compromised_hashes = {h.upper() for h in compromised_hashes}

    def detect_hash_algorithm(self, hash_string: str) -> HashType:
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
        if not hash_string:
            return False
        clean_hash = hash_string.upper()
        return clean_hash in self.compromised_hashes

    def run_audit(self, accounts: List[AccountRecord], policy: SystemPolicy) -> List[AuditResultItem]:
        logger.info("Starting account audit process...")
        results: List[AuditResultItem] = []
        hash_counts = {}

        for acc in accounts:
            h = acc.hash_string.upper()
            if h:
                hash_counts[h] = hash_counts.get(h, 0) + 1

        for acc in accounts:
            algo = self.detect_hash_algorithm(acc.hash_string)
            issues = []
            base_risk = 0.0

            if algo == HashType.NTLM:
                issues.append("Weak algorithm (NTLM is vulnerable to Pass-the-Hash)")
                base_risk += config.RISK_WEIGHTS["NTLM"]

            if acc.hash_string and hash_counts.get(acc.hash_string.upper(), 0) > 1:
                issues.append(f"Password reused ({hash_counts[acc.hash_string.upper()]} accounts share this hash)")
                base_risk += config.RISK_WEIGHTS["REUSE"]

            if self.is_breached(acc.hash_string):
                issues.append("Hash found in breach database (compromised)")
                base_risk += config.RISK_WEIGHTS["BREACHED"]

            if acc.password_age_days > policy.max_age_days:
                issues.append(f"Password expired ({acc.password_age_days} days, limit {policy.max_age_days})")
                base_risk += config.RISK_WEIGHTS["EXPIRED"]

            # Weighted risk calculation based on account type criticality
            multiplier = config.ACCOUNT_TYPE_MULTIPLIERS.get(acc.type.value, 1.0)
            final_risk = min(round(base_risk * multiplier, 1), 100.0)

            if final_risk >= 50:
                status = TrafficLight.RED.value
            elif final_risk > 0:
                status = TrafficLight.YELLOW.value
            else:
                status = TrafficLight.GREEN.value

            results.append(AuditResultItem(
                username=acc.username,
                type=acc.type.value,
                algo=algo.value,
                age=acc.password_age_days,
                risk_score=final_risk,
                status=status,
                issues="\n".join(issues) if issues else "No issues"
            ))

        return results