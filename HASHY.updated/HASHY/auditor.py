# auditor.py
"""
Core audit module.

Interprets stored password hashes, detects reuse, matches against an
algorithm-aware breach dataset, applies the organizational age rule and
produces a risk score with remediation guidance.

Interpretation rules (see README, "Hash & risk model"):
- A bare 32-hex value is ambiguous (NTLM and MD5 share the format). It is
  only treated as NTLM or MD5 when the account's source declares it.
- Reuse can be PROVEN only for unsalted formats: same password -> same hash.
  For salted formats, different strings say nothing about reuse; identical
  strings mean a copied record or a reused salt and are reported as such.
- Breach matching is per algorithm. Hex values compare case-insensitively;
  crypt strings compare exactly (their base64 alphabet is case-sensitive).
"""
import re
from typing import Any, Dict, Iterable, List, Mapping, Set, Union

from models import (DECLARABLE_FORMATS, SALTED_TYPES, UNASSESSABLE_TYPES,
                    UNSALTED_TYPES, WEAK_TYPES, HashType, SystemPolicy,
                    TrafficLight)
import remediation

CRITICAL_THRESHOLD = 50
MAX_SCORE = 100

_C = r"[./0-9A-Za-z]"
_FORMATS = [
    (HashType.BCRYPT, "$2", re.compile(rf"^\$2[abxy]?\$(0[4-9]|[12]\d|3[01])\${_C}{{53}}$")),
    (HashType.SHA512_CRYPT, "$6$", re.compile(rf"^\$6\$(rounds=\d+\$)?[^$:\n]{{1,16}}\${_C}{{86}}$")),
    (HashType.SHA256_CRYPT, "$5$", re.compile(rf"^\$5\$(rounds=\d+\$)?[^$:\n]{{1,16}}\${_C}{{43}}$")),
    (HashType.MD5_CRYPT, "$1$", re.compile(rf"^\$1\$[^$:\n]{{1,8}}\${_C}{{22}}$")),
    (HashType.YESCRYPT, "$y$", re.compile(rf"^\$y\${_C}+\${_C}+\${_C}{{43}}$")),
    (HashType.ARGON2, "$argon2", re.compile(r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$")),
]
_HEX32 = re.compile(r"^[0-9A-Fa-f]{32}$")

BreachData = Mapping[str, Set[str]]  # algorithm name -> normalized hash values


def normalize(hash_string: str, algo: HashType) -> str:
    return hash_string.upper() if algo in UNSALTED_TYPES else hash_string


class SecurityAuditor:
    def __init__(self, compromised_hashes: Union[BreachData, Iterable[str]]):
        if isinstance(compromised_hashes, Mapping):
            self.breaches = {k: set(v) for k, v in compromised_hashes.items()}
        else:
            # Legacy input: a flat set of hex strings, assumed NTLM.
            self.breaches = {"NTLM": {h.upper() for h in compromised_hashes}}

    # ------------------------------------------------------------------
    def detect_hash_algorithm(self, hash_string: str, declared: str = "") -> HashType:
        """Identify the format; `declared` is the source system's statement
        (e.g. 'NTLM' for an Active Directory export)."""
        if not hash_string:
            return HashType.EMPTY
        if _HEX32.match(hash_string):
            return DECLARABLE_FORMATS.get(declared or "") or HashType.UNSALTED_32HEX
        for htype, prefix, pattern in _FORMATS:
            if hash_string.startswith(prefix):
                return htype if pattern.match(hash_string) else HashType.MALFORMED
        return HashType.UNKNOWN

    def is_breached(self, hash_string: str, algo: HashType) -> bool:
        if algo in UNASSESSABLE_TYPES:
            return False
        value = normalize(hash_string, algo)
        if algo == HashType.UNSALTED_32HEX:
            candidates = ("NTLM", "MD5")
        else:
            candidates = (algo.name,)
        return any(value in self.breaches.get(c, ()) for c in candidates)

    # ------------------------------------------------------------------
    def run_audit(self, accounts: list, policy: SystemPolicy) -> List[Dict[str, Any]]:
        prepared = []
        for acc in accounts:
            h = acc.get("hash_string", "") or ""
            algo = self.detect_hash_algorithm(h, acc.get("hash_format", ""))
            prepared.append((acc, h, algo))

        # Group identical values. Unsalted values group case-insensitively.
        groups: Dict[str, int] = {}
        for _, h, algo in prepared:
            if algo not in UNASSESSABLE_TYPES:
                key = normalize(h, algo)
                groups[key] = groups.get(key, 0) + 1

        results = []
        for acc, h, algo in prepared:
            codes, details = [], []
            enabled = bool(acc.get("enabled", True))
            age = acc.get("password_age_days", 0)

            if algo in UNASSESSABLE_TYPES:
                codes.append("UNASSESSABLE_HASH")
                details.append(f"Hash cannot be assessed: {algo.value}")
            if algo == HashType.UNSALTED_32HEX:
                codes.append("AMBIGUOUS_FORMAT")
                details.append("32-hex value could be NTLM or MD5; source did not declare which")
            if algo in WEAK_TYPES:
                codes.append("WEAK_ALGORITHM")
                details.append(f"Weak algorithm: {algo.value}")

            shared = groups.get(normalize(h, algo), 0) if algo not in UNASSESSABLE_TYPES else 0
            if shared > 1 and algo in UNSALTED_TYPES:
                codes.append("PASSWORD_REUSE")
                details.append(f"Password reused: {shared} accounts share this unsalted hash")
            elif shared > 1 and algo in SALTED_TYPES:
                codes.append("DUPLICATE_SALTED_RECORD")
                details.append(f"Identical salted hash string on {shared} accounts "
                               f"(copied record or reused salt)")

            if self.is_breached(h, algo):
                codes.append("BREACHED")
                details.append("Hash matches the breach dataset for this algorithm")

            if age > policy.max_age_days:
                codes.append("EXPIRED")
                details.append(f"Password age {age} days exceeds organizational maximum "
                               f"{policy.max_age_days}")

            risk = min(sum(remediation.ISSUES[c].points for c in codes), MAX_SCORE)

            if not enabled:
                codes.append("INACTIVE_ACCOUNT")
                details.append("Account disabled: reported separately from active risk")
                status = TrafficLight.INACTIVE
            elif risk >= CRITICAL_THRESHOLD:
                status = TrafficLight.RED
            elif risk > 0:
                status = TrafficLight.YELLOW
            else:
                status = TrafficLight.GREEN

            results.append({
                "username": acc["username"],
                "type": acc["type"].value,
                "algo": algo.value,
                "age": age,
                "enabled": enabled,
                "risk_score": risk,
                "status": status.value,
                "issue_codes": codes,
                "issues": "\n".join(details) if details else "No issues",
                "remediation": remediation.render(codes),
            })
        return results
