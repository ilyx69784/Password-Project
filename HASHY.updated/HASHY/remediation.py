# remediation.py
"""
Issue catalogue: every audit finding has a stable code, a score and
remediation steps. The auditor emits codes; the GUI, CSV export and the
database store the codes plus the rendered guidance.
"""
from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class IssueSpec:
    code: str
    points: int
    title: str
    steps: tuple


ISSUES: Dict[str, IssueSpec] = {s.code: s for s in [
    IssueSpec("WEAK_ALGORITHM", 30, "Weak or unsalted hashing algorithm", (
        "Force a password reset so the system re-stores the password with a salted, "
        "adaptive algorithm (Argon2id, yescrypt, bcrypt, or SHA-512-crypt with high rounds).",
        "Active Directory always keeps NTLM hashes: reduce exposure instead by restricting "
        "NTLM authentication, putting privileged accounts in Protected Users, and enforcing "
        "long unique passwords.",
    )),
    IssueSpec("PASSWORD_REUSE", 40, "Password reuse confirmed (identical unsalted hash)", (
        "Reset every listed account with a different password.",
        "For service accounts, move to a managed credential (e.g. gMSA in AD) or a secrets vault.",
    )),
    IssueSpec("DUPLICATE_SALTED_RECORD", 40, "Identical salted hash string on several accounts", (
        "A salted hash should be unique per account; identical strings mean the record was "
        "copied or the salt was reused. Investigate the provisioning process.",
        "Reset the affected passwords so each account gets a fresh random salt.",
    )),
    IssueSpec("BREACHED", 50, "Hash matches the breach dataset", (
        "Reset the password immediately and revoke active sessions/tokens.",
        "Review sign-in logs for use of this account since the breach date.",
        "Add the password value to the blocklist so it cannot be chosen again.",
    )),
    IssueSpec("EXPIRED", 20, "Password older than organizational maximum age", (
        "Rotate per organizational policy.",
        "Note: NIST SP 800-63B-4 does not require periodic changes; consider replacing "
        "calendar expiry with breach-triggered resets plus MFA.",
    )),
    IssueSpec("UNASSESSABLE_HASH", 10, "Hash cannot be assessed (missing, unknown or malformed)", (
        "Re-export the hash from the source system; the stored value is empty, truncated "
        "or not a recognised format.",
        "Until fixed, treat the account as unverified rather than compliant.",
    )),
    IssueSpec("AMBIGUOUS_FORMAT", 0, "32-hex value: NTLM or MD5 cannot be distinguished", (
        "Record the source system's algorithm in the account's hash_format field "
        "(NTLM for Active Directory exports) so breach matching is exact.",
    )),
    IssueSpec("INACTIVE_ACCOUNT", 0, "Account is disabled", (
        "Confirm the account is still needed; delete it if not.",
        "Reset the password before re-enabling, since dormant credentials are not monitored.",
    )),
]}


def render(codes: List[str]) -> str:
    """Human-readable remediation plan for a list of issue codes."""
    if not codes:
        return "No action required."
    lines = []
    for code in codes:
        spec = ISSUES[code]
        lines.append(f"[{code}] {spec.title}")
        lines.extend(f"  - {step}" for step in spec.steps)
    return "\n".join(lines)
