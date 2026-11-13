"""Print a readable summary of the runtime SQLite database (hashes masked)."""
from database import Database, mask_hash


def main():
    db = Database()
    report = db.integrity_report()
    print("DATABASE:", db.path, f"(schema v{report['schema_version']}, "
          f"integrity: {report['integrity_check']})")

    p = db.get_policy()
    print("\nPOLICY (shared by audit and strength checker)")
    print(f"  length {p.min_length}-{p.max_length} | entropy >= {p.min_entropy_bits:g} bits | "
          f"composition {'on' if p.require_complexity else 'off'} | max age {p.max_age_days} d")

    print("\nACCOUNTS")
    for a in db.get_accounts():
        print(f"  {a['username']:<20} {a['type'].value:<16} age: {a['password_age_days']:<5} "
              f"format: {a['hash_format'] or 'auto':<5} hash: {mask_hash(a['hash_string']):<22} "
              f"{'enabled' if a['enabled'] else 'DISABLED'}")

    print("\nBREACH DATA (by algorithm and source)")
    for row in db.get_breach_summary():
        print(f"  {row['algorithm']:<5} {row['entries']:>6}  {row['source']}")

    print("\nAUDIT HISTORY")
    for run in db.get_audit_runs(limit=10):
        avg = "-" if run["avg_risk"] is None else f"{run['avg_risk']:.1f}"
        print(f"  Scan #{run['id']} | {run['created_at']} | checked: {run['accounts_checked']} | "
              f"critical: {run['critical_count']} | inactive: {run['inactive_count']} | avg risk: {avg}")

    print("\nPASSWORD STRENGTH HISTORY (passwords never stored)")
    for row in db.get_strength_checks(limit=10):
        print(f"  #{row['id']} | {row['created_at']} | entropy: {row['entropy']:.2f} | "
              f"rating: {row['rating']}")


if __name__ == "__main__":
    main()
