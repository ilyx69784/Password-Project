"""Print a readable summary of the SQLite data in the terminal."""

from database import Database


def main():
    db = Database()
    print("DATABASE:", db.path)
    print("\nACCOUNTS")
    for account in db.get_accounts():
        print(f"  {account['username']:<20} {account['type'].value:<18} age: {account['password_age_days']}")

    print("\nAUDIT HISTORY")
    for run in db.get_audit_runs(limit=10):
        print(f"  Scan #{run['id']} | {run['created_at']} | "
              f"checked: {run['accounts_checked']} | critical: {run['critical_count']}")

    print("\nPASSWORD STRENGTH HISTORY (passwords never stored)")
    for row in db.get_strength_checks(limit=10):
        print(f"  #{row['id']} | {row['created_at']} | "
              f"entropy: {row['entropy']:.2f} | rating: {row['rating']}")


if __name__ == "__main__":
    main()
