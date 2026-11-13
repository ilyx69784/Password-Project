"""Database-backed connector for the educational password auditor.

The runtime SQLite database is the only data source. Production directory
connections (Active Directory, /etc/shadow) and online breach APIs are
deliberately out of scope; see README "Scope & limitations".
"""

from database import Database


class DataSourceConnector:
    def __init__(self, db=None):
        self.db = db if db is not None else Database()

    def get_system_policy(self):
        return self.db.get_policy()

    def fetch_accounts(self):
        return self.db.get_accounts()

    def fetch_compromised_hashes(self):
        """{algorithm: set(hash values)}: breach matching is per algorithm."""
        return self.db.get_breached_hashes()
