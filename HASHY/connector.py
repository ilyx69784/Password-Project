# connector.py
"""
Database-backed connector for HASHY.
Bridges the database storage layer with the security auditor.
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
        return self.db.get_breached_hashes()