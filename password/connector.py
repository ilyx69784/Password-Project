# connector.py
"""
Data source connector module with error handling and logging.
"""
import logging
from typing import List
from models import AccountRecord, AccountType, SystemPolicy

logger = logging.getLogger(__name__)

class DataSourceConnector:
    def get_system_policy(self) -> SystemPolicy:
        try:
            logger.info("Loading system security policy...")
            return SystemPolicy(
                min_length=12,
                require_complexity=True,
                max_age_days=90,
                lockout_threshold=5
            )
        except Exception as e:
            logger.error(f"Error fetching system policy: {e}")
            raise

    def fetch_accounts(self) -> List[AccountRecord]:
        try:
            logger.info("Fetching accounts and hashes from data source...")
            return [
                AccountRecord("admin_ivan", AccountType.ADMIN, 120, "32ED87BDF5FAC7728E709E306CE449F7", True),
                AccountRecord("anna.manager", AccountType.STANDARD, 15, "$2b$12$eImiTXuWVxfM37uY4JANjQ==.xyz...", True),
                AccountRecord("service_sql", AccountType.SERVICE, 365, "32ED87BDF5FAC7728E709E306CE449F7", True),
                AccountRecord("guest_user", AccountType.STANDARD, 5, "$6$saltsalt$vJ1...", True)
            ]
        except Exception as e:
            logger.error(f"Error fetching accounts: {e}")
            raise