# connector.py
"""
Data source connector module.
In a real application, this module is responsible for extracting data
from live systems.
"""
from models import AccountType, SystemPolicy

class DataSourceConnector:
    """
    Base connector class.
    In practice you would create subclasses such as:
    1. ActiveDirectoryConnector:
       - Uses the `ldap3` library to connect to a domain controller
         (reading GPO policies, userAccountControl, pwdLastSet).
       - Uses techniques like DCSync (via the `impacket` library) to safely
         extract NTDS.dit (the AD database) and obtain user NTLM hashes.
    2. LinuxShadowConnector:
       - Reads /etc/shadow on Linux servers over SSH (via the `paramiko`
         library).
       - Parses hashes starting with $6$ (SHA-512) or $2b$ (bcrypt).
    """

    def get_system_policy(self) -> SystemPolicy:
        """In practice: reads the Default Domain Policy settings from AD."""
        return SystemPolicy(
            min_length=8,
            require_complexity=True,
            max_age_days=90,
            lockout_threshold=5
        )

    def fetch_accounts(self) -> list:
        """
        Simulated retrieval of data from a database/AD.
        Returns a list of users, their metadata, and password hashes.
        No plaintext passwords are present here.
        """
        return [
            {
                "username": "admin_ivan",
                "type": AccountType.ADMIN,
                "password_age_days": 120,  # Password unchanged for 120 days
                "hash_string": "32ED87BDF5FAC7728E709E306CE449F7",  # NTLM hash (unsalted)
                "enabled": True
            },
            {
                "username": "anna.manager",
                "type": AccountType.STANDARD,
                "password_age_days": 15,
                "hash_string": "$2b$12$eImiTXuWVxfM37uY4JANjQ==.xyz...",  # bcrypt hash (salted, cost factor 12)
                "enabled": True
            },
            {
                "username": "service_sql",
                "type": AccountType.SERVICE,
                "password_age_days": 365,
                "hash_string": "32ED87BDF5FAC7728E709E306CE449F7",  # Same NTLM hash as admin_ivan (duplicate!)
                "enabled": True
            },
            {
                "username": "guest_user",
                "type": AccountType.STANDARD,
                "password_age_days": 5,
                "hash_string": "$6$saltsalt$vJ1...",  # SHA-512 crypt
                "enabled": True
            }
        ]
