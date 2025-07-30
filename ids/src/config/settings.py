import os

# Database Configuration
DB_NAME = "ids_logs.db"
DB_PATH = os.path.join(os.path.dirname(__file__), "..", DB_NAME)

# Network Configuration
DEFAULT_INTERFACE = "eth0"  # Default network interface for monitoring
SCAN_TIMEOUT = 3  # Timeout for network scans in seconds
REFRESH_INTERVAL = 5  # Auto-refresh interval for the GUI in seconds

MALWARE_API_URL = "https://mb-api.abuse.ch/api/v1/"

# API Keys from Environment
MALWARE_API_KEY = os.getenv("MALWARE_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Logging Configuration
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "ids.log")
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 3  # Number of backup log files to keep

# Reports Configuration
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

# Alert Configuration
ALERT_SEVERITY_LEVELS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
DEFAULT_ALERT_SEVERITY = "medium"

# Web App Configuration
WEB_HOST = "0.0.0.0"
WEB_PORT = 5000
WEB_DEBUG = False
WEB_API_KEY = "ids_secure_api_key"  # API key for secure API access

# Packet Monitoring Configuration
SNIFF_TIMEOUT = None  # Timeout for packet sniffing in seconds (None for indefinite)
SNIFF_FILTER = "ip or ip6"  # BPF filter for packet sniffing
SNIFF_COUNT = 0  # Number of packets to capture (0 for indefinite)

# IDS Configuration
IDS_ENABLED = True
IDS_RULES_FILE = os.path.join(os.path.dirname(__file__), "ids_rules.json")
IDS_BLACKLIST_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "full_blacklist_database.txt",
)

# Detection Thresholds
PORT_SCAN_THRESHOLD = 5  # Number of unique ports to trigger port scan alert
PORT_SCAN_TIMEFRAME = 10  # Timeframe in seconds for port scan detection
BRUTEFORCE_THRESHOLD = 3  # Number of failed login attempts to trigger brute force alert
BRUTEFORCE_TIMEFRAME = 60  # Timeframe in seconds for brute force detection
DDOS_THRESHOLD = 100  # Number of packets to trigger DDoS alert
DDOS_TIMEFRAME = 60  # Timeframe in seconds for DDoS detection

# Response Configuration
AUTO_BLOCK_ENABLED = True  # Automatically block malicious IPs
NOTIFICATION_ENABLED = True  # Send notifications for alerts

# Email Configuration (Gmail)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")
ALERT_RECIPIENT = os.getenv("ALERT_RECIPIENT")

print(EMAIL_PASSWORD)

# Ensure log directory exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
