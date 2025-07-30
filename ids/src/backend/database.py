import sqlite3
import time
from contextlib import contextmanager
from config.settings import DB_PATH, DB_NAME


@contextmanager
def db_connection():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Initialize the database and create tables if they don't exist."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Create devices table
        cursor.execute(
            """
			CREATE TABLE IF NOT EXISTS devices (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ip TEXT NOT NULL UNIQUE,
				mac TEXT NOT NULL,
				timestamp TEXT NOT NULL,
				status TEXT NOT NULL
			)
		"""
        )

        # Create packets table
        cursor.execute(
            """
			CREATE TABLE IF NOT EXISTS packets (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp TEXT NOT NULL,
				src_ip TEXT NOT NULL,
				dst_ip TEXT NOT NULL,
				protocol TEXT NOT NULL,
				payload_hash TEXT,
				payload_size INTEGER
			)
		"""
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS malware_hashes (
                sha256 TEXT PRIMARY KEY
            )
        """
        )

        # Check if we need to migrate existing packets table
        cursor.execute("PRAGMA table_info(packets)")
        columns = [column[1] for column in cursor.fetchall()]

        if "payload_hash" not in columns:
            print("[Database] Migrating packets table to add payload_hash column...")
            cursor.execute("ALTER TABLE packets ADD COLUMN payload_hash TEXT")

        if "payload_size" not in columns:
            print("[Database] Migrating packets table to add payload_size column...")
            cursor.execute("ALTER TABLE packets ADD COLUMN payload_size INTEGER")

        # Create alerts table
        cursor.execute(
            """
			CREATE TABLE IF NOT EXISTS alerts (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp TEXT NOT NULL,
				alert_type TEXT NOT NULL,
				severity TEXT NOT NULL,
				src_ip TEXT NOT NULL,
				message TEXT NOT NULL
			)
		"""
        )

        # Create malicious ips table
        cursor.execute(
            """
			CREATE TABLE IF NOT EXISTS malicious_ips (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ip TEXT NOT NULL UNIQUE,
				confidence_score INTEGER NOT NULL,
				reason TEXT,
				country TEXT,
				timestamp TEXT DEFAULT CURRENT_TIMESTAMP
			)
		"""
        )

        # Check if we need to migrate existing malicious_ips table
        cursor.execute("PRAGMA table_info(malicious_ips)")
        columns = [column[1] for column in cursor.fetchall()]

        if "reason" not in columns:
            print("[Database] Migrating malicious_ips table to add reason column...")
            cursor.execute("ALTER TABLE malicious_ips ADD COLUMN reason TEXT")

        if "country" not in columns:
            print("[Database] Migrating malicious_ips table to add country column...")
            cursor.execute("ALTER TABLE malicious_ips ADD COLUMN country TEXT")

        conn.commit()
        conn.close()
        print("[Database] Initialized successfully.")
    except sqlite3.OperationalError as e:
        print(f"[Database ERROR] Failed to initialize: {e}")


def log_packet(
    src_ip, dst_ip, protocol, payload_hash=None, payload_size=None, additional_info=None
):
    """Log a network packet to the database.

    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address
        protocol: Protocol name (e.g., TCP, UDP, SSL/TLS)
        payload_hash: Hash of the packet payload (optional)
        payload_size: Size of the packet payload (optional)
        additional_info: Dictionary with additional packet information (optional)
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Store basic packet info
        cursor.execute(
            """
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, payload_hash, payload_size)
            VALUES (datetime('now'), ?, ?, ?, ?, ?)
            """,
            (src_ip, dst_ip, protocol, payload_hash, payload_size),
        )
        packet_id = cursor.lastrowid

        # Store additional info if provided
        if additional_info and isinstance(additional_info, dict):
            # Create additional_packet_info table if it doesn't exist
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS additional_packet_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    packet_id INTEGER NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT,
                    FOREIGN KEY (packet_id) REFERENCES packets(id)
                )
                """
            )

            # Insert additional info
            for key, value in additional_info.items():
                cursor.execute(
                    """
                    INSERT INTO additional_packet_info (packet_id, key, value)
                    VALUES (?, ?, ?)
                    """,
                    (packet_id, key, str(value)),
                )

        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(f"[Database ERROR] Failed to log packet: {e}")


def log_alert(alert_type, severity, src_ip, message):
    """Log a security alert to the database."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (timestamp, alert_type, severity, src_ip, message) VALUES (?, ?, ?, ?, ?)",
            (timestamp, alert_type, severity, src_ip, message),
        )
        conn.commit()


def update_device_status(ip, status):
    """Update the status of a device in the database."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE devices SET status=? WHERE ip=?",
            (status, ip),
        )
        conn.commit()


def fetch_devices():
    """Fetch all devices from the database."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip, mac, timestamp, status FROM devices")
        return cursor.fetchall()


def fetch_packets(limit=10):
    """Fetch recent packets from the database."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT timestamp, src_ip, dst_ip, protocol FROM packets ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return cursor.fetchall()


def fetch_alerts(limit=20):
    """Fetch recent alerts from the database."""
    with db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT timestamp, alert_type, severity, src_ip, message FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return cursor.fetchall()
