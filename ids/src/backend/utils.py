import ipaddress
import re
import socket
import sqlite3
import time
from config.settings import DB_PATH


def is_valid_ip(ip: str):
    """Check if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_mac(mac: str):
    """Check if a string is a valid MAC address."""
    mac_regex = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    return bool(re.match(mac_regex, mac))


def resolve_hostname(ip: str):
    """Resolve the hostname for a given IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def get_timestamp():
    """Get the current timestamp in a standardized format."""
    return time.strftime("%Y-%m-%d %H:%M:%S")


def get_device_info(ip: str):
    """Retrieve device information from the database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ip, mac, timestamp, status FROM devices WHERE ip = ?", (ip,)
        )
        result = cursor.fetchone()
        conn.close()
        if result:
            return {
                "ip": result[0],
                "mac": result[1],
                "timestamp": result[2],
                "status": result[3],
            }
        return None
    except sqlite3.OperationalError as e:
        print(f"[UTILS ERROR] Failed to fetch device info: {e}")
        return None


def is_private_ip(ip: str):
    """Check if an IP address is in a private range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def format_bytes(size):
    """Convert bytes to a human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"
