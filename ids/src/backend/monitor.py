import requests
import scapy.all as scapy
import sqlite3
import time
import threading
import os
import json
import datetime
import csv
import hashlib
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from config.settings import (
    ABUSEIPDB_API_KEY,
    DB_PATH,
    MALWARE_API_KEY,
    MALWARE_API_URL,
    OTX_API_KEY,
    SNIFF_FILTER,
    SNIFF_TIMEOUT,
    REPORTS_DIR,
)
from backend.database import log_alert, log_packet as db_log_packet
from backend.ssl_inspector import SSLInspector
from backend.topology import NetworkTopology
from backend.alerting import log_alert, send_alert_email
from backend.scanner import scan_network




# Initialize global variables for tracking
port_scan_attempts = {}
failed_logins = {}
packet_counts = {}  # Tracks packet counts per IP
suspicious_connections = {}  # Tracks abnormal connections
blocked_ips = set()  # Tracks blocked IPs
last_reset_time = time.time()
INTERVAL = 60  # Time window for anomaly detection in seconds
THRESHOLD = 100  # Packet count threshold for DDoS detection
UDP_THRESHOLD = 200  # Lower threshold for UDP flood detection

# Initialize new components
ssl_inspector = SSLInspector()
topology_mapper = NetworkTopology()

# Hash comparison tracking
known_hashes = {}  # Store known hashes for comparison
HASH_WINDOW = 300  # 5 minutes window for hash tracking
HASH_THRESHOLD = 10  # Number of identical hashes to trigger alert

# IDS Configuration
IDS_RULES = []
IDS_ENABLED = True
DEFAULT_RULES_FILE = os.path.join(
    os.path.dirname(__file__), "..", "config", "ids_rules.json"
)

# Malware hash checking sets
otx_checked_ips = set()
abuseipdb_checked_ips = set()


def load_ids_rules(rules_file=DEFAULT_RULES_FILE):
    """Load IDS rules from configuration file."""
    global IDS_RULES
    try:
        if os.path.exists(rules_file):
            with open(rules_file, "r") as f:
                IDS_RULES = json.load(f)
                print(f"[IDS] Loaded {len(IDS_RULES)} rules from {rules_file}")
        else:
            # Create default rules if file doesn't exist
            IDS_RULES = [
                {
                    "id": 1,
                    "name": "Port Scan Detection",
                    "type": "port_scan",
                    "threshold": 2,
                    "timeframe": 30,
                    "severity": "high",
                    "enabled": True,
                },
                {
                    "id": 2,
                    "name": "SSH Brute Force",
                    "type": "brute_force",
                    "ports": [22],
                    "threshold": 2,
                    "timeframe": 60,
                    "severity": "high",
                    "enabled": True,
                },
                {
                    "id": 3,
                    "name": "HTTP Flood",
                    "type": "http_flood",
                    "ports": [80, 443],
                    "threshold": 10,
                    "timeframe": 10,
                    "severity": "high",
                    "enabled": True,
                },
                {
                    "id": 4,
                    "name": "ICMP Flood",
                    "type": "icmp_flood",
                    "threshold": 5,
                    "timeframe": 30,
                    "severity": "high",
                    "enabled": True,
                },
            ]
            # Save default rules
            os.makedirs(os.path.dirname(rules_file), exist_ok=True)
            with open(rules_file, "w") as f:
                json.dump(IDS_RULES, f, indent=4)
                print(f"[IDS] Created default rules file at {rules_file}")
    except Exception as e:
        print(f"[ERROR] Failed to load IDS rules: {e}")
        IDS_RULES = []


def calculate_packet_hash(packet):
    """Calculate hash of packet payload."""
    try:
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            return hashlib.sha256(payload).hexdigest()
        return None
    except Exception as e:
        print(f"[ERROR] Failed to calculate packet hash: {e}")
        return None


def check_packet_hash(packet, src_ip):
    """Check if packet hash matches known patterns."""
    try:
        packet_hash = calculate_packet_hash(packet)
        if not packet_hash:
            return

        current_time = time.time()

        # Initialize hash tracking for this IP if not exists
        if src_ip not in known_hashes:
            known_hashes[src_ip] = {"hashes": {}, "last_reset": current_time}

        # Clean up old hashes
        if current_time - known_hashes[src_ip]["last_reset"] > HASH_WINDOW:
            known_hashes[src_ip] = {"hashes": {}, "last_reset": current_time}

        # Track this hash
        if packet_hash not in known_hashes[src_ip]["hashes"]:
            known_hashes[src_ip]["hashes"][packet_hash] = {
                "count": 1,
                "first_seen": current_time,
            }
        else:
            known_hashes[src_ip]["hashes"][packet_hash]["count"] += 1

            # Check if hash appears too frequently
            if known_hashes[src_ip]["hashes"][packet_hash]["count"] > HASH_THRESHOLD:
                log_alert(
                    "Suspicious Traffic Pattern",
                    "medium",
                    src_ip,
                    f"Repeated identical payload detected: {known_hashes[src_ip]['hashes'][packet_hash]['count']} occurrences in {HASH_WINDOW} seconds",
                )
                # Reset count after alert
                known_hashes[src_ip]["hashes"][packet_hash]["count"] = 0

    except Exception as e:
        print(f"[ERROR] Failed to check packet hash: {e}")


def packet_callback(packet):
    """Callback function for each captured packet."""
    try:
        if not IDS_ENABLED:
            return

        # ✅ Log basic info
        print(f"\n[DEBUG] Packet received: {packet.summary()}")

        if not packet.haslayer(IP):
            return  # Skip non-IP packets (e.g., ARP)

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # ✅ Skip further processing early if IP is known malicious
        if is_malicious_ip(src_ip):
            log_alert("Malicious IP", "high", src_ip, f"Traffic from blocked IP {src_ip}")
            block_ip(src_ip)
            return

        # ✅ Inspect payload hash (malware)
        payload_hash = None
        payload_size = 0
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load
                payload_hash = hashlib.sha256(payload).hexdigest()
                payload_size = len(payload)

                if payload_hash and not is_hash_in_cache(payload_hash):
                    result = query_malwarebazaar(payload_hash)
                    if result.get("query_status") == "ok":
                        msg = f"[MalwareBazaar] Malware from {src_ip} → {dst_ip}\nSHA256: {payload_hash}"
                        print(f"[ALERT] {msg}")
                        send_alert_email("Malware Detected", msg)
                        block_ip(src_ip, "Malware Distribution")
                        save_to_cache(payload_hash)
            except Exception as e:
                print(f"[ERROR] Failed to process payload hash: {e}")

        # ✅ Log the packet
        db_log_packet(src_ip, dst_ip, get_protocol_name(packet), payload_hash, payload_size)

        # ✅ OTX and AbuseIPDB reputation check
        try:
            check_ip_with_otx(src_ip)
            check_ip_with_otx(dst_ip)
            check_ip_with_abuseipdb(src_ip)
            check_ip_with_abuseipdb(dst_ip)
        except Exception as e:
            print(f"[ERROR] Threat intelligence check failed: {e}")

        # ✅ SSL and Topology Mapping
        try:
            ssl_inspector.inspect_tls_packet(packet)
            topology_mapper.update_topology(packet)
        except Exception as e:
            print(f"[ERROR] Packet enrichment failed: {e}")

        # ✅ Check for repeated hash anomalies
        check_packet_hash(packet, src_ip)

        # ✅ Apply detection rules
        print(f"[DEBUG] Evaluating rules for {src_ip}...")
        apply_ids_rules(packet)

        # ✅ Deep protocol-based analysis
        analyze_packet(packet)

        # ✅ Attack-specific rules
        detect_port_scan(packet)
        detect_password_cracking(packet)
        detect_ddos(packet)

        # ✅ Behavioral anomaly detection
        check_anomaly(src_ip, packet)

    except Exception as e:
        print(f"[ERROR] Failed to process packet: {e}")



def get_protocol_name(packet):
    """Get the protocol name from a packet."""
    if packet.haslayer(IP):
        proto = packet[IP].proto
        if proto == 6:
            return "TCP"
        elif proto == 17:
            return "UDP"
        elif proto == 1:
            return "ICMP"
        else:
            return f"Unknown ({proto})"
    return "Unknown"


def apply_ids_rules(packet):
    """Apply IDS rules to the packet."""
    for rule in IDS_RULES:
        if not rule.get("enabled", True):
            continue

        rule_type = rule.get("type", "")

        # Apply rule based on type
        if rule_type == "port_scan" and packet.haslayer(TCP):
            # Port scan detection handled by detect_port_scan()
            pass
        elif rule_type == "brute_force" and packet.haslayer(TCP):
            # Brute force detection handled by detect_password_cracking()
            pass
        elif rule_type == "http_flood" and packet.haslayer(TCP):
            if packet[TCP].dport in rule.get("ports", [80, 443, 5000]):
                print(f"[DEBUG] Running detect_http_flood() for {packet[IP].src}")
                detect_http_flood(packet, rule)
        elif rule_type == "icmp_flood" and packet.haslayer(ICMP):
            detect_icmp_flood(packet, rule)
        elif rule_type == "tcp_flags" and packet.haslayer(TCP):
            detect_tcp_flags(packet, rule)


def detect_http_flood(packet, rule):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    src_ip = packet[IP].src
    dport = packet[TCP].dport

    if dport not in rule.get("ports", [5000]):
        return

    print(f"[DEBUG] Running detect_http_flood() for {src_ip}:{dport}")

    current_time = time.time()
    threshold = rule.get("threshold", 10)
    timeframe = rule.get("timeframe", 10)

    if src_ip not in packet_counts:
        packet_counts[src_ip] = {"http": 1, "timestamp": current_time}
    else:
        if "http" not in packet_counts[src_ip]:
            packet_counts[src_ip]["http"] = 1
            packet_counts[src_ip]["timestamp"] = current_time
        else:
            packet_counts[src_ip]["http"] += 1

        elapsed = current_time - packet_counts[src_ip]["timestamp"]
        print(f"[DEBUG] HTTP count from {src_ip}: {packet_counts[src_ip]['http']} in {elapsed:.2f}s")

        if elapsed <= timeframe and packet_counts[src_ip]["http"] >= threshold:
            msg = (
                f"HTTP flood detected: {packet_counts[src_ip]['http']} requests "
                f"in {elapsed:.1f}s from {src_ip} to port {dport}"
            )
            print(f"[ALERT] 🚨 {msg}")
            log_alert("HTTP Flood", rule.get("severity", "high"), src_ip, msg)
            send_alert_email("🚨 HTTP Flood Detected", msg)
            block_ip(src_ip, "HTTP Flood")
            print(f"[CLI] ✅ HTTP Flood Detected from {src_ip} → blocked.")
            packet_counts[src_ip]["http"] = 0  # reset

        elif elapsed > timeframe:
            packet_counts[src_ip]["http"] = 1
            packet_counts[src_ip]["timestamp"] = current_time



def detect_icmp_flood(packet, rule):
    if packet.haslayer(ICMP):
        src_ip = packet[IP].src
        current_time = time.time()

        if src_ip not in packet_counts:
            packet_counts[src_ip] = {"icmp": 1, "timestamp": current_time}
        else:
            packet_counts[src_ip]["icmp"] += 1

        elapsed = current_time - packet_counts[src_ip]["timestamp"]
        threshold = rule.get("threshold", 20)
        timeframe = rule.get("timeframe", 30)

        print(f"[DEBUG] ICMP Flood → {src_ip} | Count: {packet_counts[src_ip]['icmp']}, Time: {elapsed:.2f}s")

        if packet_counts[src_ip]["icmp"] > threshold and elapsed <= timeframe:
            msg = f"ICMP flood detected from {src_ip} — {packet_counts[src_ip]['icmp']} packets in {elapsed:.2f}s."
            log_alert("ICMP Flood", rule.get("severity", "medium"), src_ip, msg)
            send_alert_email("🚨 ICMP Flood Detected", msg)
            block_ip(src_ip, "ICMP Flood")
            print(f"[CLI] ✅ ICMP Flood Detected from {src_ip} → blocked.")
            packet_counts[src_ip]["icmp"] = 0
        elif elapsed > timeframe:
            packet_counts[src_ip] = {"icmp": 1, "timestamp": current_time}


def detect_tcp_flags(packet, rule):
    """Detect suspicious TCP flag combinations."""
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        suspicious_flags = rule.get("flags", "")

        if flags == suspicious_flags:
            src_ip = packet[IP].src
            log_alert(
                "Suspicious TCP Flags",
                rule.get("severity", "medium"),
                src_ip,
                f"Suspicious TCP flags detected: {flags}",
            )


def analyze_packet(packet):
    """Analyze a packet for potential threats."""
    if packet.haslayer(TCP):
        # Check for suspicious TCP flag combinations (NULL, FIN, XMAS scans)
        tcp_flags = packet[TCP].flags

        # NULL scan (no flags set)
        if tcp_flags == 0:
            log_alert(
                "NULL Scan",
                "high",
                packet[IP].src,
                "NULL scan detected (no TCP flags).",
            )

        # FIN scan (only FIN flag set)
        elif tcp_flags == "F":
            log_alert("FIN Scan", "high", packet[IP].src, "FIN scan detected.")

        # XMAS scan (FIN, PSH, URG flags set)
        elif tcp_flags == "FPU":
            log_alert(
                "XMAS Scan",
                "high",
                packet[IP].src,
                "XMAS scan detected (FIN, PSH, URG flags).",
            )

        # SYN flood
        elif tcp_flags == "S":
            src_ip = packet[IP].src
            try:
                if src_ip not in packet_counts:
                    packet_counts[src_ip] = {"syn": 0, "timestamp": time.time()}
                elif "syn" not in packet_counts[src_ip]:
                    packet_counts[src_ip]["syn"] = 0

                packet_counts[src_ip]["syn"] += 1

                elapsed = time.time() - packet_counts[src_ip]["timestamp"]
                if elapsed <= 5:  # 5 second window
                    if packet_counts[src_ip]["syn"] > 20:  # 20 SYN packets in 5 seconds
                        log_alert(
                            "SYN Flood",
                            "high",
                            src_ip,
                            f"SYN flood attack detected: {packet_counts[src_ip]['syn']} SYN packets in {elapsed:.2f} seconds",
                        )
                        block_ip(src_ip)
                else:
                    packet_counts[src_ip] = {"syn": 1, "timestamp": time.time()}
            except Exception as e:
                print(f"[ERROR] Error in SYN flood detection for IP {src_ip}: {e}")
                packet_counts[src_ip] = {"syn": 1, "timestamp": time.time()}

    if packet.haslayer(ICMP):
        # Basic ICMP flood check
        src_ip = packet[IP].src
        try:
            if src_ip not in packet_counts:
                packet_counts[src_ip] = {"icmp": 0, "timestamp": time.time()}
            elif "icmp" not in packet_counts[src_ip]:
                packet_counts[src_ip]["icmp"] = 0

            packet_counts[src_ip]["icmp"] += 1

            elapsed = time.time() - packet_counts[src_ip]["timestamp"]
            if elapsed <= 30:  # 30 second window
                if packet_counts[src_ip]["icmp"] > 15:  # 15 ICMP packets in 30 seconds
                    log_alert(
                        "ICMP Flood",
                        "medium",
                        src_ip,
                        f"ICMP flood detected: {packet_counts[src_ip]['icmp']} ICMP packets in {elapsed:.2f} seconds",
                    )
                    block_ip(src_ip)
            else:
                packet_counts[src_ip] = {"icmp": 1, "timestamp": time.time()}
        except Exception as e:
            print(f"[ERROR] Error in ICMP flood detection for IP {src_ip}: {e}")
            packet_counts[src_ip] = {"icmp": 1, "timestamp": time.time()}


def detect_port_scan(packet):
    if packet.haslayer(TCP) and packet[TCP].flags & 0x02:  # SYN
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()

        if src_ip not in port_scan_attempts:
            port_scan_attempts[src_ip] = {"ports": set(), "start_time": current_time}

        port_scan_attempts[src_ip]["ports"].add(dst_port)
        elapsed = current_time - port_scan_attempts[src_ip]["start_time"]

        threshold = 5
        timeframe = 10
        for rule in IDS_RULES:
            if rule.get("type") == "port_scan" and rule.get("enabled", True):
                threshold = rule.get("threshold", 5)
                timeframe = rule.get("timeframe", 10)
                break

        print(f"[DEBUG] PortScan → {src_ip} | Ports: {len(port_scan_attempts[src_ip]['ports'])}, Time: {elapsed:.2f}s")

        if len(port_scan_attempts[src_ip]["ports"]) > threshold and elapsed <= timeframe:
            scanned_ports = sorted(port_scan_attempts[src_ip]["ports"])
            msg = (
                f"Port scan detected from {src_ip}:\n"
                f"→ Ports scanned: {len(scanned_ports)} in {elapsed:.2f} seconds\n"
                f"→ Ports: {', '.join(map(str, scanned_ports[:10]))}..."
            )
            log_alert("Port Scan", "high", src_ip, msg)
            send_alert_email("🚨 Port Scan Detected", msg)
            block_ip(src_ip, "Port Scanning")
            print(f"[CLI] ✅ PORT Scan Detected from {src_ip} → blocked.")
            port_scan_attempts.pop(src_ip, None)
        elif elapsed > timeframe:
            port_scan_attempts[src_ip] = {"ports": {dst_port}, "start_time": current_time}



def detect_password_cracking(packet):
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    dst_port = packet[TCP].dport
    src_ip = packet[IP].src

    common_auth_ports = [22, 23, 80, 443]

    if dst_port not in common_auth_ports:
        return

    print(f"[DEBUG] Running detect_password_cracking() for {src_ip} → port {dst_port}")

    current_time = time.time()
    if src_ip not in failed_logins:
        failed_logins[src_ip] = {"attempts": 1, "start_time": current_time, "port": dst_port}
    else:
        # Reset if different port
        if failed_logins[src_ip]["port"] != dst_port:
            failed_logins[src_ip] = {"attempts": 1, "start_time": current_time, "port": dst_port}
        else:
            failed_logins[src_ip]["attempts"] += 1

    elapsed = current_time - failed_logins[src_ip]["start_time"]
    threshold = 3
    timeframe = 30

    if failed_logins[src_ip]["attempts"] >= threshold and elapsed <= timeframe:
        msg = f"Brute force detected: {failed_logins[src_ip]['attempts']} attempts to port {dst_port} from {src_ip}"
        print(f"[ALERT] 🚨 {msg}")
        log_alert("SSH Brute Force", "high", src_ip, msg)
        send_alert_email("🚨 SSH Brute Force Detected", msg)
        block_ip(src_ip, "SSH Brute Force")
        print(f"[CLI] ✅ SSH Brute Detected from {src_ip} → blocked.")
        failed_logins.pop(src_ip, None)
    elif elapsed > timeframe:
        failed_logins[src_ip] = {"attempts": 1, "start_time": current_time, "port": dst_port}



def is_malicious_ip(ip):
    """Check if an IP is in a known malicious IP list."""
    # Check if IP is already blocked
    if ip in blocked_ips:
        return True

    try:
        # Check local database first
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM malicious_ips WHERE ip = ?", (ip,))
        result = cursor.fetchone()
        conn.close()

        if result:
            return True

        # Check blacklist file
        blacklist_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "full_blacklist_database.txt"
        )
        if os.path.exists(blacklist_file):
            with open(blacklist_file, "r") as f:
                for line in f:
                    if ip in line:
                        # Create a new connection to cache result in database
                        conn = sqlite3.connect(DB_PATH)
                        cursor = conn.cursor()
                        cursor.execute(
                            "INSERT INTO malicious_ips (ip, confidence_score) VALUES (?, ?)",
                            (ip, 100),
                        )
                        conn.commit()
                        conn.close()
                        return True

    except Exception as e:
        print(f"[ERROR] Failed to check IP reputation: {e}")

    return False


def block_ip(ip, reason=None):
    """Block an IP address by adding it to the blocked list.

    Args:
            ip: The IP address to block
            reason: The reason for blocking this IP (e.g., 'Port Scanning', 'DDoS')
    """
    if ip not in blocked_ips:
        blocked_ips.add(ip)
        print(f"[ALERT] Blocked IP: {ip}" + (f" - Reason: {reason}" if reason else ""))

        # Add to database for persistence
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            # If no reason provided, check if there's a recent alert for this IP
            if reason is None:
                cursor.execute(
                    "SELECT alert_type FROM alerts WHERE src_ip = ? ORDER BY timestamp DESC LIMIT 1",
                    (ip,),
                )
                result = cursor.fetchone()
                if result:
                    reason = result[0]
                else:
                    reason = "Malicious Activity"

            cursor.execute(
                "INSERT OR REPLACE INTO malicious_ips (ip, confidence_score, reason, timestamp) VALUES (?, ?, ?, datetime('now'))",
                (ip, 90, reason),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[ERROR] Failed to add blocked IP to database: {e}")


def check_anomaly(src_ip, packet=None):
    """Check for anomalous behavior."""
    global last_reset_time
    current_time = time.time()

    # Reset packet counts if the interval has passed
    if current_time - last_reset_time > INTERVAL:
        reset_anomaly_detection()

    try:
        # Initialize IP entry if not exists
        if src_ip not in packet_counts:
            packet_counts[src_ip] = {"total": 0, "timestamp": current_time}
        elif "total" not in packet_counts[src_ip]:
            packet_counts[src_ip]["total"] = 0

        # Update packet count
        packet_counts[src_ip]["total"] += 1

        # Check for DDoS (based on threshold of packets in time window)
        if packet_counts[src_ip]["total"] > THRESHOLD:
            log_alert(
                "DDoS",
                "critical",
                src_ip,
                f"Possible DDoS attack: {packet_counts[src_ip]['total']} packets in {INTERVAL} seconds",
            )
            block_ip(src_ip, "DDoS Attack")
            packet_counts[src_ip]["total"] = 0  # Reset after alert

        # UDP flood detection (lower threshold for UDP packets)
        if packet and packet.haslayer(UDP):
            if "udp" not in packet_counts[src_ip]:
                packet_counts[src_ip]["udp"] = 0

            packet_counts[src_ip]["udp"] += 1

            if packet_counts[src_ip]["udp"] > UDP_THRESHOLD:
                log_alert(
                    "UDP Flood",
                    "high",
                    src_ip,
                    f"Possible UDP flood attack: {packet_counts[src_ip]['udp']} UDP packets in {INTERVAL} seconds",
                )
                block_ip(src_ip, "UDP Flood")
                packet_counts[src_ip]["udp"] = 0  # Reset after alert
    except Exception as e:
        print(f"[ERROR] Error in check_anomaly for IP {src_ip}: {e}")
        # Ensure valid structure exists to prevent future errors
        packet_counts[src_ip] = {"total": 1, "timestamp": current_time, "udp": 0}


def reset_anomaly_detection():
    """Reset all packet counting for anomaly detection."""
    global packet_counts, last_reset_time
    packet_counts = {}
    last_reset_time = time.time()
    print("[Monitor] Reset anomaly detection counters")


def detect_ddos(packet):
    """Detect distributed denial of service attacks."""
    if packet.haslayer(IP):
        dst_ip = packet[IP].dst

        # Only track internal IPs
        if dst_ip.startswith(("192.168.", "10.", "172.16.")):
            try:
                if "ddos_targets" not in packet_counts:
                    packet_counts["ddos_targets"] = {}

                if dst_ip not in packet_counts["ddos_targets"]:
                    packet_counts["ddos_targets"][dst_ip] = {
                        "count": 0,
                        "sources": set(),
                        "timestamp": time.time(),
                    }

                packet_counts["ddos_targets"][dst_ip]["count"] += 1
                packet_counts["ddos_targets"][dst_ip]["sources"].add(packet[IP].src)

                # Check if threshold is exceeded
                current_time = time.time()
                elapsed = (
                    current_time - packet_counts["ddos_targets"][dst_ip]["timestamp"]
                )

                if elapsed <= 60:  # 60 second window
                    # Alert if many packets from multiple sources
                    if (
                        packet_counts["ddos_targets"][dst_ip]["count"] > 1000
                        and len(packet_counts["ddos_targets"][dst_ip]["sources"]) > 3
                    ):
                        log_alert(
                            "DDoS",
                            "critical",
                            dst_ip,
                            f"DDoS attack detected: {packet_counts['ddos_targets'][dst_ip]['count']} packets from {len(packet_counts['ddos_targets'][dst_ip]['sources'])} sources in {elapsed:.2f} seconds",
                        )
                        # Block all attacking IPs
                        for attacking_ip in packet_counts["ddos_targets"][dst_ip][
                            "sources"
                        ]:
                            block_ip(attacking_ip, "DDoS Attack")

                        # Reset after alert
                        packet_counts["ddos_targets"][dst_ip] = {
                            "count": 0,
                            "sources": set(),
                            "timestamp": current_time,
                        }
                else:
                    # Reset if timeframe has passed
                    packet_counts["ddos_targets"][dst_ip] = {
                        "count": 1,
                        "sources": {packet[IP].src},
                        "timestamp": current_time,
                    }
            except Exception as e:
                print(f"[ERROR] Error in detect_ddos for IP {dst_ip}: {e}")
                # Ensure valid structure exists to prevent future errors
                if "ddos_targets" not in packet_counts:
                    packet_counts["ddos_targets"] = {}
                packet_counts["ddos_targets"][dst_ip] = {
                    "count": 1,
                    "sources": {packet[IP].src},
                    "timestamp": time.time(),
                }

def periodic_network_scan(interval=60):
    """Periodically scan network to update device Online/Offline status."""
    while True:
        try:
            print("[Scanner] Running periodic device scan...")
            scan_network()
        except Exception as e:
            print(f"[Scanner] Periodic scan failed: {e}")
        time.sleep(interval)

def start_sniffing(interface=None, retry_count=0, max_retries=10):
    """Start packet sniffing for intrusion detection."""
    # Initialize malware database
    init_malware_db()

    # Check if we've exceeded the max retries
    if retry_count >= max_retries:
        print(
            f"[CRITICAL] Maximum retry count ({max_retries}) exceeded. Packet monitoring has failed permanently."
        )
        return

    # Load IDS rules first
    try:
        load_ids_rules()
    except Exception as e:
        print(f"[ERROR] Failed to load IDS rules: {e}")
        # Continue anyway with default or empty rules

    if not interface:
        try:
            from backend.scanner import get_valid_interface

            interface = get_valid_interface()
        except Exception as e:
            print(f"[ERROR] Error getting valid interface: {e}")
            interface = None

    if not interface:
        print("[ERROR] No valid interface found. Cannot start monitoring.")
        print("[INFO] Retrying in 30 seconds...")
        time.sleep(30)
        start_sniffing(
            interface=None, retry_count=retry_count + 1, max_retries=max_retries
        )
        return

    print(f"[Monitor] Starting packet monitoring on interface {interface}")
    print(f"[Monitor] Using filter: {SNIFF_FILTER}")

    try:
        # Start packet sniffing with comprehensive error handling
        try:
            # Set a reasonable timeout to avoid infinite sniffing
            actual_timeout = 300 if SNIFF_TIMEOUT is None else SNIFF_TIMEOUT

            scapy.sniff(
                iface=interface,
                store=False,
                prn=packet_callback,
                filter=SNIFF_FILTER,
                timeout=actual_timeout,
                count=0,  # Set count to 0 to avoid 'total' key access issues
            )
        except KeyError as ke:
            print(f"[WARNING] KeyError in packet sniffing: {ke}")
            # Continue to restart with incremented retry count
        except AttributeError as ae:
            print(f"[WARNING] AttributeError in packet sniffing: {ae}")
            # Continue to restart with incremented retry count
        except PermissionError as pe:
            print(f"[ERROR] Permission error: {pe}")
            print("[INFO] You may need to run the program with sudo/admin privileges.")
            # Wait longer before retrying permission issues
            time.sleep(60)
            start_sniffing(
                interface, retry_count=retry_count + 1, max_retries=max_retries
            )
            return

        print("[Monitor] Packet sniffing stopped")
    except KeyboardInterrupt:
        print("[Monitor] Packet sniffing stopped by user")
        raise  # Re-raise to allow main thread to handle shutdown
    except Exception as e:
        print(f"[ERROR] Packet sniffing failed with unhandled exception: {e}")

    # Wait a bit before restarting
    print(
        f"[Monitor] Restarting packet monitoring... (retry {retry_count+1}/{max_retries})"
    )

    # Exponential backoff for retries
    wait_time = min(5 * (2**retry_count), 300)  # Maximum 5 minutes
    time.sleep(wait_time)

    # Recursive call with incremented retry count
    start_sniffing(interface, retry_count=retry_count + 1, max_retries=max_retries)


def query_malwarebazaar(file_hash, retries=3, delay=10):
    payload = {"query": "get_info", "hash": file_hash}
    headers = {"Auth-Key": MALWARE_API_KEY}

    for attempt in range(retries):
        try:
            response = requests.post(
                MALWARE_API_URL, json=payload, headers=headers, timeout=15
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"[MalwareBazaar] Error: {e} | Retrying in {delay}s...")
            time.sleep(delay)
    return {"query_status": "failed"}


def check_ip_with_otx(ip_address):
    """Check if an IP is malicious using OTX AlienVault."""
    if ip_address in otx_checked_ips:
        return

    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            pulses = data.get("pulse_info", {})
            count = pulses.get("count", 0)
            if count > 0:
                categories = [p.get("name") for p in pulses.get("pulses", [])]
                category_str = ", ".join(categories)
                msg = f"[OTX] {ip_address} found in {count} pulses.\nThreat Categories: {category_str}"
                print(f"[ALERT] {msg}")
                send_alert_email("OTX IP Alert", msg)
                block_ip(ip_address, "OTX Threat Intelligence")
        else:
            print(f"[OTX] Failed to check {ip_address}. Status: {response.status_code}")
    except Exception as e:
        print(f"[OTX] Error for {ip_address}: {e}")
    otx_checked_ips.add(ip_address)


def check_ip_with_abuseipdb(ip_address, score_threshold=50):
    """Check if an IP is abusive using AbuseIPDB."""
    if ip_address in abuseipdb_checked_ips:
        return

    try:
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": 30}
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=10,
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            if score >= score_threshold:
                usage_type = data.get("usageType", "Unknown")
                msg = f"[AbuseIPDB] {ip_address} flagged with score {score} | Usage: {usage_type}"
                print(f"[ALERT] {msg}")
                send_alert_email("AbuseIPDB Alert", msg)
                block_ip(ip_address, "AbuseIPDB Flagged")
        else:
            print(
                f"[AbuseIPDB] Failed for {ip_address}. Status: {response.status_code}"
            )
    except Exception as e:
        print(f"[AbuseIPDB] Error for {ip_address}: {e}")
    abuseipdb_checked_ips.add(ip_address)


# Report generation functions
def generate_report(report_type="daily", output_format="html", custom_range=None):
    """
    Generate security reports from the monitoring data.

    Args:
            report_type: Type of report - 'daily', 'weekly', 'monthly', or 'custom'
            output_format: Format of report - 'html', 'csv', or 'json'
            custom_range: Tuple of (start_date, end_date) for custom reports

    Returns:
            Path to the generated report file
    """
    # Create reports directory if it doesn't exist
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)

    # Determine date range for the report
    end_date = datetime.datetime.now()
    if report_type == "daily":
        start_date = end_date - datetime.timedelta(days=1)
        report_name = f"ids_report_daily_{end_date.strftime('%Y%m%d')}"
    elif report_type == "weekly":
        start_date = end_date - datetime.timedelta(days=7)
        report_name = f"ids_report_weekly_{end_date.strftime('%Y%m%d')}"
    elif report_type == "monthly":
        start_date = end_date - datetime.timedelta(days=30)
        report_name = f"ids_report_monthly_{end_date.strftime('%Y%m%d')}"
    elif report_type == "custom" and custom_range:
        start_date, end_date = custom_range
        report_name = f"ids_report_custom_{start_date.strftime('%Y%m%d')}_to_{end_date.strftime('%Y%m%d')}"
    else:
        # Default to daily if invalid type
        start_date = end_date - datetime.timedelta(days=1)
        report_name = f"ids_report_daily_{end_date.strftime('%Y%m%d')}"

    # Get report data from database
    report_data = get_report_data(start_date, end_date)

    # Generate report in requested format
    report_path = None
    if output_format == "html":
        report_path = generate_html_report(
            report_name, report_data, start_date, end_date
        )
    elif output_format == "csv":
        report_path = generate_csv_report(
            report_name, report_data, start_date, end_date
        )
    elif output_format == "json":
        report_path = generate_json_report(
            report_name, report_data, start_date, end_date
        )

    print(f"[Report] Generated {report_type} report at {report_path}")
    return report_path


def get_report_data(start_date, end_date):
    """Fetch report data from the database for the given time period."""
    # Convert dates to strings for SQLite
    start_str = start_date.strftime("%Y-%m-%d %H:%M:%S")
    end_str = end_date.strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Alerts summary by severity
        cursor.execute(
            """
			SELECT severity, COUNT(*) as count 
			FROM alerts 
			WHERE timestamp BETWEEN ? AND ? 
			GROUP BY severity
			ORDER BY count DESC
		""",
            (start_str, end_str),
        )
        alerts_by_severity = cursor.fetchall()

        # Alerts by type
        cursor.execute(
            """
			SELECT alert_type, COUNT(*) as count 
			FROM alerts 
			WHERE timestamp BETWEEN ? AND ? 
			GROUP BY alert_type
			ORDER BY count DESC
		""",
            (start_str, end_str),
        )
        alerts_by_type = cursor.fetchall()

        # Top source IPs
        cursor.execute(
            """
			SELECT source_ip, COUNT(*) as count 
			FROM alerts 
			WHERE timestamp BETWEEN ? AND ? 
			GROUP BY source_ip
			ORDER BY count DESC
			LIMIT 10
		""",
            (start_str, end_str),
        )
        top_source_ips = cursor.fetchall()

        # Traffic statistics
        cursor.execute(
            """
			SELECT protocol, COUNT(*) as count 
			FROM packets 
			WHERE timestamp BETWEEN ? AND ? 
			GROUP BY protocol
		""",
            (start_str, end_str),
        )
        traffic_by_protocol = cursor.fetchall()

        # Total packet count
        cursor.execute(
            """
			SELECT COUNT(*) 
			FROM packets 
			WHERE timestamp BETWEEN ? AND ?
		""",
            (start_str, end_str),
        )
        total_packets = cursor.fetchone()[0]

        # Total alert count
        cursor.execute(
            """
			SELECT COUNT(*) 
			FROM alerts 
			WHERE timestamp BETWEEN ? AND ?
		""",
            (start_str, end_str),
        )
        total_alerts = cursor.fetchone()[0]

        # Hourly traffic distribution
        cursor.execute(
            """
			SELECT strftime('%H', timestamp) as hour, COUNT(*) as count 
			FROM packets 
			WHERE timestamp BETWEEN ? AND ? 
			GROUP BY hour
			ORDER BY hour
		""",
            (start_str, end_str),
        )
        hourly_traffic = cursor.fetchall()

        # Recent alerts (last 20)
        cursor.execute(
            """
			SELECT alert_type, severity, source_ip, description, timestamp 
			FROM alerts 
			WHERE timestamp BETWEEN ? AND ? 
			ORDER BY timestamp DESC
			LIMIT 20
		""",
            (start_str, end_str),
        )
        recent_alerts = cursor.fetchall()

        conn.close()

        return {
            "alerts_by_severity": alerts_by_severity,
            "alerts_by_type": alerts_by_type,
            "top_source_ips": top_source_ips,
            "traffic_by_protocol": traffic_by_protocol,
            "total_packets": total_packets,
            "total_alerts": total_alerts,
            "hourly_traffic": hourly_traffic,
            "recent_alerts": recent_alerts,
            "start_date": start_date,
            "end_date": end_date,
        }

    except Exception as e:
        print(f"[ERROR] Failed to fetch report data: {e}")
        return {"error": str(e), "start_date": start_date, "end_date": end_date}


def generate_html_report(report_name, report_data, start_date, end_date):
    """Generate an HTML report from the given data."""
    report_path = os.path.join(REPORTS_DIR, f"{report_name}.html")

    try:
        with open(report_path, "w") as f:
            # Write HTML header
            f.write(
                f"""<!DOCTYPE html>
<html>
<head>
	<title>IDS Security Report</title>
	<style>
		body {{ font-family: Arial, sans-serif; margin: 20px; }}
		h1, h2 {{ color: #2c3e50; }}
		.container {{ max-width: 1200px; margin: 0 auto; }}
		.section {{ margin-bottom: 30px; border: 1px solid #ddd; padding: 20px; border-radius: 5px; }}
		.summary {{ display: flex; justify-content: space-between; }}
		.summary-box {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; width: 23%; text-align: center; }}
		.high {{ color: #e74c3c; }}
		.medium {{ color: #f39c12; }}
		.low {{ color: #3498db; }}
		table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
		th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
		th {{ background-color: #f2f2f2; }}
		tr:hover {{ background-color: #f5f5f5; }}
	</style>
</head>
<body>
	<div class="container">
		<h1>Network IDS Security Report</h1>
		<p>Period: {start_date.strftime("%Y-%m-%d %H:%M:%S")} to {end_date.strftime("%Y-%m-%d %H:%M:%S")}</p>
		<p>Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
		
		<div class="section summary">
			<div class="summary-box">
				<h3>Total Alerts</h3>
				<p style="font-size: 24px;">{report_data.get('total_alerts', 0)}</p>
			</div>
			<div class="summary-box">
				<h3>Total Traffic</h3>
				<p style="font-size: 24px;">{report_data.get('total_packets', 0)} packets</p>
			</div>
			<div class="summary-box">
				<h3>Critical Alerts</h3>
				<p style="font-size: 24px;" class="high">
					{sum(count for sev, count in report_data.get('alerts_by_severity', []) if sev == 'critical' or sev == 'high')}
				</p>
			</div>
			<div class="summary-box">
				<h3>Top Attack</h3>
				<p style="font-size: 24px;">
					{report_data.get('alerts_by_type', [['None', 0]])[0][0] if report_data.get('alerts_by_type') else 'None'}
				</p>
			</div>
		</div>
		
		<div class="section">
			<h2>Alert Distribution by Severity</h2>
			<table>
				<tr>
					<th>Severity</th>
					<th>Count</th>
					<th>Percentage</th>
				</tr>"""
            )

            # Add alert severity data
            total_alerts = report_data.get("total_alerts", 0)
            for severity, count in report_data.get("alerts_by_severity", []):
                percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                severity_class = (
                    "high"
                    if severity in ["critical", "high"]
                    else ("medium" if severity == "medium" else "low")
                )
                f.write(
                    f"""
				<tr>
					<td class="{severity_class}">{severity}</td>
					<td>{count}</td>
					<td>{percentage:.2f}%</td>
				</tr>"""
                )

            f.write(
                """
			</table>
		</div>
		
		<div class="section">
			<h2>Top Alert Types</h2>
			<table>
				<tr>
					<th>Alert Type</th>
					<th>Count</th>
					<th>Percentage</th>
				</tr>"""
            )

            # Add alert type data
            for alert_type, count in report_data.get("alerts_by_type", []):
                percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                f.write(
                    f"""
				<tr>
					<td>{alert_type}</td>
					<td>{count}</td>
					<td>{percentage:.2f}%</td>
				</tr>"""
                )

            f.write(
                """
			</table>
		</div>
		
		<div class="section">
			<h2>Top Source IPs</h2>
			<table>
				<tr>
					<th>Source IP</th>
					<th>Alert Count</th>
				</tr>"""
            )

            # Add source IP data
            for ip, count in report_data.get("top_source_ips", []):
                f.write(
                    f"""
				<tr>
					<td>{ip}</td>
					<td>{count}</td>
				</tr>"""
                )

            f.write(
                """
			</table>
		</div>
		
		<div class="section">
			<h2>Traffic by Protocol</h2>
			<table>
				<tr>
					<th>Protocol</th>
					<th>Packet Count</th>
					<th>Percentage</th>
				</tr>"""
            )

            # Add protocol data
            total_packets = report_data.get("total_packets", 0)
            for protocol, count in report_data.get("traffic_by_protocol", []):
                percentage = (count / total_packets * 100) if total_packets > 0 else 0
                f.write(
                    f"""
				<tr>
					<td>{protocol}</td>
					<td>{count}</td>
					<td>{percentage:.2f}%</td>
				</tr>"""
                )

            f.write(
                """
			</table>
		</div>
		
		<div class="section">
			<h2>Recent Alerts</h2>
			<table>
				<tr>
					<th>Timestamp</th>
					<th>Type</th>
					<th>Severity</th>
					<th>Source IP</th>
					<th>Description</th>
				</tr>"""
            )

            # Add recent alerts
            for (
                alert_type,
                severity,
                source_ip,
                description,
                timestamp,
            ) in report_data.get("recent_alerts", []):
                severity_class = (
                    "high"
                    if severity in ["critical", "high"]
                    else ("medium" if severity == "medium" else "low")
                )
                f.write(
                    f"""
				<tr>
					<td>{timestamp}</td>
					<td>{alert_type}</td>
					<td class="{severity_class}">{severity}</td>
					<td>{source_ip}</td>
					<td>{description}</td>
				</tr>"""
                )

            f.write(
                """
							</table>
						</div>
					</div>
				</body>
			</html>
			"""
            )

        return report_path
    except Exception as e:
        print(f"[ERROR] Failed to generate HTML report: {e}")
        return None


def generate_csv_report(report_name, report_data, start_date, end_date):
    """Generate a CSV report from the given data."""
    report_path = os.path.join(REPORTS_DIR, f"{report_name}.csv")

    try:
        with open(report_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)

            # Write header information
            writer.writerow(["IDS Security Report"])
            writer.writerow(
                [
                    f'Period: {start_date.strftime("%Y-%m-%d %H:%M:%S")} to {end_date.strftime("%Y-%m-%d %H:%M:%S")}'
                ]
            )
            writer.writerow(
                [
                    f'Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
                ]
            )
            writer.writerow([])

            # Write summary
            writer.writerow(["Summary"])
            writer.writerow(["Total Alerts", report_data.get("total_alerts", 0)])
            writer.writerow(["Total Packets", report_data.get("total_packets", 0)])
            writer.writerow([])

            # Write alerts by severity
            writer.writerow(["Alert Distribution by Severity"])
            writer.writerow(["Severity", "Count", "Percentage"])
            total_alerts = report_data.get("total_alerts", 0)
            for severity, count in report_data.get("alerts_by_severity", []):
                percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                writer.writerow([severity, count, f"{percentage:.2f}%"])
            writer.writerow([])

            # Write alerts by type
            writer.writerow(["Top Alert Types"])
            writer.writerow(["Alert Type", "Count", "Percentage"])
            for alert_type, count in report_data.get("alerts_by_type", []):
                percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                writer.writerow([alert_type, count, f"{percentage:.2f}%"])
            writer.writerow([])

            # Write top source IPs
            writer.writerow(["Top Source IPs"])
            writer.writerow(["Source IP", "Alert Count"])
            for ip, count in report_data.get("top_source_ips", []):
                writer.writerow([ip, count])
            writer.writerow([])

            # Write traffic by protocol
            writer.writerow(["Traffic by Protocol"])
            writer.writerow(["Protocol", "Packet Count", "Percentage"])
            total_packets = report_data.get("total_packets", 0)
            for protocol, count in report_data.get("traffic_by_protocol", []):
                percentage = (count / total_packets * 100) if total_packets > 0 else 0
                writer.writerow([protocol, count, f"{percentage:.2f}%"])
            writer.writerow([])

            # Write recent alerts
            writer.writerow(["Recent Alerts"])
            writer.writerow(
                ["Timestamp", "Type", "Severity", "Source IP", "Description"]
            )
            for (
                alert_type,
                severity,
                source_ip,
                description,
                timestamp,
            ) in report_data.get("recent_alerts", []):
                writer.writerow(
                    [timestamp, alert_type, severity, source_ip, description]
                )

        return report_path
    except Exception as e:
        print(f"[ERROR] Failed to generate CSV report: {e}")
        return None


def generate_json_report(report_name, report_data, start_date, end_date):
    """Generate a JSON report from the given data."""
    report_path = os.path.join(REPORTS_DIR, f"{report_name}.json")

    try:
        # Convert datetime objects to strings for JSON serialization
        report_data_copy = report_data.copy()
        report_data_copy["start_date"] = start_date.strftime("%Y-%m-%d %H:%M:%S")
        report_data_copy["end_date"] = end_date.strftime("%Y-%m-%d %H:%M:%S")
        report_data_copy["generated_at"] = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        with open(report_path, "w") as f:
            json.dump(report_data_copy, f, indent=4)

        return report_path
    except Exception as e:
        print(f"[ERROR] Failed to generate JSON report: {e}")
        return None


def schedule_daily_report():
    """Schedule automatic daily report generation."""
    print("[Report] Scheduling daily report generation")

    # Function to run at the scheduled time
    def run_daily_report():
        try:
            # Generate report in all formats
            for fmt in ["html", "csv", "json"]:
                generate_report(report_type="daily", output_format=fmt)
            print("[Report] Daily report generated successfully")
        except Exception as e:
            print(f"[ERROR] Failed to generate daily report: {e}")

    # Calculate time until next run (midnight)
    now = datetime.datetime.now()
    tomorrow = now + datetime.timedelta(days=1)
    tomorrow_midnight = datetime.datetime(
        tomorrow.year, tomorrow.month, tomorrow.day, 0, 0, 0
    )
    seconds_until_midnight = (tomorrow_midnight - now).total_seconds()

    # Schedule the first run
    threading.Timer(seconds_until_midnight, run_daily_report).start()
    print(
        f"[Report] Next daily report scheduled at {tomorrow_midnight.strftime('%Y-%m-%d %H:%M:%S')}"
    )


def generate_reports():
    """Generate comprehensive reports from all components."""
    try:
        reports = {
            "timestamp": datetime.now().isoformat(),
            "ssl_inspection": ssl_inspector.get_traffic_stats(),
            "topology": topology_mapper.get_topology(),
        }

        report_path = os.path.join(
            REPORTS_DIR,
            f'comprehensive_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
        )
        with open(report_path, "w") as f:
            json.dump(reports, f, indent=4)

        return report_path

    except Exception as e:
        print(f"[ERROR] Failed to generate reports: {e}")
        return None


def run_monitor_in_thread():
    """Run the packet monitoring functionality in a separate thread."""
    import threading

    monitor_thread = threading.Thread(target=start_sniffing)
    monitor_thread.daemon = (
        True  # This ensures the thread will exit when the main program exits
    )
    monitor_thread.start()

    print(
        f"[Monitor] Started packet sniffing in background thread {monitor_thread.name}"
    )
    return monitor_thread



def is_hash_in_cache(file_hash):
    """Check if a file hash exists in the malware hash cache."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT 1 FROM malware_hashes WHERE sha256 = ?", (file_hash,))
        result = cursor.fetchone()
    except sqlite3.OperationalError as e:
        print(f"[Error] DB error: {e}")
        init_malware_db()
        return False
    finally:
        conn.close()
    return result is not None


def save_to_cache(file_hash):
    """Save a hash to the malware hash cache."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO malware_hashes (sha256) VALUES (?)", (file_hash,)
    )
    conn.commit()
    conn.close()


def init_malware_db():
    """Initialize the malware hashes table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS malware_hashes (
            sha256 TEXT PRIMARY KEY
        )
    """
    )
    conn.commit()
    conn.close()
    print("[Monitor] Malware database initialized.")
