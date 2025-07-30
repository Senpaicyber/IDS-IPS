import scapy.all as scapy
import ssl
import hashlib
import datetime
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from .database import log_alert, log_packet
from config.settings import DB_PATH, REPORTS_DIR


class SSLInspector:
    def __init__(self):
        self.known_certificates = {}
        self.suspicious_certificates = set()
        self.encrypted_traffic_stats = {
            "total": 0,
            "by_protocol": {},
            "by_domain": {},
            "suspicious": 0,
        }
        self.ssl_ports = {443, 993, 995, 465, 587}  # Common SSL/TLS ports

    def inspect_tls_packet(self, packet):
        """Inspect SSL/TLS traffic for anomalies."""
        try:
            if packet.haslayer(scapy.TCP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                dst_port = packet[scapy.TCP].dport

                # Check if it's an SSL/TLS port
                if dst_port in self.ssl_ports:
                    self._update_traffic_stats(packet)

                    # Check for SSL/TLS handshake
                    if packet[scapy.TCP].flags & 0x02:  # SYN flag
                        self._analyze_ssl_handshake(packet)

                    # Check for encrypted payload
                    if packet.haslayer(scapy.Raw):
                        self._analyze_encrypted_payload(packet)

        except Exception as e:
            print(f"[SSL Inspector] Error analyzing packet: {e}")

    def _analyze_ssl_handshake(self, packet):
        """Analyze SSL/TLS handshake patterns."""
        try:
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            # Extract TCP options for fingerprinting
            tcp_options = packet[scapy.TCP].options

            # Check for suspicious handshake patterns
            if self._is_suspicious_handshake(tcp_options):
                log_alert(
                    "Suspicious SSL Handshake",
                    "medium",
                    src_ip,
                    "Suspicious SSL/TLS handshake pattern detected",
                )

            # Log the connection attempt with additional_info
            log_packet(
                src_ip,
                dst_ip,
                "SSL/TLS",
                None,
                len(packet),
                additional_info={
                    "port": packet[scapy.TCP].dport,
                    "options": str(tcp_options),
                },
            )

        except Exception as e:
            print(f"[SSL Inspector] Error analyzing handshake: {e}")

    def _analyze_encrypted_payload(self, packet):
        """Analyze encrypted payload for anomalies."""
        try:
            payload = packet[scapy.Raw].load

            # Check payload size
            if len(payload) > 1500:  # Large encrypted payload
                log_alert(
                    "Large Encrypted Payload",
                    "medium",
                    packet[scapy.IP].src,
                    f"Large encrypted payload detected: {len(payload)} bytes",
                )

            # Check for common encryption patterns
            if self._is_suspicious_payload(payload):
                log_alert(
                    "Suspicious Encrypted Payload",
                    "high",
                    packet[scapy.IP].src,
                    "Suspicious encrypted payload pattern detected",
                )

            # Log detailed information about the encrypted payload
            payload_stats = {
                "size": len(payload),
                "entropy": len(set(payload)),
                "port": packet[scapy.TCP].dport,
                "has_ssl_header": 1 if payload.startswith(b"\x16\x03") else 0,
            }

            log_packet(
                packet[scapy.IP].src,
                packet[scapy.IP].dst,
                "SSL/TLS-Data",
                hashlib.sha256(payload).hexdigest(),
                len(payload),
                additional_info=payload_stats,
            )

        except Exception as e:
            print(f"[SSL Inspector] Error analyzing payload: {e}")

    def _is_suspicious_handshake(self, tcp_options):
        """Check for suspicious SSL/TLS handshake patterns."""
        suspicious_patterns = [
            "MSS",  # Unusual MSS values
            "WScale",  # Unusual window scaling
            "Timestamp",  # Missing timestamp
            "SACK",  # Unusual SACK options
        ]

        # Convert options to string for pattern matching
        options_str = str(tcp_options)
        return any(pattern in options_str for pattern in suspicious_patterns)

    def _is_suspicious_payload(self, payload):
        """Check for suspicious encrypted payload patterns."""
        try:
            # Check for common encryption patterns
            if payload.startswith(b"\x16\x03"):  # SSL/TLS record header
                return False

            # Check for unusual patterns
            if len(set(payload)) < 10:  # Low entropy
                return True

            # Check for common malware patterns
            malware_patterns = [
                b"\x00\x00\x00\x00",  # Null padding
                b"\xFF\xFF\xFF\xFF",  # All ones
                b"\x00\x01\x00\x01",  # Common pattern
            ]

            return any(pattern in payload for pattern in malware_patterns)

        except Exception:
            return False

    def _update_traffic_stats(self, packet):
        """Update encrypted traffic statistics."""
        try:
            self.encrypted_traffic_stats["total"] += 1

            # Update protocol stats
            protocol = packet[scapy.IP].proto
            if protocol not in self.encrypted_traffic_stats["by_protocol"]:
                self.encrypted_traffic_stats["by_protocol"][protocol] = 0
            self.encrypted_traffic_stats["by_protocol"][protocol] += 1

            # Check for suspicious patterns
            if self._is_suspicious_traffic(packet):
                self.encrypted_traffic_stats["suspicious"] += 1

        except Exception as e:
            print(f"[SSL Inspector] Error updating traffic stats: {e}")

    def _is_suspicious_traffic(self, packet):
        """Check for suspicious encrypted traffic patterns."""
        try:
            # Check for high volume of encrypted traffic
            if len(packet) > 1500:  # Large encrypted packets
                return True

            # Check for unusual port usage
            if packet[scapy.TCP].dport not in self.ssl_ports:
                return True

            return False
        except:
            return False

    def get_traffic_stats(self):
        """Get current encrypted traffic statistics."""
        return self.encrypted_traffic_stats
