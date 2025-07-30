import scapy.all as scapy
import networkx as nx
import matplotlib.pyplot as plt
import ipaddress
import json
import os
from datetime import datetime
from .database import log_packet
from config.settings import DB_PATH, REPORTS_DIR


class NetworkTopology:
    def __init__(self):
        self.graph = nx.Graph()
        self.devices = {}
        self.last_update = datetime.now()
        self.update_interval = 300  # 5 minutes

    def update_topology(self, packet):
        """Update network topology based on packet information."""
        try:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst

                # Add nodes (devices)
                self._add_device(src_ip, packet)
                self._add_device(dst_ip, packet)

                # Add edge (connection)
                self.graph.add_edge(src_ip, dst_ip)

                # Update device information
                self._update_device_info(src_ip, packet)
                self._update_device_info(dst_ip, packet)

        except Exception as e:
            print(f"[Topology] Error updating topology: {e}")

    def _add_device(self, ip, packet):
        """Add a device to the topology."""
        if ip not in self.devices:
            self.devices[ip] = {
                "ip": ip,
                "mac": self._get_mac(packet, ip),
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "services": set(),
                "os_fingerprint": None,
                "vendor": None,
                "traffic_stats": {"inbound": 0, "outbound": 0, "total": 0},
            }

    def _update_device_info(self, ip, packet):
        """Update device information based on packet."""
        if ip in self.devices:
            device = self.devices[ip]
            device["last_seen"] = datetime.now()

            # Update MAC address if available
            mac = self._get_mac(packet, ip)
            if mac:
                device["mac"] = mac

            # Update services
            if packet.haslayer(scapy.TCP):
                port = packet[scapy.TCP].dport
                device["services"].add(port)

            # Update traffic stats
            if packet[scapy.IP].src == ip:
                device["traffic_stats"]["outbound"] += 1
            else:
                device["traffic_stats"]["inbound"] += 1
            device["traffic_stats"]["total"] += 1

            # Attempt OS fingerprinting
            self._fingerprint_os(device, packet)

    def _get_mac(self, packet, ip):
        """Extract MAC address from packet."""
        try:
            if packet.haslayer(scapy.Ether):
                if packet[scapy.IP].src == ip:
                    return packet[scapy.Ether].src
                elif packet[scapy.IP].dst == ip:
                    return packet[scapy.Ether].dst
        except:
            pass
        return None

    def _fingerprint_os(self, device, packet):
        """Attempt to fingerprint the operating system."""
        try:
            if packet.haslayer(scapy.TCP):
                tcp = packet[scapy.TCP]

                # Basic OS fingerprinting based on TCP options and window size
                window_size = tcp.window
                options = tcp.options

                # Windows typically uses window sizes that are multiples of 8192
                if window_size % 8192 == 0:
                    device["os_fingerprint"] = "Windows"
                # Linux often uses specific window sizes and TCP options
                elif window_size in [5840, 5720, 4096]:
                    device["os_fingerprint"] = "Linux"
                # macOS has distinct TCP behavior
                elif window_size == 65535 and len(options) > 0:
                    device["os_fingerprint"] = "macOS"

        except Exception as e:
            print(f"[Topology] Error in OS fingerprinting: {e}")

    def get_topology(self):
        """Get current network topology."""
        return {
            "devices": self.devices,
            "connections": list(self.graph.edges()),
            "last_update": self.last_update,
        }

    def generate_report(self):
        """Generate a topology report."""
        try:
            # Create reports directory if it doesn't exist
            os.makedirs(REPORTS_DIR, exist_ok=True)

            # Generate JSON report
            report = {
                "timestamp": datetime.now().isoformat(),
                "devices": len(self.devices),
                "connections": len(self.graph.edges()),
                "device_details": self.devices,
            }

            report_path = os.path.join(
                REPORTS_DIR,
                f'topology_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
            )
            with open(report_path, "w") as f:
                json.dump(report, f, indent=4)

            # Generate visualization
            self._visualize_topology()

            return report_path

        except Exception as e:
            print(f"[Topology] Error generating report: {e}")
            return None

    def _visualize_topology(self):
        """Generate a visualization of the network topology."""
        try:
            plt.figure(figsize=(12, 8))

            # Draw the graph
            pos = nx.spring_layout(self.graph)
            nx.draw(
                self.graph,
                pos,
                with_labels=True,
                node_color="lightblue",
                node_size=500,
                font_size=8,
                font_weight="bold",
            )

            # Save the visualization
            viz_path = os.path.join(
                REPORTS_DIR,
                f'topology_viz_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png',
            )
            plt.savefig(viz_path)
            plt.close()

            return viz_path

        except Exception as e:
            print(f"[Topology] Error generating visualization: {e}")
            return None
