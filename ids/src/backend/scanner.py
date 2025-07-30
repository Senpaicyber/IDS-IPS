import scapy.all as scapy
import netifaces
import sqlite3
import socket
import psutil
import os
from scapy.all import ARP, Ether, srp, IPv6, ICMPv6ND_NS, ICMPv6ND_NA

# Try importing DB_PATH or fallback to default local DB
try:
    from config.settings import DB_PATH
except ImportError:
    DB_PATH = os.path.join(os.path.dirname(__file__), "devices.db")

def get_valid_interface():
    interfaces = scapy.get_if_list()
    selected = None

    print("\n[Scanner] Detected Available Interfaces:")
    for idx, iface in enumerate(interfaces):
        try:
            ip = scapy.get_if_addr(iface)
            if ip.startswith("169.254.") or ip == "0.0.0.0":
                continue
            print(f"  [{idx}] {iface} -> {ip}")
            if ip.startswith(("192.168.", "10.", "172.")):
                selected = iface
                break
        except Exception:
            continue

    if selected:
        print(f"\n[Scanner] ✅ Automatically selected interface: {selected}")
        return selected

    for iface in interfaces:
        try:
            ip = scapy.get_if_addr(iface)
            if ip.startswith("169.254.") or ip == "0.0.0.0":
                continue
            print(f"\n[Scanner] ⚠ Fallback selected: {iface}")
            return iface
        except Exception:
            continue

    print("[ERROR] ❌ No valid network interface found.")
    return None

def get_network_range(interface):
    try:
        ip = scapy.get_if_addr(interface)
        for iface_name, iface_addrs in psutil.net_if_addrs().items():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET and addr.address == ip:
                    netmask = addr.netmask
                    if not netmask:
                        return None
                    network_parts = [
                        str(int(ip.split(".")[i]) & int(netmask.split(".")[i])) for i in range(4)
                    ]
                    network = ".".join(network_parts)
                    return f"{network}/24"
        return None
    except Exception as e:
        print(f"[ERROR] Failed to get network range: {e}")
        return None

def scan_ipv4_network(interface):
    ip_range = get_network_range(interface)
    if not ip_range:
        return []

    print(f"\n[Scanner] Scanning IPv4 network range: {ip_range} on {interface}")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast / arp_request

    try:
        answered_list = srp(arp_packet, iface=interface, timeout=3, verbose=False)[0]
    except Exception as e:
        print(f"[ERROR] Scapy failed to scan: {e}")
        return []

    active_ips = set()
    devices = []
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for _, received in answered_list:
        ip = received.psrc
        mac = received.hwsrc
        active_ips.add(ip)
        devices.append({"ip": ip, "mac": mac})
        print(f"[Scanner] ✅ Found IPv4 Device → IP: {ip}, MAC: {mac}")
        cursor.execute(
            "INSERT OR REPLACE INTO devices (ip, mac, timestamp, status) VALUES (?, ?, datetime('now'), 'Online')",
            (ip, mac),
        )

    cursor.execute("SELECT ip FROM devices WHERE ip LIKE '%.%'")
    known_ips = {row[0] for row in cursor.fetchall()}
    offline_ips = known_ips - active_ips

    for ip in offline_ips:
        print(f"[Scanner] ❌ Marked as Offline → IP: {ip}")
        cursor.execute(
            "UPDATE devices SET status='Offline', timestamp=datetime('now') WHERE ip=?",
            (ip,),
        )

    conn.commit()
    conn.close()
    return devices

def scan_ipv6_network(interface):
    print("\n[Scanner] Scanning IPv6 network...")
    ipv6_request = ICMPv6ND_NS()

    try:
        answered_list = srp(
            Ether(dst="33:33:00:00:00:01") / IPv6(dst="ff02::1") / ipv6_request,
            iface=interface,
            timeout=3,
            verbose=False,
        )[0]
    except Exception as e:
        print(f"[ERROR] Scapy failed to scan IPv6: {e}")
        return []

    active_ips = set()
    devices = []
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for _, received in answered_list:
        if received.haslayer(ICMPv6ND_NA):
            ipv6_address = received[IPv6].src
            mac_address = received.src
            active_ips.add(ipv6_address)
            devices.append({"ip": ipv6_address, "mac": mac_address})
            print(f"[Scanner] ✅ Found IPv6 Device → IP: {ipv6_address}, MAC: {mac_address}")
            cursor.execute(
                "INSERT OR REPLACE INTO devices (ip, mac, timestamp, status) VALUES (?, ?, datetime('now'), 'Online')",
                (ipv6_address, mac_address),
            )

    cursor.execute("SELECT ip FROM devices WHERE ip LIKE '%:%'")
    known_ips = {row[0] for row in cursor.fetchall()}
    offline_ips = known_ips - active_ips

    for ip in offline_ips:
        print(f"[Scanner] ❌ Marked IPv6 device as Offline → IP: {ip}")
        cursor.execute(
            "UPDATE devices SET status='Offline', timestamp=datetime('now') WHERE ip=?",
            (ip,),
        )

    conn.commit()
    conn.close()
    return devices

def scan_network():
    interface = get_valid_interface()
    if not interface:
        print("[Scanner] ❌ No valid interface available. Exiting scan.")
        return []

    ipv4_devices = scan_ipv4_network(interface)
    ipv6_devices = scan_ipv6_network(interface)
    return ipv4_devices + ipv6_devices