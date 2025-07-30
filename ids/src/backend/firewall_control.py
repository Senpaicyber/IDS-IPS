import subprocess
import platform

def block_ip_firewall(ip):
    """Block the IP using system firewall."""
    if platform.system() == "Windows":
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=IDS_Block_{ip}",
                "dir=in", "action=block", f"remoteip={ip}", "enable=yes"
            ], check=True)
            print(f"[Firewall] 🔒 Blocked IP {ip} via Windows Firewall.")
        except subprocess.CalledProcessError as e:
            print(f"[Firewall ERROR] Could not block {ip}: {e}")
    elif platform.system() == "Linux":
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"[Firewall] 🔒 Blocked IP {ip} via iptables.")
        except subprocess.CalledProcessError as e:
            print(f"[Firewall ERROR] Could not block {ip}: {e}")

def unblock_ip_firewall(ip):
    """Unblock the IP from system firewall."""
    if platform.system() == "Windows":
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=IDS_Block_{ip}"
            ], check=True)
            print(f"[Firewall] ✅ Unblocked IP {ip}.")
        except subprocess.CalledProcessError as e:
            print(f"[Firewall ERROR] Could not unblock {ip}: {e}")
    elif platform.system() == "Linux":
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"[Firewall] ✅ Unblocked IP {ip}.")
        except subprocess.CalledProcessError as e:
            print(f"[Firewall ERROR] Could not unblock {ip}: {e}")
