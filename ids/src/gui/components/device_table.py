import tkinter as tk
from tkinter import ttk
import sqlite3
from config.settings import DB_PATH
from backend.utils import is_valid_ip, is_valid_mac, get_timestamp


class DeviceTable(ttk.Treeview):
    def __init__(self, parent, columns, *args, **kwargs):
        super().__init__(parent, columns=columns, show="headings", *args, **kwargs)
        self.columns = columns
        self.parent = parent
        self.setup_columns()
        self.populate_table()

    def setup_columns(self):
        """Configure the columns and headings."""
        for col in self.columns:
            self.heading(col, text=col)
            self.column(col, anchor="center", width=120)

    def populate_table(self):
        """Populate the table with data from the database."""
        self.delete(*self.get_children())
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT ip, mac, timestamp, status FROM devices")
            for row in cursor.fetchall():
                self.insert("", "end", values=row)
            conn.close()
        except sqlite3.OperationalError as e:
            print(f"[DeviceTable ERROR] Failed to populate table: {e}")

    def add_device(self, ip: str, mac: str):
        """Add a new device to the table and database."""
        if not is_valid_ip(ip) or not is_valid_mac(mac):
            print("[DeviceTable ERROR] Invalid IP or MAC address.")
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO devices (ip, mac, timestamp, status) VALUES (?, ?, ?, ?)",
                (ip, mac, get_timestamp(), "active"),
            )
            conn.commit()
            conn.close()
            self.populate_table()
        except sqlite3.OperationalError as e:
            print(f"[DeviceTable ERROR] Failed to add device: {e}")

    def update_device_status(self, ip: str, status: str):
        """Update the status of a device in the table and database."""
        if not is_valid_ip(ip):
            print("[DeviceTable ERROR] Invalid IP address.")
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("UPDATE devices SET status = ? WHERE ip = ?", (status, ip))
            conn.commit()
            conn.close()
            self.populate_table()
        except sqlite3.OperationalError as e:
            print(f"[DeviceTable ERROR] Failed to update device status: {e}")

    def delete_device(self, ip: str):
        """Delete a device from the table and database."""
        if not is_valid_ip(ip):
            print("[DeviceTable ERROR] Invalid IP address.")
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM devices WHERE ip = ?", (ip,))
            conn.commit()
            conn.close()
            self.populate_table()
        except sqlite3.OperationalError as e:
            print(f"[DeviceTable ERROR] Failed to delete device: {e}")

    def filter_devices(self, filter_text: str):
        """Filter devices based on IP, MAC, or status."""
        self.delete(*self.get_children())
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ip, mac, timestamp, status FROM devices WHERE ip LIKE ? OR mac LIKE ? OR status LIKE ?",
                (f"%{filter_text}%", f"%{filter_text}%", f"%{filter_text}%"),
            )
            for row in cursor.fetchall():
                self.insert("", "end", values=row)
            conn.close()
        except sqlite3.OperationalError as e:
            print(f"[DeviceTable ERROR] Failed to filter devices: {e}")
