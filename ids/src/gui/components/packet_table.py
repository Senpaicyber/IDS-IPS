import tkinter as tk
from tkinter import ttk
import sqlite3
from config.settings import DB_PATH
from backend.utils import is_valid_ip, get_timestamp
import csv


class PacketTable(ttk.Treeview):
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
            cursor.execute(
                "SELECT timestamp, src_ip, dst_ip, protocol FROM packets ORDER BY id DESC LIMIT 10"
            )
            for row in cursor.fetchall():
                self.insert("", "end", values=row)
            conn.close()
        except sqlite3.OperationalError as e:
            print(f"[PacketTable ERROR] Failed to populate table: {e}")

    def add_packet(self, src_ip: str, dst_ip: str, protocol: str):
        """Add a new packet to the table and database."""
        if not is_valid_ip(src_ip) or not is_valid_ip(dst_ip):
            print("[PacketTable ERROR] Invalid source or destination IP address.")
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol) VALUES (?, ?, ?, ?)",
                (get_timestamp(), src_ip, dst_ip, protocol),
            )
            conn.commit()
            conn.close()
            self.populate_table()
        except sqlite3.OperationalError as e:
            print(f"[PacketTable ERROR] Failed to add packet: {e}")

    def filter_packets(self, filter_text: str):
        """Filter packets based on source IP, destination IP, or protocol."""
        self.delete(*self.get_children())
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT timestamp, src_ip, dst_ip, protocol FROM packets WHERE src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ? ORDER BY id DESC LIMIT 10",
                (f"%{filter_text}%", f"%{filter_text}%", f"%{filter_text}%"),
            )
            for row in cursor.fetchall():
                self.insert("", "end", values=row)
            conn.close()
        except sqlite3.OperationalError as e:
            print(f"[PacketTable ERROR] Failed to filter packets: {e}")

    def export_to_csv(self, filename: str = "packets.csv"):
        """Export the packet data to a CSV file."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM packets")
            with open(filename, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(
                    ["Timestamp", "Source IP", "Destination IP", "Protocol"]
                )
                writer.writerows(cursor.fetchall())
            conn.close()
            print(f"[PacketTable] Exported data to {filename}")
        except (sqlite3.OperationalError, IOError) as e:
            print(f"[PacketTable ERROR] Failed to export data: {e}")
