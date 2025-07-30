import tkinter as tk
from tkinter import ttk
import sqlite3
from config.settings import DB_PATH
from backend.utils import get_timestamp
import csv


class AlertTable(ttk.Treeview):
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
                "SELECT timestamp, alert_type, severity, src_ip, message FROM alerts ORDER BY id DESC LIMIT 20"
            )
            for row in cursor.fetchall():
                self.insert("", "end", values=row)
            conn.close()
        except sqlite3.OperationalError as e:
            print(f"[AlertTable ERROR] Failed to populate table: {e}")

    def add_alert(self, alert_type: str, severity: str, src_ip: str, message: str):
        """Add a new alert to the table and database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO alerts (timestamp, alert_type, severity, src_ip, message) VALUES (?, ?, ?, ?, ?)",
                (get_timestamp(), alert_type, severity, src_ip, message),
            )
            conn.commit()
            conn.close()
            self.populate_table()
        except sqlite3.OperationalError as e:
            print(f"[AlertTable ERROR] Failed to add alert: {e}")

    def filter_alerts(self, filter_text: str):
        """Filter alerts based on type, severity, source IP, or message."""
        self.delete(*self.get_children())
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT timestamp, alert_type, severity, src_ip, message FROM alerts WHERE alert_type LIKE ? OR severity LIKE ? OR src_ip LIKE ? OR message LIKE ? ORDER BY id DESC LIMIT 20",
                (
                    f"%{filter_text}%",
                    f"%{filter_text}%",
                    f"%{filter_text}%",
                    f"%{filter_text}%",
                ),
            )
            for row in cursor.fetchall():
                self.insert("", "end", values=row)
            conn.close()
        except sqlite3.OperationalError as e:
            print(f"[AlertTable ERROR] Failed to filter alerts: {e}")

    def export_to_csv(self, filename: str = "alerts.csv"):
        """Export the alert data to a CSV file."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts")
            with open(filename, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(
                    ["Timestamp", "Type", "Severity", "Source IP", "Message"]
                )
                writer.writerows(cursor.fetchall())
            conn.close()
            print(f"[AlertTable] Exported data to {filename}")
        except (sqlite3.OperationalError, IOError) as e:
            print(f"[AlertTable ERROR] Failed to export data: {e}")
