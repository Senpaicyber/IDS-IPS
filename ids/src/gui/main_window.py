import tkinter as tk
from tkinter import ttk
import sqlite3
import threading
import time
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import csv
from backend.database import init_db
from backend.scanner import scan_network
from config.settings import DB_PATH
from gui.components.alert_table import AlertTable


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network IDS Dashboard")
        self.geometry("1200x800")
        self.setup_ui()
        self.start_auto_refresh()

    def setup_ui(self):
        # Device List section
        self.device_frame = ttk.LabelFrame(self, text="Connected Devices")
        self.device_frame.pack(fill="x", padx=5, pady=5)
        self.device_columns = (
            "IP Address",
            "MAC Address",
            "Last Seen",
            "Status",
            "Actions",
        )
        self.device_table = ttk.Treeview(
            self.device_frame, columns=self.device_columns, show="headings"
        )
        for col in self.device_columns:
            self.device_table.heading(col, text=col)
        self.device_table.pack(fill="x", padx=5, pady=5)

        # Packet Log section
        self.packet_frame = ttk.LabelFrame(self, text="Recent Network Traffic")
        self.packet_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.packet_columns = ("Time", "Source IP", "Destination IP", "Protocol")
        self.packet_table = ttk.Treeview(
            self.packet_frame, columns=self.packet_columns, show="headings"
        )
        for col in self.packet_columns:
            self.packet_table.heading(col, text=col)
        self.packet_table.pack(fill="both", expand=True, padx=5, pady=5)

        # Security Events section
        self.event_frame = ttk.LabelFrame(self, text="Security Events")
        self.event_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.event_columns = ("Time", "Alert Type", "Severity", "Source IP", "Message")
        self.event_table = AlertTable(self.event_frame, columns=self.event_columns)
        self.event_table.pack(fill="both", expand=True, padx=5, pady=5)

        # Add refresh button
        self.refresh_button = ttk.Button(
            self.event_frame, text="Refresh", command=self.refresh_data
        )
        self.refresh_button.pack(side="right", padx=5, pady=5)

        # Event Details section
        self.details_frame = ttk.LabelFrame(self, text="Event Details")
        self.details_frame.pack(fill="x", padx=5, pady=5)
        self.details_text = tk.Text(self.details_frame, height=10)
        self.details_text.pack(fill="x", padx=5, pady=5)

        # Buttons
        self.btn_frame = tk.Frame(self)
        self.btn_frame.pack(fill="x", padx=5, pady=5)
        self.scan_button = tk.Button(
            self.btn_frame, text="Scan Network", command=self.scan_network
        )
        self.scan_button.pack(side="left", padx=5)

    def start_auto_refresh(self):
        # Schedule the first refresh after the main loop starts
        self.after(100, self._start_auto_refresh_thread)

    def _start_auto_refresh_thread(self):
        # Start the auto-refresh thread
        self.refresh_thread = threading.Thread(target=self.auto_refresh, daemon=True)
        self.refresh_thread.start()

    def auto_refresh(self):
        while True:
            # Use Tkinter's after method to schedule refresh in the main thread
            self.after(0, self.refresh_data)
            time.sleep(5)

    def refresh_data(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            # Clear current data
            for table in [self.device_table, self.packet_table, self.event_table]:
                for row in table.get_children():
                    table.delete(row)

            # Fetch and update devices
            cursor.execute("SELECT ip, mac, timestamp, status FROM devices")
            for ip, mac, ts, status in cursor.fetchall():
                self.device_table.insert("", "end", values=(ip, mac, ts, status, ""))

            # Fetch and update packets
            cursor.execute(
                "SELECT timestamp, src_ip, dst_ip, protocol FROM packets ORDER BY id DESC LIMIT 10"
            )
            for ts, src, dst, proto in cursor.fetchall():
                self.packet_table.insert("", "end", values=(ts, src, dst, proto))

            # Fetch and update security events
            cursor.execute(
                "SELECT timestamp, alert_type, severity, src_ip, message FROM alerts ORDER BY id DESC LIMIT 20"
            )
            for ts, alert_type, severity, src_ip, message in cursor.fetchall():
                self.event_table.insert(
                    "", "end", values=(ts, alert_type, severity, src_ip, message)
                )

            conn.close()
            print("[GUI] Data refreshed.")
        except sqlite3.OperationalError as e:
            print(f"[GUI ERROR] Database error: {e}")

    def scan_network(self):
        scan_network()
        self.refresh_data()
