import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import sqlite3
from config.settings import DB_PATH


class NetworkCharts:
    def __init__(self, parent):
        self.parent = parent
        self.fig, self.ax = plt.subplots(figsize=(8, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.parent)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def update_packet_protocol_chart(self):
        """Update the chart showing packet distribution by protocol."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            self.ax.clear()

            # Fetch protocol distribution data
            cursor.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol")
            results = cursor.fetchall()

            if results:
                protocols, counts = zip(*results)
                self.ax.bar(protocols, counts)
                self.ax.set_title("Packet Distribution by Protocol")
                self.ax.set_xlabel("Protocol")
                self.ax.set_ylabel("Packet Count")
                self.canvas.draw()

            conn.close()
        except sqlite3.OperationalError as e:
            print(f"[Charts ERROR] Failed to update protocol chart: {e}")

    def update_alert_severity_chart(self):
        """Update the chart showing alert distribution by severity."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            self.ax.clear()

            # Fetch alert severity distribution data
            cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
            results = cursor.fetchall()

            if results:
                severities, counts = zip(*results)
                self.ax.pie(counts, labels=severities, autopct="%1.1f%%", startangle=90)
                self.ax.set_title("Alert Distribution by Severity")
                self.canvas.draw()

            conn.close()
        except sqlite3.OperationalError as e:
            print(f"[Charts ERROR] Failed to update severity chart: {e}")

    def update_device_status_chart(self):
        """Update the chart showing device status distribution."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            self.ax.clear()

            # Fetch device status distribution data
            cursor.execute("SELECT status, COUNT(*) FROM devices GROUP BY status")
            results = cursor.fetchall()

            if results:
                statuses, counts = zip(*results)
                self.ax.bar(statuses, counts)
                self.ax.set_title("Device Status Distribution")
                self.ax.set_xlabel("Status")
                self.ax.set_ylabel("Device Count")
                self.canvas.draw()

            conn.close()
        except sqlite3.OperationalError as e:
            print(f"[Charts ERROR] Failed to update device status chart: {e}")
