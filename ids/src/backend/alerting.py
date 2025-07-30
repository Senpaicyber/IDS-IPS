import time
import sqlite3
import smtplib
from email.mime.text import MIMEText
import time
import traceback
from config.settings import (
    ALERT_RECIPIENT,
    DB_PATH,
    DEFAULT_ALERT_SEVERITY,
    EMAIL_PASSWORD,
    EMAIL_USER,
    SMTP_SERVER,
    SMTP_PORT
)


def log_alert(alert_type, message, severity=DEFAULT_ALERT_SEVERITY, src_ip="0.0.0.0"):
    """Log a security alert to the database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO alerts (timestamp, alert_type, severity, src_ip, message) VALUES (?, ?, ?, ?, ?)",
            (timestamp, alert_type, severity, src_ip, message),
        )
        conn.commit()
        conn.close()
        print(f"[ALERT] {alert_type}: {message}")
    except sqlite3.OperationalError as e:
        print(f"[ALERT ERROR] Failed to log alert: {e}")


def send_alert_email(subject, body):
    """Send an email alert with the given subject and body."""
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_USER
        msg["To"] = ALERT_RECIPIENT

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)  
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()

        print(f"[ALERT] Email sent: {subject}")
    except Exception as e:
        print(f"[ALERT] Failed to send email: {e}")
        traceback.print_exc()
