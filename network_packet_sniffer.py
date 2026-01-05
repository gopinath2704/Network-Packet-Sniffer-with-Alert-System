"""
Network Packet Sniffer with Alert System (Advanced Single File)

Features:
- Alert-only IDS mode
- Severity levels (LOW / HIGH / CRITICAL)
- SQLite logging
- GUI alert panel
- Alert sound
"""

import time
import threading
import sqlite3
from datetime import datetime
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP
import tkinter as tk
from tkinter import scrolledtext
import sys

# ==========================
# CONFIG
# ==========================

VERBOSE = False
DB_NAME = "traffic.db"
LOG_FILE = "alerts.log"

PORT_SCAN_THRESHOLD = 20
FLOOD_THRESHOLD = 100
TIME_WINDOW = 10  # seconds

# ==========================
# DATABASE
# ==========================

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            length INTEGER,
            flags TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_packet(data):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO packets
        (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, data)
    conn.commit()
    conn.close()

# ==========================
# ALERT SYSTEM (WITH SEVERITY)
# ==========================

alert_box = None  # GUI reference

def play_alert_sound():
    try:
        if sys.platform.startswith("win"):
            import winsound
            winsound.Beep(1000, 300)
        else:
            print("\a", end="")  # Unix beep
    except:
        pass

def send_alert(message, severity="LOW"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_msg = f"[{timestamp}] [{severity}] 🚨 {message}"

    # Terminal
    print(alert_msg)

    # File log
    with open(LOG_FILE, "a") as f:
        f.write(alert_msg + "\n")

    # GUI panel
    if alert_box:
        alert_box.insert(tk.END, alert_msg + "\n")
        alert_box.see(tk.END)

    # Sound for HIGH / CRITICAL
    if severity in ("HIGH", "CRITICAL"):
        play_alert_sound()

# ==========================
# ANOMALY DETECTION
# ==========================

port_scan_tracker = defaultdict(set)
packet_counter = defaultdict(list)

def detect_port_scan(src_ip, dst_port):
    port_scan_tracker[src_ip].add(dst_port)

    count = len(port_scan_tracker[src_ip])

    if count > PORT_SCAN_THRESHOLD:
        send_alert(
            f"Port scan detected from {src_ip} ({count} ports)",
            severity="HIGH"
        )
        port_scan_tracker[src_ip].clear()

def detect_flood(src_ip):
    now = time.time()
    packet_counter[src_ip].append(now)

    packet_counter[src_ip] = [
        t for t in packet_counter[src_ip]
        if now - t <= TIME_WINDOW
    ]

    count = len(packet_counter[src_ip])

    if count > FLOOD_THRESHOLD:
        send_alert(
            f"Flooding attack detected from {src_ip} ({count} packets)",
            severity="CRITICAL"
        )
        packet_counter[src_ip].clear()

# ==========================
# PACKET PROCESSING
# ==========================

def process_packet(packet):
    if IP not in packet:
        return

    ip = packet[IP]
    protocol = "OTHER"
    src_port = dst_port = flags = None

    if TCP in packet:
        tcp = packet[TCP]
        protocol = "TCP"
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = str(tcp.flags)

        detect_port_scan(ip.src, dst_port)
        detect_flood(ip.src)

    elif UDP in packet:
        udp = packet[UDP]
        protocol = "UDP"
        src_port = udp.sport
        dst_port = udp.dport
        detect_flood(ip.src)

    data = (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip.src,
        ip.dst,
        src_port,
        dst_port,
        protocol,
        len(packet),
        flags
    )

    insert_packet(data)

    if VERBOSE:
        print(f"{protocol} | {ip.src}:{src_port} → {ip.dst}:{dst_port}")

# ==========================
# SNIFFER
# ==========================

def start_sniffing():
    init_db()
    print("🔍 IDS running (Alert-only mode)")
    sniff(prn=process_packet, store=False)

# ==========================
# GUI WITH ALERT PANEL
# ==========================

def start_sniffer_thread():
    threading.Thread(target=start_sniffing, daemon=True).start()
    status_label.config(text="Status: Sniffing (IDS Active)")

def start_gui():
    global status_label, alert_box

    app = tk.Tk()
    app.title("Network Packet Sniffer IDS")
    app.geometry("700x400")

    tk.Label(app, text="Network Packet Sniffer IDS",
             font=("Arial", 15, "bold")).pack(pady=10)

    tk.Button(app, text="Start Sniffing",
              width=30, command=start_sniffer_thread).pack(pady=5)

    status_label = tk.Label(app, text="Status: Idle")
    status_label.pack(pady=5)

    tk.Label(app, text="🚨 Alert Panel",
             font=("Arial", 12)).pack(pady=5)

    alert_box = scrolledtext.ScrolledText(
        app, height=12, width=90, state="normal"
    )
    alert_box.pack(padx=10, pady=5)

    tk.Label(
        app,
        text="Severity: LOW (log only) | HIGH (sound) | CRITICAL (sound)",
        fg="gray"
    ).pack(pady=5)

    app.mainloop()

# ==========================
# ENTRY POINT
# ==========================

if __name__ == "__main__":
    print("1 → CLI (Alert-only)")
    print("2 → GUI (Alert Panel + Sound)")

    choice = input("Select mode: ")

    if choice == "2":
        start_gui()
    else:
        start_sniffing()
