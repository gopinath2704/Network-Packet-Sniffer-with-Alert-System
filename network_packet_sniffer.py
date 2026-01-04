"""
Network Packet Sniffer with Alert System (Single File Version)

Features:
- Packet capture using Scapy
- Port scan & flooding detection
- SQLite logging
- Console + file alerts
- Optional Tkinter GUI
"""

import time
import threading
import sqlite3
from datetime import datetime
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP
import tkinter as tk

# ==========================
# DATABASE CONFIG
# ==========================

DB_NAME = "traffic.db"

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
# ALERT SYSTEM
# ==========================

LOG_FILE = "alerts.log"

def send_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_msg = f"[{timestamp}] ALERT: {message}"
    print(alert_msg)

    with open(LOG_FILE, "a") as f:
        f.write(alert_msg + "\n")

# ==========================
# ANOMALY DETECTION
# ==========================

PORT_SCAN_THRESHOLD = 20
FLOOD_THRESHOLD = 100
TIME_WINDOW = 10  # seconds

port_scan_tracker = defaultdict(set)
packet_counter = defaultdict(list)

def detect_port_scan(src_ip, dst_port):
    port_scan_tracker[src_ip].add(dst_port)

    if len(port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
        send_alert(f"Port scan detected from {src_ip}")
        port_scan_tracker[src_ip].clear()

def detect_flood(src_ip):
    now = time.time()
    packet_counter[src_ip].append(now)

    packet_counter[src_ip] = [
        t for t in packet_counter[src_ip]
        if now - t <= TIME_WINDOW
    ]

    if len(packet_counter[src_ip]) > FLOOD_THRESHOLD:
        send_alert(f"Possible flooding attack from {src_ip}")
        packet_counter[src_ip].clear()

# ==========================
# PACKET SNIFFING
# ==========================

def process_packet(packet):
    if IP not in packet:
        return

    ip = packet[IP]
    protocol = "OTHER"
    src_port = dst_port = flags = None

    if TCP in packet:
        protocol = "TCP"
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = str(tcp.flags)

        detect_port_scan(ip.src, dst_port)
        detect_flood(ip.src)

    elif UDP in packet:
        protocol = "UDP"
        udp = packet[UDP]
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

    print(f"{protocol} | {ip.src}:{src_port} → {ip.dst}:{dst_port}")

def start_sniffing():
    init_db()
    print("🔍 Sniffing started... Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)

# ==========================
# GUI IMPLEMENTATION
# ==========================

def start_sniffer_thread():
    threading.Thread(target=start_sniffing, daemon=True).start()
    status_label.config(text="Status: Sniffing...")

def start_gui():
    global status_label

    app = tk.Tk()
    app.title("Network Packet Sniffer")
    app.geometry("400x220")

    title = tk.Label(app, text="Network Packet Sniffer", font=("Arial", 14))
    title.pack(pady=15)

    start_btn = tk.Button(app, text="Start Sniffing", width=20, command=start_sniffer_thread)
    start_btn.pack(pady=10)

    status_label = tk.Label(app, text="Status: Idle")
    status_label.pack(pady=10)

    app.mainloop()

# ==========================
# ENTRY POINT
# ==========================

if __name__ == "__main__":
    print("1 → CLI Mode")
    print("2 → GUI Mode")

    choice = input("Select mode: ")

    if choice == "2":
        start_gui()
    else:
        start_sniffing()
