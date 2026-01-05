import threading
import time
import sqlite3
import os
from collections import defaultdict
from datetime import datetime
import socket

import tkinter as tk
from scapy.all import sniff, IP, TCP
import winsound


# ===================== CONFIG =====================
DB_NAME = "traffic.db"
ALERT_LOG = "alerts.log"

PORT_SCAN_THRESHOLD = 10     # unique ports within window
TIME_WINDOW = 5              # seconds
FLOOD_RATE = 40              # SYN packets per window
ALERT_COOLDOWN = 10          # seconds


# ===================== DARK MODE =====================
BG = "#121212"
FG = "#E0E0E0"
ALERT_BG = "#1E1E1E"

LOW_COLOR = "#4CAF50"
HIGH_COLOR = "#FF9800"
CRITICAL_COLOR = "#FF0000"


# ===================== GLOBALS =====================
connection_tracker = defaultdict(list)
packet_times = defaultdict(list)
last_alert_time = defaultdict(lambda: {"HIGH": 0, "CRITICAL": 0})

alert_box = None
flash_active = False


# ===================== FIND LOCAL HOST IP =====================
MY_IP = socket.gethostbyname(socket.gethostname())


def is_local(ip):
    """
    Ignore ONLY this PC — still detect other LAN devices.
    """
    if ip.startswith("127."):
        return True
    if ip == MY_IP:
        return True
    return False


# ===================== DB =====================
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            time TEXT,
            source_ip TEXT,
            message TEXT,
            severity TEXT
        )
    """)
    conn.commit()
    conn.close()


# ===================== ALERT HANDLING =====================
def log_alert(src_ip, msg, severity):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(ALERT_LOG, "a") as f:
        f.write(f"[{now}] {severity} | {src_ip} | {msg}\n")

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO alerts VALUES (?,?,?,?)",
              (now, src_ip, msg, severity))
    conn.commit()
    conn.close()

    send_alert(src_ip, msg, severity)


def play_alert_sound(severity):
    if severity in ("HIGH", "CRITICAL"):
        winsound.Beep(1200, 500)


def flash_critical():
    global flash_active
    flash_active = True

    def toggle():
        if not flash_active or not alert_box:
            alert_box.tag_config("CRITICAL", background=ALERT_BG)
            return

        current = alert_box.tag_cget("CRITICAL", "background")
        new = "#550000" if current == ALERT_BG else ALERT_BG
        alert_box.tag_config("CRITICAL", background=new)

        alert_box.after(300, toggle)

    toggle()


def send_alert(src_ip, msg, severity):
    play_alert_sound(severity)

    alert_msg = f"[{severity}] {src_ip} → {msg}\n"

    def gui_update():
        if not alert_box:
            return

        alert_box.insert(tk.END, alert_msg, severity)
        alert_box.see(tk.END)

        if severity == "CRITICAL":
            flash_critical()

    alert_box.after(0, gui_update)


# ===================== DETECTION =====================
def detect_port_scan(src_ip, dst_port):
    now = time.time()

    # Track packet timestamps (for flood detection)
    packet_times[src_ip].append(now)
    packet_times[src_ip] = [t for t in packet_times[src_ip]
                            if now - t <= TIME_WINDOW]

    # Track unique ports hit in time window
    connection_tracker[src_ip].append((dst_port, now))
    connection_tracker[src_ip] = [(p, t) for p, t in connection_tracker[src_ip]
                                  if now - t <= TIME_WINDOW]

    unique_ports = len(set(p for p, _ in connection_tracker[src_ip]))
    syn_rate = len(packet_times[src_ip])

    # -------- CRITICAL: PORT SCAN --------
    if unique_ports >= PORT_SCAN_THRESHOLD:
        if now - last_alert_time[src_ip]["CRITICAL"] >= ALERT_COOLDOWN:
            log_alert(src_ip,
                      f"Port scanning detected ({unique_ports} ports)",
                      "CRITICAL")
            last_alert_time[src_ip]["CRITICAL"] = now

        connection_tracker[src_ip].clear()
        packet_times[src_ip].clear()
        return

    # -------- HIGH: SYN FLOOD --------
    if syn_rate >= FLOOD_RATE:
        if now - last_alert_time[src_ip]["HIGH"] >= ALERT_COOLDOWN:
            log_alert(src_ip, "Suspicious SYN traffic flood", "HIGH")
            last_alert_time[src_ip]["HIGH"] = now


# ===================== PACKET SNIFFER =====================
def packet_handler(packet):
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return

    ip = packet[IP]
    tcp = packet[TCP]

    src_ip = ip.src

    # IGNORE ONLY LOCAL PC
    if is_local(src_ip):
        return

    # ONLY COUNT SYN WITHOUT ACK
    syn = tcp.flags & 0x02 != 0
    ack = tcp.flags & 0x10 != 0

    if not syn or ack:
        return

    dst_port = tcp.dport

    detect_port_scan(src_ip, dst_port)


def start_sniffer():
    sniff(filter="tcp", prn=packet_handler, store=False)


# ===================== GUI =====================
def start_gui():
    global alert_box, flash_active

    app = tk.Tk()
    app.title("Network Packet Sniffer with Alert System")
    app.geometry("900x550")
    app.configure(bg=BG)

    title = tk.Label(app, text="🚨 Intrusion Detection Alerts",
                     bg=BG, fg=FG, font=("Segoe UI", 18, "bold"))
    title.pack(pady=10)

    frame = tk.Frame(app, bg=ALERT_BG)
    frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    alert_box = tk.Text(frame, bg=ALERT_BG, fg=FG,
                        insertbackground=FG, font=("Consolas", 11),
                        borderwidth=0)
    alert_box.pack(fill=tk.BOTH, expand=True)

    alert_box.tag_config("LOW", foreground=LOW_COLOR)
    alert_box.tag_config("HIGH", foreground=HIGH_COLOR)
    alert_box.tag_config("CRITICAL",
                         foreground=CRITICAL_COLOR,
                         background=ALERT_BG)

    def on_close():
        global flash_active
        flash_active = False
        app.destroy()

    app.protocol("WM_DELETE_WINDOW", on_close)

    threading.Thread(target=start_sniffer, daemon=True).start()
    app.mainloop()


# ===================== MAIN =====================
if __name__ == "__main__":
    os.system("cls")
    print("[*] Starting Network Packet Sniffer with Alert System")
    print(f"Local IP ignored: {MY_IP}")
    init_db()
    start_gui()
