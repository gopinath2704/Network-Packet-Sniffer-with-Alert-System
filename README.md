# 🔍 Network Packet Sniffer with Intrusion Alert System

A Python-based **real-time packet sniffer and intrusion alert system** with a **Tkinter GUI dashboard**.  
This tool detects **suspicious incoming traffic such as port scans or repeated connection attempts** and raises alerts with severity levels:

- 🟢 NORMAL
- 🟡 LOW
- 🟠 HIGH
- 🔴 CRITICAL (with red flashing alert)

It also supports **Dark Mode UI** and can be converted to a Windows `.exe`.

> ✅ The system is designed to **ignore your own device traffic**, but still detect:
> - Attackers on the same Wi-Fi / LAN
> - Attackers from the internet

So scanning **your own PC from WSL or localhost will NOT trigger alerts**, but scanning from another device **WILL**.

---

## ✨ Features

✔ Real-time packet sniffing using Scapy  
✔ Suspicious activity detection (port scans, repeated hits, SYN flood patterns etc.)  
✔ Severity-based alerts:
- LOW 🟡
- HIGH 🟠
- CRITICAL 🔴 (red flashing & sound alert)

✔ Tkinter GUI dashboard  
✔ Dark Mode theme  
✔ Ignore local system traffic (no false alerts while browsing)  
✔ Detects LAN & Internet attackers  
✔ Convert to `.exe` for Windows

---

## 🛡 Local Traffic Ignore Logic (IMPORTANT)

The tool **ignores only your own system IP & loopback traffic**, not the entire LAN.

So:

| Source | Alert Triggered? |
|--------|------------------|
| Your PC / Localhost | ❌ No |
| WSL Kali Scan | ❌ No |
| Another device on same Wi-Fi | ✅ YES |
| Public IP attacker | ✅ YES |

This keeps the alerts **useful, accurate, and not noisy** 👍

---

## 🧰 Requirements

Install Python 3.10+ and run:

    pip install scapy
    pip install tkintertable

On Linux, you may need root permissions
On Windows, run the script in Admin mode

## ▶️ How to Run
python sniffing.py


The GUI will open and packets begin processing automatically.

🧪 Testing the Alert System
🔹 Test 1 — Local scan from SAME PC (Expected: No Alert)

From WSL / same machine:

nmap 127.0.0.1


or

nmap <your_local_IP>


✔ This should NOT trigger alerts

🔹 Test 2 — Scan from another device on SAME Wi-Fi (Expected: Alert)

From another phone / laptop:

nmap -sS <your_IP>


✔ This WILL trigger alerts

Severity depends on intensity.

🔹 Test 3 — Internet-based scan (Expected: Alert)

From a VPS etc:

nmap -Pn <your_public_IP>


⚠ Your router firewall may block this, meaning your PC won’t receive packets.
If packets reach your PC, the alert will fire.

## 🎨 GUI Features

Dark UI theme

Real-time logs

Color severity tags

CRITICAL alerts flash red

Optional sound alert

## 📦 Convert to .EXE (Windows)

Install PyInstaller:

pip install pyinstaller


Build:

pyinstaller --onefile --windowed sniffing.py


The EXE will appear in the dist folder.

## ⚠️ Legal & Ethical Notice

This tool is for:

  * Learning

  * Lab use

  * Monitoring your OWN network

Do NOT use on networks you do not own or have permission to test.

## 🛠 Future Improvements

 * Log export support

 * Pcap recording

 * Machine-learning attack detection

 * Email / Telegram alerts

## 🙌 Credits

Built using:

  * Python

  * Scapy

  * Tkinter
