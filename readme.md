# Virtual IoT Honeypot

**Design and Implementation of a Virtual IoT Honeypot for Network Threat Analysis**

A lightweight Virtual IoT Honeypot that simulates a Telnet-based IoT device, captures attacker interactions, and provides an interactive Streamlit dashboard for analysis.

---

## Features
- Async Telnet honeypot server that logs sessions (one JSON object per line).
- Structured session logs with timestamps, source IP/port, and send/receive events.
- Interactive Streamlit dashboard to visualize sessions, top attacker IPs, and full transcripts.
- Simple replay tool to print or re-send recorded client events.
- Optional log merger to combine multiple session files into a single `all_sessions.jsonl`.

---
## Quick Start (Linux/macOS)

### 1. Create project folder
bash
mkdir -p ~/virtual-iot-honeypot
cd ~/virtual-iot-honeypot
### 2. Create & activate virtual environment
python3 -m venv .venv
source venv/bin/activate
python -m pip install --upgrade pip
### 3. Install Dependencies
pip install -r requirements.txt
### 4. Ensure log folder exist
mkdir -p logs
### 5. Run the Honeypot server
python3 telnet_honeypot.py --host 0.0.0.0 --port 2323
### 6. Open the Streamlit dashboard
streamlit run dashboard.py 
### 7. Test using Telent
telnet 127.0.0.1 2323
# try: /system identity, /system resource print, /interface print, /user print, ls, cat /etc/passwd
