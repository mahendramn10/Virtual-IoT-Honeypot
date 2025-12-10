import json
import os
import datetime
import random
import time

BASE_DIR = os.path.dirname(__file__)
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "all_sessions.jsonl")

services = ["virtual-iot-telnet", "virtual-http", "virtual-ssh"]
usernames = ["root", "admin", "guest", "pi", "user"]
passwords = ["1234", "admin", "toor", "raspberry", "password", "iot123"]
commands = ["ls", "cat /etc/passwd", "uname -a", "reboot", "print data", "wget exploit.sh"]

def generate_virtual_entry():
    service = random.choice(services)
    username = random.choice(usernames)
    password = random.choice(passwords)
    src_ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"

    # Simulate a fake transcript for Telnet/SSH sessions
    transcript = []
    now = datetime.datetime.utcnow()
    for cmd in random.sample(commands, random.randint(2, 4)):
        now += datetime.timedelta(seconds=random.randint(1, 3))
        transcript.append({
            "ts": now.isoformat() + "Z",
            "dir": "in",
            "text": cmd
        })
        transcript.append({
            "ts": (now + datetime.timedelta(milliseconds=200)).isoformat() + "Z",
            "dir": "out",
            "text": f"sh: {cmd}: command not found\\r\\n"
        })

    data = {
        "session_start": datetime.datetime.utcnow().isoformat() + "Z",
        "username": username,
        "transcript": transcript
    }

    entry = {
        "time": datetime.datetime.utcnow().isoformat() + "Z",
        "src_ip": src_ip,
        "service": service,
        "path": f"/{service}",
        "method": "SESSION",
        "data": data
    }

    return entry

def append_entry(entry):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

if __name__ == "__main__":
    print("Simulating virtual honeypot sessions... (Press Ctrl+C to stop)")
    while True:
        entry = generate_virtual_entry()
        append_entry(entry)
        print(f"[+] Added log for {entry['src_ip']} on {entry['service']}")
        time.sleep(random.randint(2, 5))
