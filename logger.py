import json
import os
import datetime

BASE_DIR = os.path.dirname(__file__)
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# 👇 All logs go here
LOG_FILE = os.path.join(LOG_DIR, "all_sessions.jsonl")

def log_request(src_ip, service, path, method, data):
    """Append a single JSON log line to one shared file."""
    entry = {
        "time": datetime.datetime.utcnow().isoformat() + "Z",
        "src_ip": src_ip,
        "service": service,
        "path": path,
        "method": method,
        "data": data
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return LOG_FILE
