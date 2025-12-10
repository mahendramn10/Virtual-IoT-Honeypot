#!/usr/bin/env python3
# replay.py - replay a telnet/http session transcript for demo
import argparse
import json
import time
import glob
import os
from datetime import datetime

def find_newest_session():
    files = sorted(glob.glob("logs/session_*.jsonl"), key=os.path.getmtime, reverse=True)
    return files[0] if files else None

def load_session(path):
    with open(path, "r") as f:
        # each file contains a single JSON object line
        data = json.load(f)
    return data

def pretty_print_meta(sess):
    print("="*60)
    print(f"TIME   : {sess.get('time')}")
    print(f"SRC IP : {sess.get('src_ip')}")
    print(f"SERVICE: {sess.get('service')}   PATH: {sess.get('path')}   METHOD: {sess.get('method')}")
    print("="*60)

def replay_transcript(sess, speed=1.0, keep_timestamps=False):
    # transcript expected as list of {"ts":..., "dir":"in"/"out", "text":...}
    transcript = sess.get("data", {}).get("transcript") or sess.get("transcript") or []
    if not transcript:
        print("No transcript found in session.")
        return

    # If timestamps exist and keep_timestamps True, use their intervals; otherwise use fixed delay
    if keep_timestamps and all("ts" in t for t in transcript):
        # compute time differences in seconds
        times = [datetime.fromisoformat(t["ts"].replace("Z","")) for t in transcript]
        # normalize to start at 0
        base = times[0]
        intervals = [(t - base).total_seconds() for t in times]
        last = 0.0
        for interval, entry in zip(intervals, transcript):
            wait = max(0.0, (interval - last) / speed)
            time.sleep(wait)
            last = interval
            dir_ = entry.get("dir","?")
            text = entry.get("text","")
            prefix = "IN: " if dir_.lower().startswith("in") else "OUT"
            print(f"{prefix} {text}")
    else:
        # simple fixed-delay replay
        for entry in transcript:
            dir_ = entry.get("dir","?")
            text = entry.get("text","")
            prefix = "IN:  " if dir_.lower().startswith("in") else "OUT: "
            print(f"{prefix}{text}")
            # small pause for readability; scale with speed
            time.sleep(max(0.05, 0.5 / float(speed)))

def main():
    p = argparse.ArgumentParser(description="Replay a honeypot session transcript (JSONL).")
    p.add_argument("session_file", nargs="?", help="Path to session JSONL file (default: newest in logs/)")
    p.add_argument("--speed", type=float, default=1.0, help="Playback speed multiplier (default 1.0). >1 = faster")
    p.add_argument("--timestamps", action="store_true", help="Respect recorded timestamps (if available)")
    args = p.parse_args()

    session_file = args.session_file
    if not session_file:
        session_file = find_newest_session()
        if not session_file:
            print("No session files found in logs/. Run the server/simulator first.")
            return

    if not os.path.isfile(session_file):
        print(f"Session file not found: {session_file}")
        return

    sess = load_session(session_file)
    pretty_print_meta(sess)
    print(f"Replaying transcript from {session_file}  (speed={args.speed})\n")
    replay_transcript(sess, speed=args.speed, keep_timestamps=args.timestamps)
    print("\n--- End of session ---")

if __name__ == "__main__":
    main()
