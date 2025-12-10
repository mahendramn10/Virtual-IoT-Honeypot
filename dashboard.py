#!/usr/bin/env python3
"""
dashboard.py

Virtual IoT Honeypot Dashboard — interactive Streamlit app with nicer UI.
Run: streamlit run dashboard.py
"""
import streamlit as st
from pathlib import Path
import json
import pandas as pd
from datetime import datetime
import subprocess

# Page config
st.set_page_config(page_title="Virtual IoT Honeypot", layout="wide", initial_sidebar_state="expanded")

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

SERVICE_FIELD = "service"
DEFAULT_SERVICE_NAME = "virtual-iot-honeypot"

# --- Utilities ---------------------------------------------------------
def list_log_files(log_dir: Path):
    if not log_dir.exists():
        return []
    files = [p for p in log_dir.iterdir() if p.suffix in (".jsonl", ".json")]
    return sorted(files, key=lambda x: x.stat().st_mtime, reverse=True)

def load_jsonl(path: Path):
    sessions = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    sessions.append(json.loads(ln))
                except Exception:
                    # skip malformed lines
                    st.session_state.setdefault("_warnings", []).append(f"Skipped invalid JSON in {path.name}")
    except FileNotFoundError:
        st.error(f"File not found: {path}")
    return sessions

def extract_transcript(session):
    if not isinstance(session, dict):
        return ""
    # direct 'transcript'
    if "transcript" in session and session["transcript"]:
        return session["transcript"] if isinstance(session["transcript"], str) else json.dumps(session["transcript"], indent=2)
    # events array
    if "events" in session and isinstance(session["events"], list):
        lines = []
        for e in session["events"]:
            if isinstance(e, dict):
                t = e.get("time", "")
                d = e.get("dir", "")
                msg = e.get("data") or e.get("payload") or e.get("message") or ""
                # simple color hints: recv (client) vs send (server) with emojis
                prefix = "👤" if d == "recv" else "💻" if d == "send" else ""
                time_str = f"[{t}] " if t else ""
                lines.append(f"{time_str}{prefix} {msg.strip()}")
            else:
                lines.append(str(e))
        return "\n".join(lines).strip()
    # http-style: request.body
    if "request" in session and isinstance(session["request"], dict):
        req = session["request"]
        first = f"{req.get('method','')} {req.get('path','')}".strip()
        body = req.get("body")
        if body:
            return f"{first}\n\n{json.dumps(body, indent=2) if isinstance(body, (dict, list)) else str(body)}"
        return first
    # fallback: stringify known keys
    for key in ("payload", "body", "data"):
        if key in session and session[key]:
            val = session[key]
            return json.dumps(val, indent=2) if isinstance(val, (dict, list)) else str(val)
    # nothing found
    return ""

def readable_time(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "")).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts or "N/A"

# --- Sidebar -----------------------------------------------------------
st.sidebar.title("📊 Virtual IoT Honeypot")
files = list_log_files(LOG_DIR)
if not files:
    st.sidebar.warning("No log files found in /logs/. Create logs/ and run the honeypot to generate sessions.")
    st.stop()

selected_file = st.sidebar.selectbox("Select log file", [f.name for f in files])
log_path = LOG_DIR / selected_file

sessions = load_jsonl(log_path)
st.sidebar.metric("Sessions (lines)", len(sessions))

# show first-line diagnostic to help debug formats
with st.sidebar.expander("File diagnostic"):
    try:
        first_line = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except Exception as e:
        first_line = f"Could not read file: {e}"
    st.code(first_line[:1000] + ("..." if len(first_line) > 1000 else ""))

# quick df for charts
df = None
if sessions:
    try:
        df = pd.json_normalize(sessions)
    except Exception:
        df = None

if df is not None:
    if "src_ip" in df.columns:
        st.sidebar.subheader("🌍 Top Source IPs")
        st.sidebar.bar_chart(df["src_ip"].value_counts().head(8))
    if "service" in df.columns:
        st.sidebar.subheader("🔎 Services")
        st.sidebar.bar_chart(df["service"].value_counts().head(8))

st.sidebar.markdown("---")
if st.sidebar.button("Refresh view"):
    st.experimental_rerun()
st.sidebar.caption("Click Refresh after new sessions are written to disk.")

# --- Main layout -------------------------------------------------------
st.markdown("<h1 style='text-align:left'>Virtual IoT Honeypot Dashboard</h1>", unsafe_allow_html=True)
st.markdown("**A lightweight interactive dashboard for analyzing honeypot sessions.**")

if not sessions:
    st.info("This file contains no valid JSON session lines.")
    st.stop()

# session selector
session_options = [
    f"{i+1}. {s.get('src_ip','?')} | {s.get('service',DEFAULT_SERVICE_NAME)} | {s.get('time','')}"
    for i, s in enumerate(sessions)
]
sel_index = st.selectbox("Select session to view", range(len(sessions)), format_func=lambda i: session_options[i])

session = sessions[sel_index]

# top metadata row
st.subheader("Session Overview")
col1, col2, col3, col4 = st.columns([2,2,2,2])
col1.metric("Time", readable_time(session.get("time", "")))
col2.metric("Source IP", session.get("src_ip", "N/A"))
col3.metric("Service", session.get("service", DEFAULT_SERVICE_NAME))
col4.metric("Events", len(session.get("events", [])))

# JSON expander and nice transcript side-by-side
left, right = st.columns([1.8, 2.2])

with left:
    st.markdown("#### 🔍 Raw JSON")
    with st.expander("Open raw session JSON", expanded=False):
        st.json(session)

with right:
    st.markdown("#### 💬 Transcript")
    transcript = extract_transcript(session)
    if transcript:
        # nice monospaced transcript box
        st.code(transcript, language=None)
    else:
        st.info("No readable transcript found. Inspect raw JSON to locate payloads or HTTP body.")

# small insights section
st.markdown("---")
st.subheader("Quick Insights")
ins_cols = st.columns(3)
try:
    # top commands/triggers (naive)
    commands = []
    for s in sessions:
        if isinstance(s, dict) and "events" in s:
            for ev in s["events"]:
                if isinstance(ev, dict) and ev.get("dir") == "recv":
                    txt = ev.get("data","").strip()
                    if txt:
                        commands.append(txt.split()[0] if len(txt.split())>0 else txt)
    top_cmds = pd.Series(commands).value_counts().head(6) if commands else None
    if top_cmds is not None and not top_cmds.empty:
        ins_cols[0].markdown("**Top received tokens**")
        ins_cols[0].bar_chart(top_cmds)
    else:
        ins_cols[0].markdown("**Top received tokens**\n_No data yet_")
except Exception:
    ins_cols[0].markdown("**Top received tokens**\n_Error computing_")

# connections timeline preview
try:
    times = []
    for s in sessions:
        t = s.get("time")
        if t:
            try:
                times.append(pd.to_datetime(t))
            except Exception:
                pass
    if times:
        ts = pd.Series(1, index=pd.DatetimeIndex(times))
        ins_cols[1].markdown("**Connections over time**")
        ins_cols[1].line_chart(ts.resample("1T").sum().fillna(0))
    else:
        ins_cols[1].markdown("**Connections over time**\n_No data_")
except Exception:
    ins_cols[1].markdown("**Connections over time**\n_Error computing_")

ins_cols[2].markdown("**Session Details**")
ins_cols[2].write(f"Session ID: `{session.get('session_id','-')}`")
ins_cols[2].write(f"Src port: {session.get('src_port','-')}")

# Replay command area
st.markdown("---")
st.subheader("▶️ Replay / Shell Command")
default_cmd = "echo 'Virtual IoT Honeypot replay command not configured'"
cmd = st.text_input("Shell command (runs on server machine)", value=default_cmd)
if st.button("Run Command"):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
        out = (res.stdout or "") + ("\nSTDERR:\n" + res.stderr if res.stderr else "")
        st.text_area("Command output", value=out, height=220)
    except Exception as e:
        st.error(f"Failed to run command: {e}")

st.markdown("---")
st.caption("Tip: Click Refresh in the sidebar after the honeypot writes new sessions to disk.")
