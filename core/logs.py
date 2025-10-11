# core/logs.py
import os
import glob
import platform
import logging
import time
import subprocess
from datetime import datetime
from typing import List, Dict

try:
    import win32evtlog  # Windows Event Logs (requires pywin32)
except ImportError:
    win32evtlog = None

log = logging.getLogger("sentinel-agent-logs")


def collect_logs(agent_id: str, max_lines: int = 1000) -> List[Dict]:
    """
    Collect system logs across multiple OS.
    Returns a list of log documents with agent_id attached.
    """
    system = platform.system().lower()
    collected = []

    if system == "windows" and win32evtlog:
        collected.extend(_collect_windows_event_logs(agent_id, max_lines))
    elif system == "linux":
        collected.extend(_collect_linux_logs(agent_id, max_lines))
    elif system == "darwin":
        collected.extend(_collect_macos_logs(agent_id, max_lines))
    else:
        log.warning(f"Unsupported OS for log collection: {system}")

    return collected


def _collect_windows_event_logs(agent_id: str, max_lines: int) -> List[Dict]:
    """
    Collect logs from Windows Event Viewer and return structured entries
    """
    collected = []
    log_types = ["System", "Application", "Security"]
    server = "localhost"

    for log_type in log_types:
        try:
            hand = win32evtlog.OpenEventLog(server, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)

            if events:
                entries = []
                for ev in events[:max_lines]:
                    ev_time = datetime.fromtimestamp(time.mktime(ev.TimeGenerated.timetuple()))
                    if ev.EventType == win32evtlog.EVENTLOG_ERROR_TYPE:
                        level = "ERROR"
                    elif ev.EventType == win32evtlog.EVENTLOG_WARNING_TYPE:
                        level = "WARNING"
                    else:
                        level = "INFO"
                    message = f"{ev.SourceName} - {ev.EventID} - {ev.StringInserts}"
                    entries.append({"time": ev_time.isoformat(), "level": level, "message": message})

                collected.append({
                    "agent_id": agent_id,
                    "log_type": log_type,
                    "entries": entries,
                    "hostname": platform.node(),
                    "timestamp": int(time.time())
                })
                return collected
        except Exception:
            log.exception(f"Failed to collect Windows logs from {log_type}")

    return collected


def _collect_linux_logs(agent_id: str, max_lines: int) -> List[Dict]:
    """
    Collect logs from /var/log on Linux and journalctl
    """
    collected = []
    log_files = glob.glob("/var/log/*.log") + glob.glob("/var/log/*/*.log")

    for file_path in log_files:
        try:
            with open(file_path, "r", errors="ignore") as f:
                lines = f.readlines()[-max_lines:]
                entries = [{"time": datetime.utcnow().isoformat(), "level": "INFO", "message": line.strip()} for line in lines]

                collected.append({
                    "agent_id": agent_id,
                    "file": file_path,
                    "log_type": "file",
                    "entries": entries,
                    "hostname": platform.node(),
                    "timestamp": int(time.time())
                })
        except Exception:
            log.exception(f"Failed to read Linux log file: {file_path}")

    # journalctl (systemd logs)
    try:
        result = subprocess.run(
            ["journalctl", "-n", str(max_lines), "--no-pager", "--output", "short-iso"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.stdout:
            entries = [{"time": datetime.utcnow().isoformat(), "level": "INFO", "message": line} for line in result.stdout.splitlines()]
            collected.append({
                "agent_id": agent_id,
                "log_type": "journalctl",
                "entries": entries,
                "hostname": platform.node(),
                "timestamp": int(time.time())
            })
    except FileNotFoundError:
        log.info("journalctl not found (non-systemd system?)")
    except Exception:
        log.exception("Failed to collect journalctl logs")

    return collected


def _collect_macos_logs(agent_id: str, max_lines: int) -> List[Dict]:
    """
    Collect logs from macOS system logs and unified log
    """
    collected = []
    log_files = glob.glob("/var/log/*.log")

    for file_path in log_files:
        try:
            with open(file_path, "r", errors="ignore") as f:
                lines = f.readlines()[-max_lines:]
                entries = [{"time": datetime.utcnow().isoformat(), "level": "INFO", "message": line.strip()} for line in lines]

                collected.append({
                    "agent_id": agent_id,
                    "file": file_path,
                    "log_type": "file",
                    "entries": entries,
                    "hostname": platform.node(),
                    "timestamp": int(time.time())
                })
        except Exception:
            log.exception(f"Failed to read macOS log file: {file_path}")

    # unified logging (requires 'log show')
    try:
        result = subprocess.run(
            ["log", "show", "--style", "syslog", "--last", "1h"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.stdout:
            lines = result.stdout.splitlines()[-max_lines:]
            entries = [{"time": datetime.utcnow().isoformat(), "level": "INFO", "message": line} for line in lines]
            collected.append({
                "agent_id": agent_id,
                "log_type": "macos_unified",
                "entries": entries,
                "hostname": platform.node(),
                "timestamp": int(time.time())
            })
    except FileNotFoundError:
        log.info("'log show' command not found on macOS")
    except Exception:
        log.exception("Failed to collect macOS unified logs")

    return collected
