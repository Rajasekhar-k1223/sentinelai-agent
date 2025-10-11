# import os
# from datetime import datetime
# from core.utils import sha256_file, read_json, write_json

# def _collect_files(paths):
#     files = []
#     for root in paths:
#         if not os.path.exists(root):
#             continue
#         for dirpath, dirs, filenames in os.walk(root):
#             for fn in filenames:
#                 p = os.path.join(dirpath, fn)
#                 files.append(p)
#     return files

# def ensure_baseline(paths=None, baseline_file=None):
#     if baseline_file is None:
#         baseline_file = ".fim_baseline.json"
#     if paths is None:
#         from config import WATCH_PATHS
#         paths = WATCH_PATHS

#     baseline = read_json(baseline_file) or {}
#     if baseline:
#         return baseline
#     # create baseline
#     baseline = {}
#     files = _collect_files(paths)
#     for p in files:
#         try:
#             baseline[p] = {"hash": sha256_file(p), "mtime": os.path.getmtime(p)}
#         except Exception:
#             continue
#     write_json(baseline_file, baseline)
#     return baseline

# def scan_and_find_changes(paths=None, baseline_file=None):
#     if baseline_file is None:
#         baseline_file = ".fim_baseline.json"
#     if paths is None:
#         from config import WATCH_PATHS
#         paths = WATCH_PATHS

#     baseline = read_json(baseline_file) or {}
#     new_baseline = baseline.copy()
#     events = []
#     files = _collect_files(paths)
#     current_set = set(files)
#     # check creations/changes
#     for p in files:
#         try:
#             h = sha256_file(p)
#             mtime = os.path.getmtime(p)
#         except Exception:
#             continue
#         old = baseline.get(p)
#         if not old:
#             events.append({"path": p, "action": "created", "hash": h, "mtime": mtime, "timestamp": datetime.utcnow().isoformat()})
#         else:
#             if old.get("hash") != h:
#                 events.append({"path": p, "action": "modified", "hash_before": old.get("hash"), "hash_after": h, "mtime": mtime, "timestamp": datetime.utcnow().isoformat()})
#         new_baseline[p] = {"hash": h, "mtime": mtime}
#     # deletions
#     for p in list(baseline.keys()):
#         if p not in current_set:
#             events.append({"path": p, "action": "deleted", "previous_hash": baseline[p].get("hash"), "timestamp": datetime.utcnow().isoformat()})
#             new_baseline.pop(p, None)
#     write_json(baseline_file, new_baseline)
#     return events

# import os
# import time
# import requests
# from datetime import datetime
# from core.utils import sha256_file  # assuming this is already implemented
# import config

# API_BASE = config.SERVER_URL.rstrip("/")  # e.g. "https://sentinel.example.com/api"
# BASELINE_ENDPOINT = f"{API_BASE}/fim/baseline"
# EVENTS_ENDPOINT = f"{API_BASE}/fim/events"

# def collect_files(paths):
#     """Collects files from specified directories recursively"""
#     files = []
#     for root in paths:
#         if not os.path.exists(root):
#             continue
#         for dirpath, dirs, filenames in os.walk(root):
#             for fn in filenames:
#                 files.append(os.path.join(dirpath, fn))
#     return files

# def build_baseline(paths):
#     """Build baseline data for file integrity monitoring"""
#     baseline = {}
#     for p in collect_files(paths):
#         try:
#             baseline[p] = {"hash": sha256_file(p), "mtime": os.path.getmtime(p)}
#         except Exception:
#             continue
#     return baseline

# def post_baseline(agent_id, hostname, paths):
#     """Send the baseline data to the backend API"""
#     baseline = build_baseline(paths)
#     payload = {
#         "agent_id": agent_id,
#         "hostname": hostname,
#         "generated_at": datetime.utcnow().isoformat(),
#         "files": baseline
#     }
#     try:
#         # res = requests.post(BASELINE_ENDPOINT, json=payload, timeout=20)
#         # res.raise_for_status()  # Will raise an exception if status code is not 2xx
#         # return res.json()
#         return payload
#     except requests.exceptions.RequestException as e:
#         print(f"Error posting baseline: {e}")
#         return None

# def detect_and_send_changes(agent_id, hostname, last_baseline, paths):
#     """
#     Detect file changes (create, modify, delete) and send them to the backend.
#     """
#     new_baseline = {}
#     changes = []

#     for p in collect_files(paths):
#         try:
#             h = sha256_file(p)
#             mtime = os.path.getmtime(p)
#         except Exception:
#             continue

#         old = last_baseline.get(p) if last_baseline else None
#         if not old:
#             # File created
#             changes.append({
#                 "file_path": p,
#                 "change_type": "created",
#                 "hash_after": h,
#                 "mtime": mtime,
#                 "timestamp": datetime.utcnow().isoformat()
#             })
#         elif old.get("hash") != h:
#             # File modified
#             changes.append({
#                 "file_path": p,
#                 "change_type": "modified",
#                 "hash_before": old.get("hash"),
#                 "hash_after": h,
#                 "mtime": mtime,
#                 "timestamp": datetime.utcnow().isoformat()
#             })
#         new_baseline[p] = {"hash": h, "mtime": mtime}

#     # Detect file deletions
#     if last_baseline:
#         for p in list(last_baseline.keys()):
#             if p not in new_baseline:
#                 changes.append({
#                     "file_path": p,
#                     "change_type": "deleted",
#                     "hash_before": last_baseline[p].get("hash"),
#                     "timestamp": datetime.utcnow().isoformat()
#                 })

#     # Send changes to the backend API if there are any
#     if changes:
#         payload = {
#             "agent_id": agent_id,
#             "hostname": hostname,
#             "timestamp": datetime.utcnow().isoformat(),
#             "changes": changes
#         }
#         try:
#             # resp = requests.post(EVENTS_ENDPOINT, json=payload, timeout=20)
#             # resp.raise_for_status()  # Will raise an exception if status code is not 2xx
#             # return new_baseline, len(changes)
#             return new_baseline, len(changes), payload  # For testing without actual API call
#         except requests.exceptions.RequestException as e:
#             print(f"Error sending events: {e}")
#             return new_baseline, 0

#     return new_baseline, 0

import os
import time
import threading
from datetime import datetime
from core.utils import sha256_file
import config


def collect_files(paths):
    """Collects files from specified directories recursively"""
    files = []
    for root in paths:
        if not os.path.exists(root):
            continue
        for dirpath, dirs, filenames in os.walk(root):
            for fn in filenames:
                files.append(os.path.join(dirpath, fn))
    return files


def build_baseline(paths):
    """Build baseline data for file integrity monitoring"""
    baseline = {}
    for p in collect_files(paths):
        try:
            baseline[p] = {"hash": sha256_file(p), "mtime": os.path.getmtime(p)}
        except Exception as e:
            print(f"Error reading file {p}: {e}")
            continue
    return baseline


def scan_and_find_changes(paths, last_baseline):
    """
    Detect file changes (create, modify, delete).
    Returns: (new_baseline, events_list)
    """
    new_baseline = {}
    events = []

    for p in collect_files(paths):
        try:
            h = sha256_file(p)
            mtime = os.path.getmtime(p)
        except Exception as e:
            print(f"Error reading file {p}: {e}")
            continue

        old = last_baseline.get(p) if last_baseline else None
        if not old:
            # File created
            events.append({
                "file_path": p,
                "change_type": "created",
                "hash_after": h,
                "mtime": mtime,
                "timestamp": datetime.utcnow().isoformat()
            })
        elif old.get("hash") != h:
            # File modified
            events.append({
                "file_path": p,
                "change_type": "modified",
                "hash_before": old.get("hash"),
                "hash_after": h,
                "mtime": mtime,
                "timestamp": datetime.utcnow().isoformat()
            })
        new_baseline[p] = {"hash": h, "mtime": mtime}

    # Detect file deletions
    if last_baseline:
        for p in list(last_baseline.keys()):
            if p not in new_baseline:
                events.append({
                    "file_path": p,
                    "change_type": "deleted",
                    "hash_before": last_baseline[p].get("hash"),
                    "timestamp": datetime.utcnow().isoformat()
                })

    return new_baseline, events


# def fim_loop(agent_id, hostname, callback=None):
#     """Loop for monitoring file integrity"""
#     print("Starting FIM loop with paths:", config.WATCH_PATHS)

#     last_baseline = build_baseline(config.WATCH_PATHS)
#     baseline_payload = {
#         "agent_id": agent_id,
#         "hostname": hostname,
#         "generated_at": datetime.utcnow().isoformat(),
#         "files": last_baseline
#     }

#     # Send baseline once
#     if callback:
#         callback("baseline", baseline_payload)

#     while True:
#         try:
#             new_baseline, events = scan_and_find_changes(config.WATCH_PATHS, last_baseline)

#             if events:
#                 changes_payload = {
#                     "agent_id": agent_id,
#                     "hostname": hostname,
#                     "timestamp": datetime.utcnow().isoformat(),
#                     "changes": events
#                 }
#                 if callback:
#                     callback("changes", changes_payload)

#             last_baseline = new_baseline

#         except Exception as e:
#             print(f"fim_loop error: {e}")

#         time.sleep(config.FIM_SCAN_INTERVAL)


# def start_fim(agent_id, hostname, callback=None):
#     """Start FIM in a separate thread"""
#     fim_thread = threading.Thread(target=fim_loop, args=(agent_id, hostname, callback), daemon=True)
#     fim_thread.start()
