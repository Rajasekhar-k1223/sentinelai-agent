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

# import os
# import time
# import threading
# from datetime import datetime
# from core.utils import sha256_file
# import config


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
#         except Exception as e:
#             print(f"Error reading file {p}: {e}")
#             continue
#     return baseline


# def scan_and_find_changes(paths, last_baseline):
#     """
#     Detect file changes (create, modify, delete).
#     Returns: (new_baseline, events_list)
#     """
#     new_baseline = {}
#     events = []

#     for p in collect_files(paths):
#         try:
#             h = sha256_file(p)
#             mtime = os.path.getmtime(p)
#         except Exception as e:
#             print(f"Error reading file {p}: {e}")
#             continue

#         old = last_baseline.get(p) if last_baseline else None
#         if not old:
#             # File created
#             events.append({
#                 "file_path": p,
#                 "change_type": "created",
#                 "hash_after": h,
#                 "mtime": mtime,
#                 "timestamp": datetime.utcnow().isoformat()
#             })
#         elif old.get("hash") != h:
#             # File modified
#             events.append({
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
#                 events.append({
#                     "file_path": p,
#                     "change_type": "deleted",
#                     "hash_before": last_baseline[p].get("hash"),
#                     "timestamp": datetime.utcnow().isoformat()
#                 })

#     return new_baseline, events


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
# import os
# import time
# import json
# import threading
# from datetime import datetime
# from core.utils import sha256_file
# from config import FIM_BASELINE_FILE,FIM_SCAN_INTERVAL,DATA_DIR


# BASELINE_FILE = os.path.join(DATA_DIR, "fim_baseline.json")
# # SCAN_INTERVAL = getattr(config, "SCAN_INTERVAL", 30)  # Default: 30 seconds
# SCAN_INTERVAL = FIM_SCAN_INTERVAL

# def collect_files(paths):
#     """Recursively collect files from given directories."""
#     files = []
#     for root in paths:
#         if not os.path.exists(root):
#             continue
#         for dirpath, dirs, filenames in os.walk(root):
#             for fn in filenames:
#                 full_path = os.path.join(dirpath, fn)
#                 if os.path.isfile(full_path):
#                     files.append(full_path)
#     return files


# def build_baseline(paths):
#     """Generate baseline file metadata for the provided paths."""
#     baseline = {}
#     for file_path in collect_files(paths):
#         try:
#             baseline[file_path] = {
#                 "hash": sha256_file(file_path),
#                 "mtime": os.path.getmtime(file_path),
#             }
#         except Exception as e:
#             print(f"[FIM] Error reading {file_path}: {e}")
#             continue
#     return baseline


# def save_baseline(baseline):
#     """Save baseline data to JSON file."""
#     try:
#         os.makedirs(os.path.dirname(BASELINE_FILE), exist_ok=True)
#         with open(BASELINE_FILE, "w") as f:
#             json.dump(baseline, f, indent=2)
#         print(f"[FIM] Baseline saved: {BASELINE_FILE}")
#     except Exception as e:
#         print(f"[FIM] Error saving baseline: {e}")


# def load_baseline():
#     """Load existing baseline data if available."""
#     if not os.path.exists(BASELINE_FILE):
#         return {}
#     try:
#         with open(BASELINE_FILE, "r") as f:
#             return json.load(f)
#     except Exception as e:
#         print(f"[FIM] Error loading baseline: {e}")
#         return {}


# def ensure_baseline(paths):
#     """
#     Ensure baseline exists — if not, create it.
#     This function replaces the missing ensure_baseline() call.
#     """
#     print(BASELINE_FILE)
#     print(os.path.exists(BASELINE_FILE))
#     if not os.path.exists(BASELINE_FILE):
#         print("[FIM] No baseline found. Creating new baseline...")
#         baseline = build_baseline(paths)
#         save_baseline(baseline)
#         return baseline
#     else:
#         print("[FIM] Existing baseline found.")
#         return load_baseline()


# def scan_and_find_changes(paths, last_baseline):
#     """
#     Detect file changes (create, modify, delete).
#     Returns: (new_baseline, events_list)
#     """
#     new_baseline = {}
#     events = []

#     for file_path in collect_files(paths):
#         try:
#             file_hash = sha256_file(file_path)
#             mtime = os.path.getmtime(file_path)
#         except Exception as e:
#             print(f"[FIM] Error reading {file_path}: {e}")
#             continue

#         old = last_baseline.get(file_path)
#         if not old:
#             events.append({
#                 "file_path": file_path,
#                 "change_type": "created",
#                 "hash_after": file_hash,
#                 "mtime": mtime,
#                 "timestamp": datetime.utcnow().isoformat()
#             })
#         elif old.get("hash") != file_hash:
#             events.append({
#                 "file_path": file_path,
#                 "change_type": "modified",
#                 "hash_before": old.get("hash"),
#                 "hash_after": file_hash,
#                 "mtime": mtime,
#                 "timestamp": datetime.utcnow().isoformat()
#             })

#         new_baseline[file_path] = {"hash": file_hash, "mtime": mtime}

#     # Detect deletions
#     for old_path in list(last_baseline.keys()):
#         if old_path not in new_baseline:
#             events.append({
#                 "file_path": old_path,
#                 "change_type": "deleted",
#                 "hash_before": last_baseline[old_path].get("hash"),
#                 "timestamp": datetime.utcnow().isoformat()
#             })

#     return new_baseline, events

# import os
# import time
# import json
# from datetime import datetime
# from core.utils import sha256_file
# from comms import api_client
# from config import FIM_BASELINE_FILE, FIM_SCAN_INTERVAL, WATCH_PATHS, HOSTNAME

# def collect_files(paths):
#     files = []
#     for root in paths:
#         if not os.path.exists(root):
#             continue
#         for dirpath, _, filenames in os.walk(root):
#             for fn in filenames:
#                 try:
#                     full_path = os.path.join(dirpath, fn)
#                     if os.path.isfile(full_path):
#                         files.append(os.path.normpath(full_path))
#                 except Exception as e:
#                     print(f"[FIM] Error accessing file {fn}: {e}")
#     return files

# def build_baseline(paths):
#     baseline = {}
#     for file_path in collect_files(paths):
#         try:
#             baseline[file_path] = {
#                 "hash": sha256_file(file_path),
#                 "mtime": os.path.getmtime(file_path)
#             }
#         except Exception as e:
#             print(f"[FIM] Error hashing {file_path}: {e}")
#     return baseline

# def save_baseline(baseline):
#     os.makedirs(os.path.dirname(FIM_BASELINE_FILE), exist_ok=True)
#     with open(FIM_BASELINE_FILE, "w") as f:
#         json.dump(baseline, f, indent=2)
#     print(f"[FIM] Baseline saved to {FIM_BASELINE_FILE}")

# def load_baseline():
#     if not os.path.exists(FIM_BASELINE_FILE):
#         return {}
#     try:
#         with open(FIM_BASELINE_FILE, "r") as f:
#             return json.load(f)
#     except Exception as e:
#         print(f"[FIM] Error loading baseline: {e}")
#         return {}

# def ensure_baseline(agent_id, hostname, paths):
#     baseline = load_baseline()
#     if not baseline:
#         print("[FIM] Creating new baseline...")
#         baseline = build_baseline(paths)
#         save_baseline(baseline)
#         return baseline
#         # try:
#         #     api_client.post_fim_baseline(agent_id, hostname, baseline)
#         # except Exception as e:
#         #     print(f"[FIM] Baseline upload failed: {e}")
#     else:
#         print("[FIM] Existing baseline found.")
#     return baseline

# def scan_and_find_changes(agent_id, hostname, paths, last_baseline):
#     new_baseline = {}
#     events = []
#     for file_path in collect_files(paths):
#         try:
#             file_hash = sha256_file(file_path)
#             mtime = os.path.getmtime(file_path)
#         except Exception as e:
#             print(f"[FIM] Error reading {file_path}: {e}")
#             continue

#         old = last_baseline.get(file_path)
#         if not old:
#             events.append({
#                 "file_path": file_path,
#                 "change_type": "created",
#                 "hash_after": file_hash,
#                 "mtime": mtime,
#                 "timestamp": datetime.utcnow().isoformat()
#             })
#         elif old.get("hash") != file_hash:
#             events.append({
#                 "file_path": file_path,
#                 "change_type": "modified",
#                 "hash_before": old.get("hash"),
#                 "hash_after": file_hash,
#                 "mtime": mtime,
#                 "timestamp": datetime.utcnow().isoformat()
#             })

#         new_baseline[file_path] = {"hash": file_hash, "mtime": mtime}

#     for old_path in list(last_baseline.keys()):
#         if old_path not in new_baseline:
#             events.append({
#                 "file_path": old_path,
#                 "change_type": "deleted",
#                 "hash_before": last_baseline[old_path].get("hash"),
#                 "timestamp": datetime.utcnow().isoformat()
#             })

#     if events:
#         api_client.post_fim_events(agent_id, hostname, events)
#         save_baseline(new_baseline)

#     return new_baseline, events

# def fim_loop(agent_id, hostname):
#     print("Starting FIM loop...")
#     baseline = ensure_baseline(agent_id, hostname, WATCH_PATHS)
#     while True:
#         try:
#             baseline, events = scan_and_find_changes(agent_id, hostname, WATCH_PATHS, baseline)
#             if events:
#                 print(f"[FIM] Detected {len(events)} changes.")
#         except Exception as e:
#             print(f"[FIM] Error during scan: {e}")
#         time.sleep(FIM_SCAN_INTERVAL)
import os
import time
import json
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.utils import sha256_file
from comms import api_client
from config import FIM_BASELINE_FILE, FIM_SCAN_INTERVAL, WATCH_PATHS, HOSTNAME

# Thread-safe baseline
baseline_lock = threading.Lock()
baseline = {}

# ------------------- Baseline Utilities -------------------

def collect_files(paths):
    files = []
    for root in paths:
        if not os.path.exists(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                try:
                    full_path = os.path.join(dirpath, fn)
                    if os.path.isfile(full_path):
                        files.append(os.path.normpath(full_path))
                except Exception as e:
                    print(f"[FIM] Error accessing file {fn}: {e}")
    return files

def build_baseline(paths):
    base = {}
    for file_path in collect_files(paths):
        try:
            base[file_path] = {
                "hash": sha256_file(file_path),
                "mtime": os.path.getmtime(file_path)
            }
        except Exception as e:
            print(f"[FIM] Error hashing {file_path}: {e}")
    return base

def save_baseline():
    with baseline_lock:
        os.makedirs(os.path.dirname(FIM_BASELINE_FILE), exist_ok=True)
        with open(FIM_BASELINE_FILE, "w") as f:
            json.dump(baseline, f, indent=2)
    # print(f"[FIM] Baseline saved to {FIM_BASELINE_FILE}")

def load_baseline():
    if not os.path.exists(FIM_BASELINE_FILE):
        return {}
    try:
        with open(FIM_BASELINE_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[FIM] Error loading baseline: {e}")
        return {}

def ensure_baseline(agent_id, hostname, paths):
    global baseline
    baseline = load_baseline()
    if not baseline:
        print("[FIM] Creating new baseline...")
        baseline = build_baseline(paths)
        save_baseline()
    else:
        print("[FIM] Existing baseline found.")
    return baseline

# ------------------- Periodic Scan Loop -------------------

def scan_and_find_changes(agent_id, hostname):
    global baseline
    new_baseline = {}
    events = []

    with baseline_lock:
        last_baseline = baseline.copy()

    for file_path in collect_files(WATCH_PATHS):
        try:
            file_hash = sha256_file(file_path)
            mtime = os.path.getmtime(file_path)
        except Exception as e:
            print(f"[FIM] Error reading {file_path}: {e}")
            continue

        old = last_baseline.get(file_path)
        if not old:
            events.append({
                "file_path": file_path,
                "change_type": "created",
                "hash_after": file_hash,
                "mtime": mtime,
                "timestamp": datetime.utcnow().isoformat()
            })
        elif old.get("hash") != file_hash:
            events.append({
                "file_path": file_path,
                "change_type": "modified",
                "hash_before": old.get("hash"),
                "hash_after": file_hash,
                "mtime": mtime,
                "timestamp": datetime.utcnow().isoformat()
            })

        new_baseline[file_path] = {"hash": file_hash, "mtime": mtime}

    # Detect deleted files
    for old_path in last_baseline:
        if old_path not in new_baseline:
            events.append({
                "file_path": old_path,
                "change_type": "deleted",
                "hash_before": last_baseline[old_path].get("hash"),
                "timestamp": datetime.utcnow().isoformat()
            })

    if events:
        try:
            timestamp = datetime.utcnow().isoformat()
            api_client.post_fim_events(agent_id, hostname,timestamp, events)
            with baseline_lock:
                baseline.update(new_baseline)
            save_baseline()
            print(f"[FIM][Periodic] Detected {len(events)} changes.")
        except Exception as e:
            print(f"[FIM] Failed to post periodic events: {e}")

def fim_periodic_loop(agent_id, hostname):
    print("[FIM] Starting periodic FIM loop...")
    ensure_baseline(agent_id, hostname, WATCH_PATHS)
    while True:
        try:
            scan_and_find_changes(agent_id, hostname)
        except Exception as e:
            print(f"[FIM] Periodic scan error: {e}")
        time.sleep(FIM_SCAN_INTERVAL)

# ------------------- Watchdog Real-time Monitoring -------------------

class FIMHandler(FileSystemEventHandler):
    def __init__(self, agent_id, hostname):
        self.agent_id = agent_id
        self.hostname = hostname

    def process_event(self, event, change_type):
        if event.is_directory:
            return

        file_path = os.path.normpath(event.src_path)

        with baseline_lock:
            old_data = baseline.get(file_path)

        try:
            if change_type != "deleted":
                file_hash = sha256_file(file_path)
                mtime = os.path.getmtime(file_path)
                new_data = {"hash_after": file_hash, "mtime": mtime}
                with baseline_lock:
                    baseline[file_path] = new_data
            else:
                with baseline_lock:
                    baseline.pop(file_path, None)
                new_data = None

            fim_event = {
                "file_path": file_path,
                "change_type": change_type,
                "timestamp": datetime.utcnow().isoformat()
            }
            if change_type == "modified" and old_data:
                fim_event["hash_before"] = old_data.get("hash")
                fim_event["hash_after"] = new_data["hash_after"]
                fim_event["mtime"] = new_data["mtime"]
            elif change_type == "created":
                fim_event["hash_after"] = new_data["hash_after"]
                fim_event["mtime"] = new_data["mtime"]
            elif change_type == "deleted" and old_data:
                fim_event["hash_before"] = old_data.get("hash")
            timestamp = datetime.utcnow().isoformat()
            api_client.post_fim_events(self.agent_id, self.hostname,timestamp, [fim_event])
            save_baseline()
            print(f"[FIM][Watchdog] {change_type} detected: {file_path}")
        except Exception as e:
            print(f"[FIM] Failed to post {change_type} event: {e}")

    def on_created(self, event):
        self.process_event(event, "created")

    def on_modified(self, event):
        self.process_event(event, "modified")

    def on_deleted(self, event):
        self.process_event(event, "deleted")

def fim_watchdog_loop(agent_id, hostname):
    print("[FIM] Starting Watchdog FIM loop...")
    observer = Observer()
    handler = FIMHandler(agent_id, hostname)
    for path in WATCH_PATHS:
        if os.path.exists(path):
            observer.schedule(handler, path, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
