# import os
# from datetime import datetime

# try:
#     import yara
#     YARA_AVAILABLE = True
# except Exception:
#     YARA_AVAILABLE = False

# def compile_rules(rules_path):
#     if not YARA_AVAILABLE or not os.path.exists(rules_path):
#         return None
#     try:
#         return yara.compile(rules_path)
#     except Exception:
#         return None

# def scan_paths(paths, rules_path="rules.yar"):
#     hits = []
#     if not YARA_AVAILABLE:
#         return hits
#     rules = compile_rules(rules_path)
#     if not rules:
#         return hits
#     for root in paths:
#         if not os.path.exists(root):
#             continue
#         for dirpath, dirs, files in os.walk(root):
#             for fn in files:
#                 p = os.path.join(dirpath, fn)
#                 try:
#                     matches = rules.match(p)
#                     if matches:
#                         hits.append({"file": p, "matches": [str(m) for m in matches], "timestamp": datetime.utcnow().isoformat()+"Z"})
#                 except Exception:
#                     continue
#     return hits

# import os
# import time
# import yara
# import logging
# from datetime import datetime
# from comms import api_client

# SCAN_PATHS = [
#     "C:\\Windows\\System32",
#     "C:\\Users\\Public",
#     "C:\\Program Files",
#     "C:\\ProgramData"
# ]

# logger = logging.getLogger("YARA")

# class YaraScanner:
#     def __init__(self, agent_id, hostname):
#         self.agent_id = agent_id
#         self.hostname = hostname
#         self.rules_cache_path = "rules_cache.yar"
#         self.compiled_rules = None

#     def fetch_rules_from_server(self):
#         """Download rules from the backend"""
#         try:
#             rules = api_client.get("/api/yara/rules")
#             if not rules:
#                 logger.info("[YARA] No rules found on server.")
#                 return False

#             with open(self.rules_cache_path, "w") as f:
#                 for r in rules:
#                     if r.get("rule_preview"):
#                         f.write(r["rule_preview"] + "\n\n")

#             logger.info(f"[YARA] Downloaded {len(rules)} rules from backend.")
#             return True
#         except Exception as e:
#             logger.error(f"[YARA] Failed to fetch rules: {e}")
#             return False

#     def load_rules(self):
#         """Load YARA rules into memory"""
#         if not os.path.exists(self.rules_cache_path):
#             logger.warning("[YARA] No cached rules found. Fetching from backend...")
#             if not self.fetch_rules_from_server():
#                 return False

#         try:
#             self.compiled_rules = yara.compile(filepath=self.rules_cache_path)
#             logger.info("[YARA] Rules loaded successfully.")
#             return True
#         except Exception as e:
#             logger.error(f"[YARA] Error compiling rules: {e}")
#             return False

#     def scan_path(self, path):
#         """Scan files in the given path"""
#         matches_found = []

#         for root, dirs, files in os.walk(path):
#             for file in files:
#                 filepath = os.path.join(root, file)
#                 try:
#                     matches = self.compiled_rules.match(filepath)
#                     if matches:
#                         match_data = {
#                             "agent_id": self.agent_id,
#                             "hostname": self.hostname,
#                             "filepath": filepath,
#                             "matches": [m.rule for m in matches],
#                             "timestamp": datetime.utcnow().isoformat()
#                         }
#                         matches_found.append(match_data)
#                         logger.warning(f"[YARA] Match found: {filepath} -> {match_data['matches']}")
#                         api_client.post("/api/yara/scan", match_data)
#                 except Exception as e:
#                     logger.debug(f"[YARA] Skipping {filepath}: {e}")

#         return matches_found

#     def run(self):
#         """Full YARA scan workflow"""
#         if not self.load_rules():
#             return

#         total_matches = []
#         for path in SCAN_PATHS:
#             if os.path.exists(path):
#                 logger.info(f"[YARA] Scanning {path} ...")
#                 total_matches.extend(self.scan_path(path))

#         logger.info(f"[YARA] Completed scan. Total matches: {len(total_matches)}")
#         return total_matches


import os
import time
import yara
import platform
import traceback
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from config import WATCH_PATHS, AGENT_ID
from comms import api_client


def fetch_yara_rules():
    """Fetch active YARA rules from backend"""
    try:
        response = api_client._get("yara/rules")
        if response and isinstance(response, list):
            rules = [r["rule_text"] for r in response if r.get("enabled", True)]
            return rules
        else:
            print("[YARA] No rules received from backend.")
            return []
    except Exception as e:
        print(f"[YARA] Failed to fetch rules: {e}")
        return []


def compile_rules(rules):
    """Compile YARA rules safely"""
    try:
        rule_source = "\n".join(rules)
        return yara.compile(source=rule_source)
    except Exception as e:
        print(f"[YARA] Error compiling rules: {e}")
        return None


def scan_file(filepath, compiled_rules):
    """Scan a single file with compiled YARA rules"""
    try:
        matches = compiled_rules.match(filepath)
        if matches:
            return [m.rule for m in matches]
    except Exception as e:
        if "Permission denied" not in str(e):
            print(f"[YARA] Error scanning {filepath}: {e}")
    return []


def scan_paths():
    """Main scan function that iterates over all WATCH_PATHS"""
    print(f"[YARA] Starting scan on {platform.system()} paths: {WATCH_PATHS}")

    yara_rules = fetch_yara_rules()
    if not yara_rules:
        print("[YARA] No rules to scan.")
        return

    compiled_rules = compile_rules(yara_rules)
    if not compiled_rules:
        print("[YARA] No compiled rules available.")
        return

    scan_results = []

    for base_path in WATCH_PATHS:
        if not os.path.exists(base_path):
            continue

        for root, dirs, files in os.walk(base_path):
            for file in files:
                file_path = os.path.join(root, file)
                matches = scan_file(file_path, compiled_rules)
                if matches:
                    result = {
                        "filepath": file_path,
                        "matches": matches,
                        "hostname": platform.node(),
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    scan_results.append(result)

    if scan_results:
        print(f"[YARA] Found {len(scan_results)} matches. Sending results...")
        try:
            api_client.post_yara_results(AGENT_ID, scan_results)
        except Exception as e:
            print(f"[YARA] Error sending results: {e}")
    else:
        print("[YARA] No matches found.")


def run_yara_monitor(interval=600):
    """Run YARA scan periodically"""
    print(f"[YARA] Monitoring started (interval: {interval}s)")
    executor = ThreadPoolExecutor(max_workers=1)
    while True:
        executor.submit(scan_paths)
        time.sleep(interval)


if __name__ == "__main__":
    run_yara_monitor(interval=300)
