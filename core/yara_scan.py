import os
from datetime import datetime

try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

def compile_rules(rules_path):
    if not YARA_AVAILABLE or not os.path.exists(rules_path):
        return None
    try:
        return yara.compile(rules_path)
    except Exception:
        return None

def scan_paths(paths, rules_path="rules.yar"):
    hits = []
    if not YARA_AVAILABLE:
        return hits
    rules = compile_rules(rules_path)
    if not rules:
        return hits
    for root in paths:
        if not os.path.exists(root):
            continue
        for dirpath, dirs, files in os.walk(root):
            for fn in files:
                p = os.path.join(dirpath, fn)
                try:
                    matches = rules.match(p)
                    if matches:
                        hits.append({"file": p, "matches": [str(m) for m in matches], "timestamp": datetime.utcnow().isoformat()+"Z"})
                except Exception:
                    continue
    return hits
