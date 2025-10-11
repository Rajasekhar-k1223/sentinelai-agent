import hashlib
import json
import os
from datetime import datetime

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def write_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, default=str, indent=2)

def read_json(path):
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)
