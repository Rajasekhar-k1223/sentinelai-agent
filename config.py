import platform
import uuid
import hashlib
import os
# config.py - edit these values for your environment

# Server endpoints (no trailing slash)
SERVER_BASE = " https://baculiform-undilatorily-deb.ngrok-free.dev/api"

AGENT_ID_FILE = "agent_id.txt"


system = platform.system().lower()
print(system.lower())
if system.lower() == "windows":
    DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "SentinelAI")
elif system.lower() == "darwin":  # macOS
    # Use a user-writable folder
    DATA_DIR = os.path.expanduser("~/Library/Application Support/SentinelAI")
else:
    DATA_DIR = "/var/lib/sentinelai"

os.makedirs(DATA_DIR, exist_ok=True)



def generate_system_uuid():
    # Use machine details (CPU + Node + OS + MAC address)
    system_info = (
        platform.node() +
        platform.system() +
        platform.release() +
        str(uuid.getnode())  # MAC address
    )
    return hashlib.sha256(system_info.encode()).hexdigest()

def get_agent_id():
    # If file exists, read and return
    if os.path.exists(AGENT_ID_FILE):
        with open(AGENT_ID_FILE, "r") as f:
            return f.read().strip()
    # Otherwise generate, store, and return
    agent_id = generate_system_uuid()
    with open(AGENT_ID_FILE, "w") as f:
        f.write(agent_id)
    return agent_id
# Agent identity - leave AGENT_ID None to auto-register and persist
AGENT_ID = get_agent_id()
AGENT_NAME = platform.node()  # optional display name

# Authentication - if server requires token, you can set a static one here
AUTH_TOKEN = None  # e.g., "Bearer eyJ..."

# Intervals (seconds)
HEARTBEAT_INTERVAL = 60
TELEMETRY_INTERVAL = 30
FIM_SCAN_INTERVAL = 120
NETWORK_INTERVAL = 60

# # FIM watch paths (adjust for Windows or Mac)
# WATCH_PATHS = ["/etc", "/var/log"]  # on Windows use ["C:\\Windows", "C:\\Program Files"]

# # YARA
# YARA_SCAN_ON_START = False
# YARA_RULES_PATH = "rules.yar"

# # Local files
# FIM_BASELINE_FILE = ".fim_baseline.json"
# LOG_FILE = "logs/agent.log"

# # Retry/backoff
# RETRY_BACKOFF = 5
# REQUEST_TIMEOUT = 10

# YARA
YARA_SCAN_ON_START = True
YARA_RULES_PATH = "rules.yar"

# Local storage dir (per-user)
def get_agent_storage_dir():
    if os.name == "nt":
        base = os.getenv("APPDATA", os.path.expanduser("~"))
        d = os.path.join(base, "SentinelAI")
    else:
        d = os.path.join(os.path.expanduser("~"), ".sentinelai")
    os.makedirs(d, exist_ok=True)
    return d

AGENT_STORAGE_DIR = get_agent_storage_dir()
FIM_BASELINE_FILE = os.path.join(AGENT_STORAGE_DIR, ".fim_baseline.json")
AGENT_ID_FILE = os.path.join(AGENT_STORAGE_DIR, "agent_id.txt")
LOG_FILE = os.path.join(AGENT_STORAGE_DIR, "agent.log")

# Retry/backoff
RETRY_BACKOFF = 5
REQUEST_TIMEOUT = 10

# FIM watch paths per OS
def get_watch_paths():
    s = platform.system()
    print("os type:- ",s)
    if s == "Windows":
        # typical sensitive locations on Windows
        return [
            os.path.join(os.environ.get("SystemRoot", "C:\\Windows")),
            os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files")),
            os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")),
            os.path.join(os.path.expanduser("~"), "Documents")
        ]
    elif s == "Linux":
        return ["/etc", "/var/log", "/usr/bin", "/opt"]
    elif s == "Darwin":  # macOS
        return ["/etc", "/var/log", "/System/Library", "/Applications"]
    else:
        return [os.path.expanduser("~")]

WATCH_PATHS = get_watch_paths()

# paths where logs should be collected
LOG_PATHS = ["./logs", "/var/log"]

# interval in seconds to send logs to backend
LOGS_INTERVAL = 60