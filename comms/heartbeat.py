import socket
import time
from datetime import datetime
import psutil
import platform

def build_heartbeat(agent_id: str):
    boot_time = psutil.boot_time()
    uptime_seconds = int(time.time() - boot_time)
    return {
        "agent_id": agent_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "uptime_seconds": uptime_seconds,
        "cpu_percent": psutil.cpu_percent(interval=1),
        "mem_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent,  # root partition usage
        "load_avg": psutil.getloadavg() if hasattr(psutil, "getloadavg") else None,
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "arch": platform.machine()
    }
