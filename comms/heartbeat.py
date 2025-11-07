import socket
import time
from datetime import datetime
import psutil
import platform


def build_heartbeat(agent_id: str):
    """
    Collect comprehensive system metrics across Windows, Linux, and macOS.
    Returns a heartbeat dictionary for storage or transmission.
    """
    boot_time = psutil.boot_time()
    uptime_seconds = int(time.time() - boot_time)

    heartbeat = {
        "agent_id": agent_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "online",
        "hostname": socket.gethostname(),
        "ip_address": get_ip_address(),
        "os": platform.system(),
        "os_version": platform.version(),
        "arch": platform.machine(),
        "uptime_seconds": uptime_seconds,
        "cpu_percent": psutil.cpu_percent(interval=1),
        "mem_percent": psutil.virtual_memory().percent,
    }

    # Load Average (Unix only)
    heartbeat["load_avg"] = psutil.getloadavg() if hasattr(psutil, "getloadavg") else None

    # Disk Metrics
    heartbeat["disks"] = get_disk_info()
    heartbeat["disk_percent"] = get_disk_activity_percent()

    # Network Metrics
    network_data = get_network_info()
    heartbeat["network_percent"] = network_data["total_usage_percent"]
    heartbeat["network_interfaces"] = network_data["interfaces"]

    # Logged-in users
    heartbeat["users"] = get_logged_in_users()

    return heartbeat


# ---------------------- Helper Functions ---------------------- #

def get_ip_address():
    """Return the system's primary IPv4 address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_disk_info():
    """Return usage info for all mounted partitions."""
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "percent": usage.percent,
                "total_gb": round(usage.total / (1024 ** 3), 2),
                "used_gb": round(usage.used / (1024 ** 3), 2),
                "free_gb": round(usage.free / (1024 ** 3), 2)
            })
        except PermissionError:
            continue
    return disks


def get_disk_activity_percent(sample_time=1.0):
    """
    Estimate disk I/O usage percentage.
    Dynamically computes bytes read/written per second.
    """
    try:
        io_start = psutil.disk_io_counters()
        time.sleep(sample_time)
        io_end = psutil.disk_io_counters()

        read_bytes = io_end.read_bytes - io_start.read_bytes
        write_bytes = io_end.write_bytes - io_start.write_bytes
        total_bytes = read_bytes + write_bytes

        # Assume 200 MB/s = 100% utilization
        max_throughput = 200 * 1024 * 1024
        usage_percent = min(100, (total_bytes / max_throughput) * 100)
        return round(usage_percent, 2)
    except Exception:
        return 0.0


def get_network_info(sample_time=1.0):
    """
    Measure network usage % for all interfaces.
    Uses NIC speed if available, else assumes 100 Mbps.
    Returns total usage % and per-interface details.
    """
    try:
        net_start = psutil.net_io_counters(pernic=True)
        time.sleep(sample_time)
        net_end = psutil.net_io_counters(pernic=True)

        interfaces = {}
        total_usage = 0
        iface_count = 0

        for iface, end_stats in net_end.items():
            start_stats = net_start.get(iface)
            if not start_stats:
                continue

            sent = end_stats.bytes_sent - start_stats.bytes_sent
            recv = end_stats.bytes_recv - start_stats.bytes_recv
            total_bytes = sent + recv

            iface_stats = psutil.net_if_stats().get(iface)
            if iface_stats and iface_stats.speed > 0:
                max_bytes_per_sec = iface_stats.speed * 125000
            else:
                max_bytes_per_sec = 100 * 125000  # assume 100 Mbps

            usage_percent = min(100, (total_bytes / max_bytes_per_sec) * 100)
            usage_percent = round(usage_percent, 2)

            interfaces[iface] = {
                "sent_bytes": sent,
                "recv_bytes": recv,
                "usage_percent": usage_percent,
                "speed_mbps": iface_stats.speed if iface_stats else 100
            }

            total_usage += usage_percent
            iface_count += 1

        avg_usage = round(total_usage / iface_count, 2) if iface_count else 0

        return {
            "total_usage_percent": avg_usage,
            "interfaces": interfaces
        }

    except Exception:
        return {"total_usage_percent": 0.0, "interfaces": {}}


def get_logged_in_users():
    """Return list of logged-in users."""
    users = []
    try:
        for u in psutil.users():
            users.append({
                "name": u.name,
                "terminal": u.terminal,
                "host": u.host,
                "started": datetime.utcfromtimestamp(u.started).isoformat() + "Z"
            })
    except Exception:
        pass
    return users
