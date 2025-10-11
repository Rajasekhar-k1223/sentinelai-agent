import psutil
import threading
import time
import platform
import json
from datetime import datetime

try:
    import pynvml
    pynvml.nvmlInit()
    GPU_AVAILABLE = True
except Exception:
    GPU_AVAILABLE = False


def collect(agent_id: str):
    """
    Collect detailed system telemetry including CPU, memory, disk, GPU, top processes, I/O, network.
    """
    try:
        # CPU & Memory
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = dict(psutil.virtual_memory()._asdict())

        # Disk usage & I/O
        disk_usage = {}
        disk_io = {}
        for p in psutil.disk_partitions()[:4]:
            try:
                usage = psutil.disk_usage(p.mountpoint)
                disk_usage[p.mountpoint] = {
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent
                }
                io_counters = psutil.disk_io_counters(perdisk=True)
                disk_io[p.device] = dict(io_counters.get(p.device, {})._asdict()) if io_counters else {}
            except Exception:
                continue
          #Power info
        battery = psutil.sensors_battery()
        battery_percentage = battery.percent if battery else None
        power_plugged = battery.power_plugged if battery else None

        # Simple health logic
        if battery_percentage is None:
            battery_health = "Unknown"
        elif battery_percentage > 80:
            battery_health = "Good"
        elif battery_percentage > 30:
            battery_health = "Fair"
        else:
            battery_health = "Poor"       
        # Network connections & I/O
        net_connections = []
        for conn in psutil.net_connections(kind="inet")[:50]:
            net_connections.append({
                "fd": conn.fd,
                "family": str(conn.family),
                "type": str(conn.type),
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status
            })
        net_io = dict(psutil.net_io_counters(pernic=True))

        # Top processes by memory
        top_processes = []
        for p in sorted(psutil.process_iter(attrs=["pid", "name", "memory_info", "username", "cmdline"]),
                        key=lambda x: x.info.get("memory_info").rss if x.info.get("memory_info") else 0,
                        reverse=True)[:10]:
            info = p.info
            top_processes.append({
                "pid": info.get("pid"),
                "name": info.get("name"),
                "memory_rss": info.get("memory_info").rss if info.get("memory_info") else None,
                "username": info.get("username"),
                "cmdline": info.get("cmdline")
            })

        # GPU metrics
        gpus = []
        if GPU_AVAILABLE:
            for i in range(pynvml.nvmlDeviceGetCount()):
                handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                gpus.append({
                    "name": pynvml.nvmlDeviceGetName(handle).decode(),
                    "memory_total": pynvml.nvmlDeviceGetMemoryInfo(handle).total,
                    "memory_used": pynvml.nvmlDeviceGetMemoryInfo(handle).used,
                    "utilization": pynvml.nvmlDeviceGetUtilizationRates(handle).gpu
                })

        payload = {
            "agent_id": agent_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "cpu_percent": cpu_percent,
            "memory": memory,
            "disk_usage": disk_usage,
            "disk_io": disk_io,
            "network_connections": net_connections,
            "network_io": net_io,
            "top_processes": top_processes,
            "gpus": gpus,
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "arch": platform.machine(),
            "battery": {
                "percentage": battery_percentage,
                "power_plugged": power_plugged,
                "health": battery_health
            }
        }

        return payload

    except Exception as e:
        return {"agent_id": agent_id, "timestamp": datetime.utcnow().isoformat() + "Z", "error": str(e)}
