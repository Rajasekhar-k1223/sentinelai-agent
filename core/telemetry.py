import psutil
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
    Collect detailed system telemetry including CPU, memory, disk, GPU, top processes, I/O, and network.
    """
    try:
        # CPU & Memory
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = dict(psutil.virtual_memory()._asdict())

        # Disk usage & I/O
        disk_usage = {}
        disk_io = {}
        try:
            io_counters = psutil.disk_io_counters(perdisk=True) or {}
            for p in psutil.disk_partitions()[:4]:
                try:
                    usage = psutil.disk_usage(p.mountpoint)
                    disk_usage[p.mountpoint] = {
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent
                    }
                    if p.device in io_counters:
                        disk_io[p.device] = dict(io_counters[p.device]._asdict())
                except Exception:
                    continue
        except Exception:
            disk_usage, disk_io = {}, {}

        # Power / Battery info
        battery_percentage = None
        power_plugged = None
        battery_health = "Unknown"
        try:
            battery = psutil.sensors_battery()
            if battery:
                battery_percentage = battery.percent
                power_plugged = battery.power_plugged
                if battery_percentage > 80:
                    battery_health = "Good"
                elif battery_percentage > 30:
                    battery_health = "Fair"
                else:
                    battery_health = "Poor"
        except Exception:
            pass

        # Network connections (limit for safety)
        net_connections = []
        try:
            for conn in psutil.net_connections(kind="inet")[:50]:
                try:
                    net_connections.append({
                        "fd": getattr(conn, "fd", None),
                        "family": str(getattr(conn, "family", None)),
                        "type": str(getattr(conn, "type", None)),
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": getattr(conn, "status", None)
                    })
                except Exception:
                    continue
        except Exception:
            pass

        net_io = {}
        try:
            net_io_raw = psutil.net_io_counters(pernic=True)
            for k, v in net_io_raw.items():
                net_io[k] = dict(v._asdict())
        except Exception:
            pass

        # Top processes (safe)
        top_processes = []
        try:
            for p in psutil.process_iter(attrs=["pid", "name", "memory_info", "username", "cmdline"]):
                try:
                    info = p.info
                    top_processes.append({
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "memory_rss": info["memory_info"].rss if info.get("memory_info") else None,
                        "username": info.get("username"),
                        "cmdline": info.get("cmdline")
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            top_processes = sorted(top_processes, key=lambda x: x["memory_rss"] or 0, reverse=True)[:10]
        except Exception:
            pass

        # GPU metrics (if available)
        gpus = []
        if GPU_AVAILABLE:
            try:
                for i in range(pynvml.nvmlDeviceGetCount()):
                    handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                    gpus.append({
                        "name": pynvml.nvmlDeviceGetName(handle).decode(),
                        "memory_total": pynvml.nvmlDeviceGetMemoryInfo(handle).total,
                        "memory_used": pynvml.nvmlDeviceGetMemoryInfo(handle).used,
                        "utilization": pynvml.nvmlDeviceGetUtilizationRates(handle).gpu
                    })
            except Exception:
                pass

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

        # print(json.dumps(payload, indent=2))
        return payload

    except Exception as e:
        return {
            "agent_id": agent_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "error": str(e)
        }
