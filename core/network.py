import psutil
from datetime import datetime

def collect_netflows():
    flows = []
    try:
        for c in psutil.net_connections(kind='inet'):
            try:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            except Exception:
                laddr = str(c.laddr) if c.laddr else ""
                raddr = str(c.raddr) if c.raddr else ""
            flows.append({
                "pid": c.pid,
                "laddr": laddr,
                "raddr": raddr,
                "status": c.status,
                "type": getattr(c, "type", None),
                "timestamp": datetime.utcnow().isoformat()+"Z"
            })
    except Exception:
        pass
    return {"flows": flows}
