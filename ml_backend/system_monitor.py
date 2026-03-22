import asyncio
import psutil
from datetime import datetime


def get_system_stats() -> dict:
    """Return current CPU and RAM usage snapshot."""
    cpu_percent = psutil.cpu_percent(interval=0.5)
    cpu_count = psutil.cpu_count(logical=True)
    memory = psutil.virtual_memory()

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "cpu": {
            "percent": cpu_percent,
            "cores": cpu_count,
        },
        "ram": {
            "total_gb": round(memory.total / (1024**3), 2),
            "used_gb": round(memory.used / (1024**3), 2),
            "available_gb": round(memory.available / (1024**3), 2),
            "percent": memory.percent,
        },
    }


async def stream_system_stats(ws, interval: float = 2.0):
    """Push live CPU/RAM stats over a WebSocket connection."""
    try:
        while True:
            stats = get_system_stats()
            await ws.send_json(stats)
            await asyncio.sleep(interval)
    except Exception:
        pass
