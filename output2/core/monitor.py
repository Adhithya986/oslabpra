"""Hardware telemetry and system metrics engine."""

import time
import platform
import datetime
import psutil
from typing import Dict, Any, List

class SystemMonitor:
    def __init__(self):
        self.last_disk_io = psutil.disk_io_counters()
        self.last_net_io = psutil.net_io_counters()
        self.last_time = time.time()

        # Prime psutil CPU calculations
        try:
            psutil.cpu_percent(interval=None)
            psutil.cpu_percent(percpu=True, interval=None)
        except Exception:
            pass

    def get_uptime_info(self) -> Dict[str, Any]:
        boot_timestamp = psutil.boot_time()
        uptime_seconds = int(time.time() - boot_timestamp)
        days, rem = divmod(uptime_seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)
        human_uptime = f"{days}d {hours}h {minutes}m {seconds}s" if days > 0 else f"{hours}h {minutes}m {seconds}s"
        return {
            "boot_time": datetime.datetime.fromtimestamp(boot_timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "uptime_seconds": uptime_seconds,
            "uptime_human": human_uptime
        }

    def get_system_static_info(self) -> Dict[str, Any]:
        uname = platform.uname()
        return {
            "os_name": uname.system,
            "os_release": uname.release,
            "os_version": uname.version,
            "machine": uname.machine,
            "processor": uname.processor or "Unknown CPU",
            "hostname": uname.node,
            "cpu_physical_cores": psutil.cpu_count(logical=False) or 1,
            "cpu_logical_cores": psutil.cpu_count(logical=True) or 1,
            **self.get_uptime_info()
        }

    def get_cpu_metrics(self) -> Dict[str, Any]:
        cpu_overall = psutil.cpu_percent(interval=None)
        cpu_per_core = psutil.cpu_percent(percpu=True, interval=None)
        try:
            freq = psutil.cpu_freq()
        except Exception:
            freq = None

        return {
            "overall_percent": round(cpu_overall, 1),
            "per_core_percent": [round(c, 1) for c in cpu_per_core],
            "core_count": len(cpu_per_core),
            "current_freq_mhz": round(freq.current, 1) if freq and freq.current else 0,
            "min_freq_mhz": round(freq.min, 1) if freq and freq.min else 0,
            "max_freq_mhz": round(freq.max, 1) if freq and freq.max else 0,
        }

    def get_memory_metrics(self) -> Dict[str, Any]:
        vmem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        return {
            "ram": {
                "total_bytes": vmem.total,
                "available_bytes": vmem.available,
                "used_bytes": vmem.used,
                "percent": round(vmem.percent, 1),
                "total_gb": round(vmem.total / (1024**3), 2),
                "used_gb": round(vmem.used / (1024**3), 2),
                "free_gb": round(vmem.available / (1024**3), 2),
            },
            "swap": {
                "total_bytes": swap.total,
                "used_bytes": swap.used,
                "free_bytes": swap.free,
                "percent": round(swap.percent, 1),
                "total_gb": round(swap.total / (1024**3), 2),
                "used_gb": round(swap.used / (1024**3), 2),
            }
        }

    def get_disk_metrics(self) -> Dict[str, Any]:
        partitions_data = []
        try:
            partitions = psutil.disk_partitions(all=False)
            for part in partitions:
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    partitions_data.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "total_gb": round(usage.total / (1024**3), 2),
                        "used_gb": round(usage.used / (1024**3), 2),
                        "free_gb": round(usage.free / (1024**3), 2),
                        "percent": round(usage.percent, 1)
                    })
                except (PermissionError, FileNotFoundError, OSError):
                    continue
        except Exception:
            pass

        now = time.time()
        time_delta = max(now - self.last_time, 0.001)

        read_speed_mb = 0.0
        write_speed_mb = 0.0
        current_disk_io = psutil.disk_io_counters()

        if current_disk_io and self.last_disk_io:
            read_bytes_delta = current_disk_io.read_bytes - self.last_disk_io.read_bytes
            write_bytes_delta = current_disk_io.write_bytes - self.last_disk_io.write_bytes
            read_speed_mb = round((read_bytes_delta / time_delta) / (1024**2), 2)
            write_speed_mb = round((write_bytes_delta / time_delta) / (1024**2), 2)

        return {
            "partitions": partitions_data,
            "read_speed_mb_s": max(read_speed_mb, 0.0),
            "write_speed_mb_s": max(write_speed_mb, 0.0),
            "read_count": current_disk_io.read_count if current_disk_io else 0,
            "write_count": current_disk_io.write_count if current_disk_io else 0
        }

    def get_network_metrics(self) -> Dict[str, Any]:
        now = time.time()
        time_delta = max(now - self.last_time, 0.001)

        current_net_io = psutil.net_io_counters()
        up_speed_kb = 0.0
        down_speed_kb = 0.0

        if current_net_io and self.last_net_io:
            sent_delta = current_net_io.bytes_sent - self.last_net_io.bytes_sent
            recv_delta = current_net_io.bytes_recv - self.last_net_io.bytes_recv
            up_speed_kb = round((sent_delta / time_delta) / 1024, 2)
            down_speed_kb = round((recv_delta / time_delta) / 1024, 2)

        # Update last IO counters
        self.last_disk_io = psutil.disk_io_counters()
        self.last_net_io = current_net_io
        self.last_time = now

        return {
            "bytes_sent": current_net_io.bytes_sent if current_net_io else 0,
            "bytes_recv": current_net_io.bytes_recv if current_net_io else 0,
            "sent_mb": round((current_net_io.bytes_sent / (1024**2)), 2) if current_net_io else 0,
            "recv_mb": round((current_net_io.bytes_recv / (1024**2)), 2) if current_net_io else 0,
            "upload_speed_kb_s": max(up_speed_kb, 0.0),
            "download_speed_kb_s": max(down_speed_kb, 0.0),
            "packets_sent": current_net_io.packets_sent if current_net_io else 0,
            "packets_recv": current_net_io.packets_recv if current_net_io else 0,
        }

    def get_battery_metrics(self) -> Dict[str, Any]:
        try:
            battery = psutil.sensors_battery()
            if battery:
                return {
                    "has_battery": True,
                    "percent": battery.percent,
                    "power_plugged": battery.power_plugged,
                    "secs_left": battery.secsleft
                }
        except Exception:
            pass
        return {"has_battery": False}

    def snapshot(self) -> Dict[str, Any]:
        return {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cpu": self.get_cpu_metrics(),
            "memory": self.get_memory_metrics(),
            "disk": self.get_disk_metrics(),
            "network": self.get_network_metrics(),
            "battery": self.get_battery_metrics()
        }

monitor = SystemMonitor()
