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
        # Initialize psutil CPU measurement
        psutil.cpu_percent(interval=None)
        psutil.cpu_percent(percpu=True, interval=None)

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
            "processor": uname.processor,
            "hostname": uname.node,
            "cpu_physical_cores": psutil.cpu_count(logical=False) or 1,
            "cpu_logical_cores": psutil.cpu_count(logical=True) or 1,
            **self.get_uptime_info()
        }

    def get_cpu_metrics(self) -> Dict[str, Any]:
        cpu_overall = psutil.cpu_percent(interval=None)
        cpu_per_core = psutil.cpu_percent(percpu=True, interval=None)
        freq = psutil.cpu_freq()
        return {
            "overall_percent": round(cpu_overall, 1),
            "per_core_percent": [round(c, 1) for c in cpu_per_core],
            "core_count": len(cpu_per_core),
            "current_freq_mhz": round(freq.current, 1) if freq else 0,
            "min_freq_mhz": round(freq.min, 1) if freq else 0,
            "max_freq_mhz": round(freq.max, 1) if freq else 0,
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
                except (PermissionError, FileNotFoundError):
                    continue
        except Exception:
            pass

        # Calculate I/O speed delta
        current_time = time.time()
        time_delta = max(current_time - self.last_time, 0.001)
        current_disk_io = psutil.disk_io_counters()

        read_speed_mb_s = 0.0
        write_speed_mb_s = 0.0
        if current_disk_io and self.last_disk_io:
            read_bytes_delta = max(0, current_disk_io.read_bytes - self.last_disk_io.read_bytes)
            write_bytes_delta = max(0, current_disk_io.write_bytes - self.last_disk_io.write_bytes)
            read_speed_mb_s = round((read_bytes_delta / (1024 * 1024)) / time_delta, 2)
            write_speed_mb_s = round((write_bytes_delta / (1024 * 1024)) / time_delta, 2)

        return {
            "partitions": partitions_data,
            "read_speed_mb_s": read_speed_mb_s,
            "write_speed_mb_s": write_speed_mb_s,
            "read_count": current_disk_io.read_count if current_disk_io else 0,
            "write_count": current_disk_io.write_count if current_disk_io else 0
        }

    def get_network_metrics(self) -> Dict[str, Any]:
        current_time = time.time()
        time_delta = max(current_time - self.last_time, 0.001)
        current_net_io = psutil.net_io_counters()

        upload_kb_s = 0.0
        download_kb_s = 0.0
        if current_net_io and self.last_net_io:
            sent_delta = max(0, current_net_io.bytes_sent - self.last_net_io.bytes_sent)
            recv_delta = max(0, current_net_io.bytes_recv - self.last_net_io.bytes_recv)
            upload_kb_s = round((sent_delta / 1024) / time_delta, 2)
            download_kb_s = round((recv_delta / 1024) / time_delta, 2)

        interfaces = {}
        try:
            if_addrs = psutil.net_if_addrs()
            if_stats = psutil.net_if_stats()
            for name, addrs in if_addrs.items():
                stats = if_stats.get(name)
                ip_list = [addr.address for addr in addrs if addr.family.name in ('AF_INET', 'AF_INET6')]
                if ip_list:
                    interfaces[name] = {
                        "is_up": stats.isup if stats else True,
                        "speed_mbps": stats.speed if stats else 0,
                        "addresses": ip_list
                    }
        except Exception:
            pass

        return {
            "upload_kb_s": upload_kb_s,
            "download_kb_s": download_kb_s,
            "bytes_sent": current_net_io.bytes_sent if current_net_io else 0,
            "bytes_recv": current_net_io.bytes_recv if current_net_io else 0,
            "interfaces": interfaces
        }

    def get_battery_info(self) -> Dict[str, Any]:
        try:
            sensors_battery = psutil.sensors_battery()
            if sensors_battery:
                return {
                    "has_battery": True,
                    "percent": sensors_battery.percent,
                    "power_plugged": sensors_battery.power_plugged,
                    "secs_left": sensors_battery.secsleft if sensors_battery.secsleft != -1 else None
                }
        except Exception:
            pass
        return {"has_battery": False}

    def snapshot(self) -> Dict[str, Any]:
        """Fetch a complete system health snapshot and advance internal I/O counters."""
        cpu = self.get_cpu_metrics()
        memory = self.get_memory_metrics()
        disk = self.get_disk_metrics()
        network = self.get_network_metrics()
        battery = self.get_battery_info()
        uptime = self.get_uptime_info()

        # Update base counters for speed calculations
        self.last_disk_io = psutil.disk_io_counters()
        self.last_net_io = psutil.net_io_counters()
        self.last_time = time.time()

        return {
            "timestamp": time.time(),
            "cpu": cpu,
            "memory": memory,
            "disk": disk,
            "network": network,
            "battery": battery,
            "uptime": uptime
        }

monitor = SystemMonitor()
