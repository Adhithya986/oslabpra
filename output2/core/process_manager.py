"""Process management, detailed inspection, and termination controller."""

import psutil
import datetime
from typing import List, Dict, Any, Optional

class ProcessManager:
    def get_process_list(self, limit: int = 50, sort_by: str = "cpu_percent") -> List[Dict[str, Any]]:
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'memory_info', 'status', 'username', 'num_threads', 'exe']):
            try:
                info = p.info
                if info['pid'] == 0 or (info.get('name') or '').lower() == 'system idle process':
                    continue
                # Calculate memory in MB
                mem_bytes = info['memory_info'].rss if info.get('memory_info') else 0
                mem_mb = round(mem_bytes / (1024 * 1024), 2)

                procs.append({
                    "pid": info['pid'],
                    "name": info['name'] or "Unknown",
                    "cpu_percent": round(info['cpu_percent'] or 0.0, 1),
                    "memory_percent": round(info['memory_percent'] or 0.0, 1),
                    "memory_mb": mem_mb,
                    "status": info['status'] or "unknown",
                    "username": info['username'] or "N/A",
                    "threads": info['num_threads'] or 0,
                    "exe": info['exe'] or "N/A"
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Valid sort keys
        sort_keys = {
            "cpu_percent": lambda x: x["cpu_percent"],
            "memory_percent": lambda x: x["memory_percent"],
            "memory_mb": lambda x: x["memory_mb"],
            "name": lambda x: x["name"].lower(),
            "pid": lambda x: x["pid"]
        }

        key_func = sort_keys.get(sort_by, sort_keys["cpu_percent"])
        reverse = sort_by != "name" and sort_by != "pid"
        procs.sort(key=key_func, reverse=reverse)

        return procs[:limit]

    def get_process_detail(self, pid: int) -> Optional[Dict[str, Any]]:
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                name = p.name()
                exe = p.exe()
                cmdline = p.cmdline()
                status = p.status()
                username = p.username()
                create_time = datetime.datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                cpu_p = p.cpu_percent(interval=0.1)
                mem_info = p.memory_info()
                mem_mb = round(mem_info.rss / (1024 * 1024), 2)
                mem_p = round(p.memory_percent(), 2)
                threads = p.num_threads()

                try:
                    num_fds = p.num_handles() if hasattr(p, 'num_handles') else p.num_fds()
                except Exception:
                    num_fds = "N/A"

                try:
                    connections = [
                        {
                            "fd": getattr(c, 'fd', -1),
                            "family": "IPv4" if c.family == 2 else "IPv6",
                            "type": "TCP" if c.type == 1 else "UDP",
                            "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                            "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                            "status": c.status
                        }
                        for c in p.net_connections()[:15]
                    ]
                except Exception:
                    connections = []

                try:
                    children = [{"pid": c.pid, "name": c.name()} for c in p.children(recursive=False)]
                except Exception:
                    children = []

            return {
                "pid": pid,
                "name": name,
                "exe": exe,
                "cmdline": " ".join(cmdline) if cmdline else "N/A",
                "status": status,
                "username": username,
                "created_at": create_time,
                "cpu_percent": cpu_p,
                "memory_mb": mem_mb,
                "memory_percent": mem_p,
                "threads": threads,
                "handles_or_fds": num_fds,
                "children": children,
                "connections": connections
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def terminate_process(self, pid: int, force: bool = False) -> Dict[str, Any]:
        try:
            p = psutil.Process(pid)
            name = p.name()
            if force:
                p.kill()
                return {"success": True, "message": f"Killed process {name} (PID: {pid}) with SIGKILL."}
            else:
                p.terminate()
                return {"success": True, "message": f"Terminated process {name} (PID: {pid}) with SIGTERM."}
        except psutil.NoSuchProcess:
            return {"success": False, "error": f"Process {pid} no longer exists."}
        except psutil.AccessDenied:
            return {"success": False, "error": f"Access denied. Elevated privileges required to terminate PID {pid}."}
        except Exception as e:
            return {"success": False, "error": str(e)}

process_mgr = ProcessManager()
