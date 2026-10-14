import psutil
import datetime
from typing import List, Dict, Any, Optional

class ProcessManager:
    @staticmethod
    def get_process_list(limit: int = 60, sort_by: str = "cpu_percent") -> List[Dict[str, Any]]:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'memory_info', 'status', 'create_time', 'exe']):
            try:
                info = proc.info
                mem_mb = round((info['memory_info'].rss if info['memory_info'] else 0) / (1024 * 1024), 1)
                create_dt = ""
                if info.get('create_time'):
                    create_dt = datetime.datetime.fromtimestamp(info['create_time']).strftime("%H:%M:%S")

                processes.append({
                    "pid": info['pid'],
                    "name": info['name'] or "Unknown",
                    "user": info['username'] or "SYSTEM",
                    "cpu_percent": round(info.get('cpu_percent') or 0.0, 1),
                    "memory_percent": round(info.get('memory_percent') or 0.0, 1),
                    "memory_mb": mem_mb,
                    "status": info.get('status') or "running",
                    "create_time": create_dt,
                    "exe": info.get('exe') or ""
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Sort processes
        reverse = True
        if sort_by in ["cpu_percent", "memory_percent", "memory_mb"]:
            processes.sort(key=lambda p: p.get(sort_by, 0), reverse=reverse)
        elif sort_by == "name":
            processes.sort(key=lambda p: p.get("name", "").lower(), reverse=False)
        elif sort_by == "pid":
            processes.sort(key=lambda p: p.get("pid", 0), reverse=False)

        return processes[:limit]

    @staticmethod
    def get_process_detail(pid: int) -> Optional[Dict[str, Any]]:
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                name = proc.name()
                exe = proc.exe()
                cmdline = proc.cmdline()
                username = proc.username()
                create_time = datetime.datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                num_threads = proc.num_threads()
                cpu_p = proc.cpu_percent()
                mem_info = proc.memory_info()
                status = proc.status()

                connections = []
                try:
                    for c in proc.connections(kind='inet'):
                        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                        connections.append({
                            "fd": c.fd,
                            "family": str(c.family),
                            "type": str(c.type),
                            "laddr": laddr,
                            "raddr": raddr,
                            "status": c.status
                        })
                except Exception:
                    pass

                children = []
                try:
                    for ch in proc.children():
                        children.append({"pid": ch.pid, "name": ch.name()})
                except Exception:
                    pass

                return {
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "cmdline": " ".join(cmdline),
                    "username": username,
                    "create_time": create_time,
                    "num_threads": num_threads,
                    "cpu_percent": cpu_p,
                    "memory_mb": round(mem_info.rss / (1024 * 1024), 2),
                    "status": status,
                    "connections": connections,
                    "children": children
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {"error": str(e), "pid": pid}

    @staticmethod
    def terminate_process(pid: int, force: bool = False) -> Dict[str, Any]:
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            if force:
                proc.kill()
            else:
                proc.terminate()
            return {"success": True, "message": f"Successfully signaled termination for process '{name}' (PID: {pid})."}
        except psutil.NoSuchProcess:
            return {"success": False, "error": f"Process PID {pid} no longer exists."}
        except psutil.AccessDenied:
            return {"success": False, "error": f"Access denied terminating PID {pid}. Administrator privileges may be required."}
        except Exception as e:
            return {"success": False, "error": str(e)}

process_mgr = ProcessManager()
