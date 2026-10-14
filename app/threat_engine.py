import os
import platform
import psutil
from typing import List, Dict, Any
from app.config import (
    SUSPICIOUS_PATHS,
    SUSPICIOUS_PORT_LIST,
    LEGIT_SYSTEM_LOCATIONS,
    CPU_HIGH_THRESHOLD,
    CPU_CRITICAL_THRESHOLD,
    RAM_HIGH_THRESHOLD,
    RAM_CRITICAL_THRESHOLD,
    DISK_HIGH_THRESHOLD
)

try:
    import winreg
except ImportError:
    winreg = None

class ThreatEngine:
    def __init__(self):
        self.cached_threats = []
        self.last_scan_time = None

    def check_suspicious_processes(self) -> List[Dict[str, Any]]:
        threats = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent', 'username', 'cmdline']):
            try:
                info = proc.info
                pid = info['pid']
                name = (info['name'] or "").lower()
                exe = (info['exe'] or "").lower()
                cmdline = " ".join(info['cmdline'] or []).lower()

                # Rule 1: Masquerading System Process
                if name in LEGIT_SYSTEM_LOCATIONS:
                    allowed_dirs = LEGIT_SYSTEM_LOCATIONS[name]
                    if exe:
                        is_valid_dir = any(exe.startswith(ad) for ad in allowed_dirs)
                        if not is_valid_dir:
                            threats.append({
                                "id": f"masq_{pid}",
                                "type": "Masquerading Process",
                                "severity": "CRITICAL",
                                "pid": pid,
                                "name": info['name'],
                                "path": info['exe'],
                                "details": f"Process '{info['name']}' is executing outside authorized system folder ({exe}). Likely malicious disguise.",
                                "action": "Kill & Quarantine"
                            })

                # Rule 2: Execution from Temporary Directories
                if exe:
                    for spath in SUSPICIOUS_PATHS:
                        if spath in exe:
                            threats.append({
                                "id": f"temp_{pid}",
                                "type": "Suspicious Execution Path",
                                "severity": "HIGH",
                                "pid": pid,
                                "name": info['name'],
                                "path": info['exe'],
                                "details": f"Process is executing from user/system temp directory: {exe}",
                                "action": "Inspect & Terminate"
                            })
                            break

                # Rule 3: Crypto Miner / Rogue High CPU Usage
                cpu_p = info.get('cpu_percent') or 0.0
                miner_keywords = ["xmrig", "miner", "stratum", "ethminer", "nicehash", "cryptonight"]
                has_miner_kw = any(kw in name or kw in cmdline for kw in miner_keywords)
                if has_miner_kw:
                    threats.append({
                        "id": f"miner_{pid}",
                        "type": "Cryptojacking / Mining Signature",
                        "severity": "CRITICAL",
                        "pid": pid,
                        "name": info['name'],
                        "path": info.get('exe') or "Unknown",
                        "details": f"Process matches known cryptocurrency mining keywords or commands. CPU: {cpu_p}%.",
                        "action": "Immediate Kill"
                    })
                elif cpu_p >= 90.0:
                    threats.append({
                        "id": f"cpu_hog_{pid}",
                        "type": "Severe Resource Spike",
                        "severity": "MEDIUM",
                        "pid": pid,
                        "name": info['name'],
                        "path": info.get('exe') or "Unknown",
                        "details": f"Process is utilizing excessive CPU ({cpu_p}%). Potential denial of service or runaway loop.",
                        "action": "Monitor / Throttle"
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return threats

    def check_network_threats(self) -> List[Dict[str, Any]]:
        threats = []
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                laddr = conn.laddr
                raddr = conn.raddr
                status = conn.status
                pid = conn.pid

                # Check listening port anomalies
                if status == psutil.CONN_LISTEN and laddr:
                    port = laddr.port
                    if port in SUSPICIOUS_PORT_LIST:
                        proc_name = "Unknown"
                        if pid:
                            try:
                                proc_name = psutil.Process(pid).name()
                            except Exception:
                                pass
                        threats.append({
                            "id": f"port_{port}_{pid}",
                            "type": "Dangerous Listening Port",
                            "severity": "CRITICAL",
                            "pid": pid,
                            "name": proc_name,
                            "path": f"0.0.0.0:{port}",
                            "details": f"Port {port} is open and listening. Known vulnerability/backdoor association: {SUSPICIOUS_PORT_LIST[port]}.",
                            "action": "Close Port & Terminate PID"
                        })

                # Check suspicious outbound connection targets
                if status == psutil.CONN_ESTABLISHED and raddr:
                    rport = raddr.port
                    if rport in SUSPICIOUS_PORT_LIST:
                        threats.append({
                            "id": f"outbound_{rport}_{pid}",
                            "type": "Suspicious Remote Connection",
                            "severity": "HIGH",
                            "pid": pid,
                            "name": f"PID {pid}",
                            "path": f"{raddr.ip}:{rport}",
                            "details": f"Outbound connection established to suspicious port {rport} ({SUSPICIOUS_PORT_LIST[rport]}).",
                            "action": "Block Remote IP"
                        })
        except (psutil.AccessDenied, Exception):
            pass
        return threats

    def check_startup_persistence(self) -> List[Dict[str, Any]]:
        items = []
        if not winreg or platform.system() != "Windows":
            return items

        reg_targets = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        ]

        for hkey, subkey, label in reg_targets:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for i in range(num_values):
                        try:
                            val_name, val_data, _ = winreg.EnumValue(key, i)
                            val_str = str(val_data).lower()
                            is_suspicious = any(p in val_str for p in SUSPICIOUS_PATHS)
                            items.append({
                                "key": label,
                                "name": val_name,
                                "command": val_data,
                                "is_suspicious": is_suspicious,
                                "warning": "Startup entry points to temporary or user-writable path!" if is_suspicious else None
                            })
                        except Exception:
                            continue
            except Exception:
                continue
        return items

    def check_hosts_file(self) -> Dict[str, Any]:
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if platform.system() == "Windows" else "/etc/hosts"
        result = {"path": hosts_path, "status": "Clean", "custom_entries": []}
        try:
            if os.path.exists(hosts_path):
                with open(hosts_path, 'r', errors='ignore') as f:
                    lines = f.readlines()
                custom = []
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        custom.append(line)
                result["custom_entries"] = custom
                if len(custom) > 5:
                    result["status"] = "Modified"
                    result["details"] = f"{len(custom)} custom DNS overrides found in hosts file."
        except Exception as e:
            result["status"] = "Error"
            result["details"] = str(e)
        return result

    def compute_health_score(self, cpu_p: float, ram_p: float, disk_p: float, threats_count: int) -> Dict[str, Any]:
        """Compute an overall system security and performance health score (0-100%)."""
        score = 100.0

        # Performance deductions
        if cpu_p > CPU_CRITICAL_THRESHOLD:
            score -= 20
        elif cpu_p > CPU_HIGH_THRESHOLD:
            score -= 10

        if ram_p > RAM_CRITICAL_THRESHOLD:
            score -= 20
        elif ram_p > RAM_HIGH_THRESHOLD:
            score -= 10

        if disk_p > DISK_HIGH_THRESHOLD:
            score -= 15
        elif disk_p > 80.0:
            score -= 5

        # Security threat deductions
        score -= min(threats_count * 15, 50)
        score = max(0.0, round(score, 1))

        if score >= 90:
            grade = "A+"
            status = "Optimal & Secure"
            color = "#10b981"
        elif score >= 80:
            grade = "A"
            status = "Good Health"
            color = "#3b82f6"
        elif score >= 70:
            grade = "B"
            status = "Moderate Load"
            color = "#f59e0b"
        elif score >= 50:
            grade = "C"
            status = "Elevated Risk"
            color = "#f97316"
        else:
            grade = "F"
            status = "Critical Threat / Load"
            color = "#ef4444"

        return {
            "score": score,
            "grade": grade,
            "status": status,
            "color": color
        }

    def run_full_scan(self, cpu_percent: float = 0.0, ram_percent: float = 0.0, disk_percent: float = 0.0) -> Dict[str, Any]:
        proc_threats = self.check_suspicious_processes()
        net_threats = self.check_network_threats()
        startup_items = self.check_startup_persistence()
        hosts_info = self.check_hosts_file()

        all_threats = proc_threats + net_threats
        # Add startup persistence threats if any
        for item in startup_items:
            if item.get("is_suspicious"):
                all_threats.append({
                    "id": f"persist_{item['name']}",
                    "type": "Suspicious Startup Persistence",
                    "severity": "HIGH",
                    "pid": None,
                    "name": item["name"],
                    "path": item["command"],
                    "details": f"Suspicious startup run key: {item['command']}",
                    "action": "Review & Disable in Registry"
                })

        health = self.compute_health_score(cpu_percent, ram_percent, disk_percent, len(all_threats))

        recommendations = []
        if len(all_threats) > 0:
            recommendations.append("Investigate and terminate identified suspicious or masquerading processes.")
        if cpu_percent > 80:
            recommendations.append("High CPU utilization detected. Inspect top active processes in the Process Manager.")
        if ram_percent > 85:
            recommendations.append("Memory utilization is high. Close unnecessary background applications.")
        if disk_percent > 85:
            recommendations.append("Primary drive space is running low. Clean temporary files.")
        if not recommendations:
            recommendations.append("All core monitors operating normally. No active threats detected.")

        return {
            "health": health,
            "threats": all_threats,
            "threat_count": len(all_threats),
            "startup_items": startup_items,
            "hosts_info": hosts_info,
            "recommendations": recommendations
        }

threat_engine = ThreatEngine()
