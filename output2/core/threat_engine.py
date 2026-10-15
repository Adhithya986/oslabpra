"""Heuristic threat detection, anomaly inspection, and security health engine."""

import os
import platform
import datetime
import psutil
from typing import List, Dict, Any

from core.config import (
    SUSPICIOUS_PATHS,
    SUSPICIOUS_PORT_LIST,
    LEGIT_SYSTEM_LOCATIONS,
    MINER_KEYWORDS,
    CPU_HIGH_THRESHOLD,
    CPU_CRITICAL_THRESHOLD,
    RAM_HIGH_THRESHOLD,
    RAM_CRITICAL_THRESHOLD,
    DISK_HIGH_THRESHOLD,
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
                                "details": f"Process '{info['name']}' executes outside authorized system directory ({exe}). Likely disguise/impersonation.",
                                "action": "Kill & Quarantine"
                            })

                # Rule 2: Execution from Temporary / Writable Paths
                if exe:
                    for spath in SUSPICIOUS_PATHS:
                        if spath in exe:
                            threats.append({
                                "id": f"temp_{pid}",
                                "type": "Suspicious Path Execution",
                                "severity": "HIGH",
                                "pid": pid,
                                "name": info['name'],
                                "path": info['exe'],
                                "details": f"Process binary launched from temporary/user-writable location: {exe}",
                                "action": "Inspect & Terminate"
                            })
                            break

                # Rule 3: Crypto Miner / Abnormal CPU Hog
                cpu_p = info.get('cpu_percent') or 0.0
                has_miner_kw = any(kw in name or kw in cmdline for kw in MINER_KEYWORDS)
                if has_miner_kw:
                    threats.append({
                        "id": f"miner_{pid}",
                        "type": "Cryptomining Signature",
                        "severity": "CRITICAL",
                        "pid": pid,
                        "name": info['name'],
                        "path": info.get('exe') or "Unknown",
                        "details": f"Binary matched known cryptocurrency miner keywords/arguments. CPU: {cpu_p}%.",
                        "action": "Immediate Termination"
                    })
                elif cpu_p >= 90.0:
                    threats.append({
                        "id": f"cpu_hog_{pid}",
                        "type": "Extreme Resource Spike",
                        "severity": "MEDIUM",
                        "pid": pid,
                        "name": info['name'],
                        "path": info.get('exe') or "Unknown",
                        "details": f"Process consuming sustained abnormal CPU load ({cpu_p}%). Possible denial of service or runaway loop.",
                        "action": "Throttle / Investigate"
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return threats

    def check_network_threats(self) -> List[Dict[str, Any]]:
        threats = []
        try:
            connections = psutil.net_connections(kind='inet')
            for c in connections:
                if c.status == 'LISTEN' and c.laddr:
                    port = c.laddr.port
                    if port in SUSPICIOUS_PORT_LIST:
                        proc_name = "Unknown"
                        proc_path = "Unknown"
                        if c.pid:
                            try:
                                p = psutil.Process(c.pid)
                                proc_name = p.name()
                                proc_path = p.exe()
                            except Exception:
                                pass

                        threats.append({
                            "id": f"port_{port}_{c.pid}",
                            "type": "Dangerous Listener Port",
                            "severity": "CRITICAL",
                            "pid": c.pid,
                            "name": proc_name,
                            "path": proc_path,
                            "details": f"Open listening port {port} matches known backdoor signature: {SUSPICIOUS_PORT_LIST[port]}.",
                            "action": "Close Port & Terminate"
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
        score = 100.0

        # Performance load deductions
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
            color = "green"
        elif score >= 80:
            grade = "A"
            status = "Good Health"
            color = "blue"
        elif score >= 70:
            grade = "B"
            status = "Moderate Load"
            color = "yellow"
        elif score >= 50:
            grade = "C"
            status = "Elevated Risk"
            color = "bright_yellow"
        else:
            grade = "F"
            status = "Critical Threat / Overload"
            color = "red"

        # Actionable recommendations
        recommendations = []
        if threats_count > 0:
            recommendations.append(f"Immediate Action: Investigate and quarantine {threats_count} flagged suspicious process/network item(s).")
        if cpu_p > CPU_HIGH_THRESHOLD:
            recommendations.append(f"High CPU utilization ({cpu_p}%). Review runaway processes or crypto mining signatures.")
        if ram_p > RAM_HIGH_THRESHOLD:
            recommendations.append(f"High memory consumption ({ram_p}%). Close unused heavy applications to prevent swapping.")
        if disk_p > DISK_HIGH_THRESHOLD:
            recommendations.append(f"Storage volume nearing capacity ({disk_p}%). Clean up temporary files or enlarge storage partition.")
        if not recommendations:
            recommendations.append("All operating system parameters within normal security & performance thresholds.")

        return {
            "score": score,
            "grade": grade,
            "status": status,
            "color": color,
            "recommendations": recommendations
        }

    def run_full_scan(self, cpu_p: float = 0.0, ram_p: float = 0.0, disk_p: float = 0.0) -> Dict[str, Any]:
        process_threats = self.check_suspicious_processes()
        network_threats = self.check_network_threats()
        all_threats = process_threats + network_threats

        health = self.compute_health_score(cpu_p, ram_p, disk_p, len(all_threats))
        self.cached_threats = all_threats
        self.last_scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return {
            "timestamp": self.last_scan_time,
            "threat_count": len(all_threats),
            "threats": all_threats,
            "health": health,
            "recommendations": health["recommendations"]
        }

threat_engine = ThreatEngine()
