"""Network socket monitor and connection analyzer."""

import psutil
from typing import List, Dict, Any
from core.config import SUSPICIOUS_PORT_LIST

class NetworkMonitor:
    def get_connections(self, limit: int = 100) -> List[Dict[str, Any]]:
        conns = []
        try:
            for c in psutil.net_connections(kind='inet'):
                proc_name = "Unknown"
                if c.pid:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except Exception:
                        pass

                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""

                is_suspicious = False
                suspicious_desc = None
                if c.laddr and c.laddr.port in SUSPICIOUS_PORT_LIST:
                    is_suspicious = True
                    suspicious_desc = SUSPICIOUS_PORT_LIST[c.laddr.port]

                conns.append({
                    "pid": c.pid,
                    "process_name": proc_name,
                    "type": "TCP" if c.type == 1 else "UDP",
                    "local_addr": laddr,
                    "remote_addr": raddr or "—",
                    "status": c.status or "—",
                    "is_suspicious": is_suspicious,
                    "suspicious_desc": suspicious_desc
                })
        except Exception:
            pass

        return conns[:limit]

    def get_interfaces(self) -> List[Dict[str, Any]]:
        ifaces = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface_name, addr_list in addrs.items():
                stat = stats.get(iface_name)
                is_up = stat.isup if stat else False
                speed = stat.speed if stat else 0
                ipv4 = "N/A"
                mac = "N/A"
                for a in addr_list:
                    if a.family == 2:  # AF_INET
                        ipv4 = a.address
                    elif getattr(a, 'family', None) == -1 or 'mac' in str(getattr(a, 'family', '')).lower():
                        mac = a.address

                ifaces.append({
                    "name": iface_name,
                    "is_up": is_up,
                    "speed_mbps": speed,
                    "ipv4": ipv4,
                    "mac": mac
                })
        except Exception:
            pass
        return ifaces

net_monitor = NetworkMonitor()
