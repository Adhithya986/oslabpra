import time
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from app.monitor import monitor
from app.threat_engine import threat_engine
from app.process_manager import process_mgr

router = APIRouter()

@router.get("/system/summary")
def get_system_summary():
    static_info = monitor.get_system_static_info()
    snapshot = monitor.snapshot()
    cpu_p = snapshot['cpu']['overall_percent']
    ram_p = snapshot['memory']['ram']['percent']
    disk_p = snapshot['disk']['partitions'][0]['percent'] if snapshot['disk']['partitions'] else 0.0

    threat_summary = threat_engine.run_full_scan(cpu_p, ram_p, disk_p)
    return {
        "system_info": static_info,
        "metrics": snapshot,
        "security": {
            "health": threat_summary["health"],
            "threat_count": threat_summary["threat_count"],
            "threats": threat_summary["threats"],
            "recommendations": threat_summary["recommendations"]
        }
    }

@router.get("/system/metrics")
def get_current_metrics():
    return monitor.snapshot()

@router.get("/processes")
def get_processes(
    limit: int = Query(60, ge=1, le=500),
    sort_by: str = Query("cpu_percent", pattern="^(cpu_percent|memory_percent|memory_mb|name|pid)$")
):
    return {"processes": process_mgr.get_process_list(limit=limit, sort_by=sort_by)}

@router.get("/processes/{pid}")
def get_process_detail(pid: int):
    detail = process_mgr.get_process_detail(pid)
    if not detail:
        raise HTTPException(status_code=404, detail="Process not found")
    return detail

@router.post("/processes/{pid}/kill")
def terminate_process(pid: int, force: bool = False):
    result = process_mgr.terminate_process(pid, force=force)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result

@router.get("/threats/scan")
def trigger_threat_scan():
    snapshot = monitor.snapshot()
    cpu_p = snapshot['cpu']['overall_percent']
    ram_p = snapshot['memory']['ram']['percent']
    disk_p = snapshot['disk']['partitions'][0]['percent'] if snapshot['disk']['partitions'] else 0.0
    return threat_engine.run_full_scan(cpu_p, ram_p, disk_p)

@router.get("/threats/persistence")
def get_startup_persistence():
    return {
        "startup_items": threat_engine.check_startup_persistence(),
        "hosts_file": threat_engine.check_hosts_file()
    }

@router.get("/network/connections")
def get_network_connections():
    import psutil
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
            conns.append({
                "pid": c.pid,
                "process_name": proc_name,
                "type": "TCP" if c.type == 1 else "UDP",
                "local_addr": laddr,
                "remote_addr": raddr,
                "status": c.status
            })
    except Exception as e:
        return {"error": str(e), "connections": []}
    return {"connections": conns[:150]}

@router.get("/report")
def generate_health_report():
    static_info = monitor.get_system_static_info()
    snapshot = monitor.snapshot()
    cpu_p = snapshot['cpu']['overall_percent']
    ram_p = snapshot['memory']['ram']['percent']
    disk_p = snapshot['disk']['partitions'][0]['percent'] if snapshot['disk']['partitions'] else 0.0
    threats = threat_engine.run_full_scan(cpu_p, ram_p, disk_p)
    top_procs = process_mgr.get_process_list(limit=10, sort_by="cpu_percent")

    return {
        "report_generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "system_profile": static_info,
        "health_score": threats["health"],
        "threats_detected": threats["threats"],
        "recommendations": threats["recommendations"],
        "top_processes_by_cpu": top_procs,
        "metrics_snapshot": snapshot
    }
