"""Diagnostic Report Generation & JSON Exporter."""

import json
import os
import datetime
from pathlib import Path
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from core.config import REPORTS_DIR
from core.monitor import monitor
from core.threat_engine import threat_engine
from core.process_manager import process_mgr
from core.network_monitor import net_monitor
from ui.theme import console, grade_badge

def generate_report(output_path: str = None, interactive: bool = True):
    console.print("\n[bold cyan]📄 Generating Full System Diagnostic & Security Health Report...[/]")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    static_info = monitor.get_system_static_info()
    snapshot = monitor.snapshot()
    cpu_p = snapshot["cpu"]["overall_percent"]
    ram_p = snapshot["memory"]["ram"]["percent"]
    disk_p = snapshot["disk"]["partitions"][0]["percent"] if snapshot["disk"]["partitions"] else 0.0

    threat_summary = threat_engine.run_full_scan(cpu_p, ram_p, disk_p)
    top_procs = process_mgr.get_process_list(limit=25, sort_by="cpu_percent")
    network_conns = net_monitor.get_connections(limit=50)
    persistence = threat_engine.check_startup_persistence()
    hosts_audit = threat_engine.check_hosts_file()

    report_payload = {
        "metadata": {
            "app": "OS Guardian - Terminal SOC Edition",
            "version": "1.0.0",
            "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "system_profile": static_info,
        "security_posture": {
            "health_score": threat_summary["health"]["score"],
            "grade": threat_summary["health"]["grade"],
            "status": threat_summary["health"]["status"],
            "threat_count": threat_summary["threat_count"],
            "threats": threat_summary["threats"],
            "recommendations": threat_summary["recommendations"]
        },
        "telemetry_metrics": snapshot,
        "top_processes": top_procs,
        "active_connections": network_conns,
        "persistence_audit": {
            "startup_items": persistence,
            "hosts_file": hosts_audit
        }
    }

    if not output_path:
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = REPORTS_DIR / f"audit_report_{timestamp_str}.json"
    else:
        output_file = Path(output_path)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)

    # Display Report Summary
    health = threat_summary["health"]
    summary_text = (
        f"• [bold white]Export Destination:[/] [bold cyan]{output_file.resolve()}[/]\n"
        f"• [bold white]Security Grade:[/] {grade_badge(health['grade'], health['score'])}\n"
        f"• [bold white]CPU Overall:[/] {cpu_p}%\n"
        f"• [bold white]RAM Overall:[/] {ram_p}% ({snapshot['memory']['ram']['used_gb']} GB used)\n"
        f"• [bold white]Flagged Threats:[/] [bold {'red' if threat_summary['threat_count'] > 0 else 'green'}]{threat_summary['threat_count']}[/]\n"
        f"• [bold white]Processes Audited:[/] {len(top_procs)}\n"
        f"• [bold white]Active Sockets Recorded:[/] {len(network_conns)}"
    )
    console.print(Panel(summary_text, title="[bold green]✔ Diagnostic Audit Report Successfully Exported[/]", border_style="green"))

    if interactive:
        Prompt.ask("\n[bold dim white]Press Enter to return to main menu[/]")
