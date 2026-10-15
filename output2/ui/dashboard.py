"""Live real-time SOC dashboard for terminal display."""

import time
import sys
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.live import Live
from rich.columns import Columns

from core.monitor import monitor
from core.threat_engine import threat_engine
from core.process_manager import process_mgr
from ui.theme import console, make_meter, grade_badge, severity_badge

def generate_dashboard() -> Panel:
    snapshot = monitor.snapshot()
    cpu = snapshot["cpu"]
    mem = snapshot["memory"]
    disk = snapshot["disk"]
    net = snapshot["network"]

    threat_summary = threat_engine.run_full_scan(
        cpu_p=cpu["overall_percent"],
        ram_p=mem["ram"]["percent"],
        disk_p=disk["partitions"][0]["percent"] if disk["partitions"] else 0.0
    )
    health = threat_summary["health"]

    static_info = monitor.get_system_static_info()

    # 1. Header Information Table
    header_tbl = Table.grid(expand=True)
    header_tbl.add_column(ratio=1)
    header_tbl.add_column(ratio=1)
    header_tbl.add_column(ratio=1)

    host_text = f"[bold cyan]Host:[/] {static_info['hostname']} ({static_info['os_name']} {static_info['os_release']})"
    uptime_text = f"[bold cyan]Uptime:[/] {static_info['uptime_human']}"
    time_text = f"[bold cyan]Time:[/] {snapshot['timestamp']}"
    header_tbl.add_row(host_text, uptime_text, time_text)

    # 2. Security Health Score Banner
    health_banner = Table.grid(expand=True)
    health_banner.add_column(ratio=2)
    health_banner.add_column(ratio=1)

    grade_display = grade_badge(health["grade"], health["score"])
    threat_alert = f"[bold red]🚨 Active Threats: {threat_summary['threat_count']}[/]" if threat_summary["threat_count"] > 0 else "[bold green]🛡️ Security Posture: Nominal (0 Threats)[/]"
    health_banner.add_row(grade_display, threat_alert)

    # 3. CPU Telemetry Panel
    cpu_content = Table.grid(expand=True, padding=(0, 1))
    cpu_content.add_column(width=16)
    cpu_content.add_column(ratio=1)

    cpu_meter = make_meter(cpu["overall_percent"], width=18)
    cpu_content.add_row("[bold white]Overall CPU:[reset]", cpu_meter)
    cpu_content.add_row(
        "[bold white]Frequency:[reset]",
        f"[cyan]{cpu['current_freq_mhz']:.0f} MHz[/] (Cores: {static_info['cpu_physical_cores']}P / {static_info['cpu_logical_cores']}L)"
    )

    # Per-core mini meters (first 8 cores)
    per_core_text = Text()
    for idx, c_pct in enumerate(cpu["per_core_percent"][:8]):
        color = "red" if c_pct >= 90 else "yellow" if c_pct >= 75 else "cyan" if c_pct >= 50 else "green"
        per_core_text.append(f"C{idx}:", style="dim")
        per_core_text.append(f"{c_pct:4.0f}% ", style=f"bold {color}")
    cpu_content.add_row("[bold white]Cores Load:[reset]", per_core_text)

    cpu_panel = Panel(cpu_content, title="[bold cyan]⚡ CPU Telemetry[/]", border_style="cyan")

    # 4. Memory & Swap Panel
    ram = mem["ram"]
    swap = mem["swap"]
    mem_content = Table.grid(expand=True, padding=(0, 1))
    mem_content.add_column(width=16)
    mem_content.add_column(ratio=1)

    ram_meter = make_meter(ram["percent"], width=18)
    swap_meter = make_meter(swap["percent"], width=18)

    mem_content.add_row("[bold white]RAM Usage:[reset]", ram_meter)
    mem_content.add_row(
        "[bold white]RAM Volume:[reset]",
        f"[bright_white]{ram['used_gb']:.2f} GB[/] used / [bright_white]{ram['total_gb']:.2f} GB[/] ({ram['free_gb']:.2f} GB free)"
    )
    mem_content.add_row("[bold white]Swap / Page:[reset]", swap_meter)
    mem_content.add_row(
        "[bold white]Swap Volume:[reset]",
        f"{swap['used_gb']:.2f} GB / {swap['total_gb']:.2f} GB"
    )

    mem_panel = Panel(mem_content, title="[bold magenta]🧠 Memory & Swap[/]", border_style="magenta")

    # 5. Disk & Storage Panel
    disk_content = Table.grid(expand=True, padding=(0, 1))
    disk_content.add_column(width=16)
    disk_content.add_column(ratio=1)

    for p in disk["partitions"][:2]:
        p_meter = make_meter(p["percent"], width=15)
        disk_content.add_row(f"[bold white]{p['mountpoint']}[/]", f"{p_meter} [dim]({p['used_gb']}G/{p['total_gb']}G)[/]")

    disk_content.add_row(
        "[bold white]Throughput:[reset]",
        f"Read: [green]{disk['read_speed_mb_s']} MB/s[/] | Write: [yellow]{disk['write_speed_mb_s']} MB/s[/]"
    )
    disk_panel = Panel(disk_content, title="[bold yellow]💾 Storage & I/O[/]", border_style="yellow")

    # 6. Network Telemetry Panel
    net_content = Table.grid(expand=True, padding=(0, 1))
    net_content.add_column(width=16)
    net_content.add_column(ratio=1)

    net_content.add_row(
        "[bold white]Down Speed:[reset]",
        f"[bold bright_green]⬇ {net['download_speed_kb_s']} KB/s[/]"
    )
    net_content.add_row(
        "[bold white]Up Speed:[reset]",
        f"[bold bright_cyan]⬆ {net['upload_speed_kb_s']} KB/s[/]"
    )
    net_content.add_row(
        "[bold white]Session Vol:[reset]",
        f"Recv: [bright_white]{net['recv_mb']} MB[/] | Sent: [bright_white]{net['sent_mb']} MB[/]"
    )
    net_panel = Panel(net_content, title="[bold blue]🌐 Network Bandwidth[/]", border_style="blue")

    # 7. Threat Alert Section
    threats = threat_summary["threats"]
    threat_box = Table(expand=True, box=None, padding=(0, 1))
    threat_box.add_column("Severity", width=12)
    threat_box.add_column("Type", width=24)
    threat_box.add_column("Details", ratio=1)
    threat_box.add_column("Action", width=20)

    if threats:
        for t in threats[:3]:
            threat_box.add_row(
                severity_badge(t["severity"]),
                f"[bold red]{t['type']}[/]",
                t["details"][:65] + ("..." if len(t["details"]) > 65 else ""),
                f"[bold yellow]{t['action']}[/]"
            )
    else:
        threat_box.add_row(
            "[bold green]SECURE[/]",
            "[bold green]No threats detected[/]",
            "[dim green]All system processes, listeners, and paths match known benign baselines.[/]",
            "[green]No action needed[/]"
        )

    threat_panel = Panel(
        threat_box,
        title=f"[bold {'red' if threats else 'green'}]🚨 Heuristic Threat Monitor & Security Alerts[/]",
        border_style="red" if threats else "green"
    )

    # 8. Top Running Processes Table
    proc_list = process_mgr.get_process_list(limit=5, sort_by="cpu_percent")
    proc_tbl = Table(expand=True, box=None, padding=(0, 1))
    proc_tbl.add_column("PID", width=8, style="cyan")
    proc_tbl.add_column("Process Name", width=22, style="bold white")
    proc_tbl.add_column("CPU %", width=10, style="yellow")
    proc_tbl.add_column("RAM %", width=10, style="magenta")
    proc_tbl.add_column("RAM (MB)", width=12, style="white")
    proc_tbl.add_column("User", width=18, style="dim white")
    proc_tbl.add_column("Status", width=10, style="green")

    for p in proc_list:
        proc_tbl.add_row(
            str(p["pid"]),
            p["name"][:20],
            f"{p['cpu_percent']}%",
            f"{p['memory_percent']}%",
            f"{p['memory_mb']} MB",
            p["username"][:16],
            p["status"]
        )

    proc_panel = Panel(proc_tbl, title="[bold white]⚙️ Top Active Processes (by CPU)[/]", border_style="white")

    # Combine into main container table
    main_layout = Table.grid(expand=True, padding=(1, 0))
    main_layout.add_row(header_tbl)
    main_layout.add_row(health_banner)
    main_layout.add_row(Columns([cpu_panel, mem_panel]))
    main_layout.add_row(Columns([disk_panel, net_panel]))
    main_layout.add_row(threat_panel)
    main_layout.add_row(proc_panel)

    return Panel(
        main_layout,
        title="[bold bright_white on dark_blue] 🛡️ OS GUARDIAN — LIVE SYSTEM HEALTH & THREAT MONITOR [/]",
        subtitle="[bold dim white]Press Ctrl+C to return to main menu | Auto-refreshing 1.0s[/]",
        border_style="bright_blue"
    )

def run_live_dashboard(refresh_interval: float = 1.0):
    console.clear()
    try:
        with Live(generate_dashboard(), console=console, screen=True, refresh_per_second=2) as live:
            while True:
                time.sleep(refresh_interval)
                live.update(generate_dashboard())
    except KeyboardInterrupt:
        console.clear()
        console.print("[bold yellow]Exited live dashboard mode.[/]")
