"""Network sockets, active connections, and interface inspection view."""

from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from core.network_monitor import net_monitor
from ui.theme import console

def display_network_view(interactive: bool = True):
    console.print("\n[bold cyan]🌐 Enumerating Active Network Sockets & Interface Telemetry...[/]")

    # 1. Interface Table
    ifaces = net_monitor.get_interfaces()
    if_tbl = Table(title="[bold cyan]📡 Network Adapters & Interfaces[/]", expand=True)
    if_tbl.add_column("Interface Name", width=24, style="bold white")
    if_tbl.add_column("Status", width=12)
    if_tbl.add_column("IPv4 Address", width=18, style="cyan")
    if_tbl.add_column("MAC Address", width=20, style="dim white")
    if_tbl.add_column("Speed (Mbps)", width=14, justify="right")

    for iface in ifaces:
        status_text = "[bold green]ONLINE[/]" if iface["is_up"] else "[dim red]OFFLINE[/]"
        if_tbl.add_row(
            iface["name"],
            status_text,
            iface["ipv4"],
            iface["mac"],
            str(iface["speed_mbps"]) if iface["speed_mbps"] > 0 else "—"
        )
    console.print(if_tbl)

    # 2. Connections Table
    conns = net_monitor.get_connections(limit=40)
    conn_tbl = Table(title="[bold blue]🔌 Active Sockets & TCP/UDP Connections[/]", expand=True)
    conn_tbl.add_column("PID", width=8, style="cyan", justify="right")
    conn_tbl.add_column("Process Name", width=20, style="bold white")
    conn_tbl.add_column("Proto", width=8)
    conn_tbl.add_column("Local Address", width=24, style="white")
    conn_tbl.add_column("Remote Address", width=24, style="yellow")
    conn_tbl.add_column("State", width=14, style="green")
    conn_tbl.add_column("Security Assessment", ratio=1)

    for c in conns:
        if c["is_suspicious"]:
            sec_assessment = f"[bold white on red] 🚨 ROGUE LISTENER [/] [bold red]{c['suspicious_desc']}[/]"
        elif c["status"] == "LISTEN":
            sec_assessment = "[cyan]Listening Service[/]"
        elif c["status"] == "ESTABLISHED":
            sec_assessment = "[dim green]Active Session[/]"
        else:
            sec_assessment = f"[dim]{c['status']}[/]"

        conn_tbl.add_row(
            str(c["pid"]) if c["pid"] else "—",
            c["process_name"][:18],
            c["type"],
            c["local_addr"],
            c["remote_addr"],
            c["status"],
            sec_assessment
        )
    console.print(conn_tbl)

    if interactive:
        Prompt.ask("\n[bold dim white]Press Enter to return to main menu[/]")
