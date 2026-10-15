"""Persistence & Autorun Audit View for Terminal."""

from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from core.threat_engine import threat_engine
from ui.theme import console

def display_persistence_view(interactive: bool = True):
    console.print("\n[bold cyan]🔎 Auditing System Startup Persistence & Hosts Redirection...[/]")

    # 1. Startup Items
    items = threat_engine.check_startup_persistence()
    reg_tbl = Table(title="[bold yellow]🗂️ Registry Autoruns & Startup Persistence Items[/]", expand=True)
    reg_tbl.add_column("Registry Root", width=14, style="cyan")
    reg_tbl.add_column("Entry Name", width=22, style="bold white")
    reg_tbl.add_column("Command / Target Path", ratio=1)
    reg_tbl.add_column("Integrity Status", width=20)

    if items:
        for it in items:
            if it["is_suspicious"]:
                status_text = "[bold white on red] SUSPICIOUS [/] [red]Temp Path[/]"
            else:
                status_text = "[bold green]VERIFIED[/]"

            reg_tbl.add_row(
                it["key"],
                it["name"][:20],
                str(it["command"]),
                status_text
            )
    else:
        reg_tbl.add_row("—", "No Registry Autoruns", "Registry Run keys empty or platform is non-Windows", "[dim]N/A[/]")

    console.print(reg_tbl)

    # 2. Hosts File Audit
    hosts = threat_engine.check_hosts_file()
    hosts_status_color = "red" if hosts["status"] == "Modified" else "green"
    hosts_text = (
        f"• [bold white]Hosts Path:[/] {hosts['path']}\n"
        f"• [bold white]Integrity Status:[/] [bold {hosts_status_color}]{hosts['status']}[/]\n"
        f"• [bold white]Active Custom DNS Overrides:[/] {len(hosts['custom_entries'])}"
    )

    if hosts['custom_entries']:
        hosts_text += "\n\n[bold yellow]Entries Found:[/]\n"
        for line in hosts['custom_entries'][:10]:
            hosts_text += f"  [dim cyan]•[/] {line}\n"

    console.print(Panel(hosts_text, title="[bold cyan]🌐 DNS Hosts File Audit[/]", border_style=hosts_status_color))

    if interactive:
        Prompt.ask("\n[bold dim white]Press Enter to return to main menu[/]")
