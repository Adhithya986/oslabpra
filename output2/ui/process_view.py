"""Interactive Process Explorer and Termination Terminal View."""

from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from core.process_manager import process_mgr
from ui.theme import console

def render_process_table(procs: list, sort_by: str = "cpu_percent", filter_term: str = None) -> Table:
    title_suffix = f" (Sorted by: {sort_by}" + (f", Filter: '{filter_term}'" if filter_term else "") + ")"
    table = Table(title=f"[bold cyan]⚙️ Running Operating System Processes{title_suffix}[/]", expand=True)
    table.add_column("PID", width=8, style="cyan", justify="right")
    table.add_column("Name", width=24, style="bold white")
    table.add_column("CPU %", width=10, style="bold yellow", justify="right")
    table.add_column("RAM %", width=10, style="magenta", justify="right")
    table.add_column("RAM (MB)", width=12, style="white", justify="right")
    table.add_column("Threads", width=8, style="dim white", justify="right")
    table.add_column("User", width=22, style="dim cyan")
    table.add_column("Status", width=12, style="green")

    for p in procs:
        cpu_val = p['cpu_percent']
        cpu_style = "bold red" if cpu_val >= 80 else "bold yellow" if cpu_val >= 30 else "cyan"

        table.add_row(
            str(p['pid']),
            p['name'][:24],
            f"[{cpu_style}]{cpu_val:5.1f}%[/]",
            f"{p['memory_percent']:5.1f}%",
            f"{p['memory_mb']:7.1f}",
            str(p['threads']),
            p['username'][:22],
            p['status']
        )
    return table

def inspect_process(pid: int):
    detail = process_mgr.get_process_detail(pid)
    if not detail:
        console.print(f"[bold red]❌ Process with PID {pid} not found or access denied.[/]")
        return

    info_text = (
        f"• [bold white]Process Name:[/] [bold cyan]{detail['name']}[/]\n"
        f"• [bold white]PID:[/] {detail['pid']}\n"
        f"• [bold white]Status:[/] {detail['status']}\n"
        f"• [bold white]User:[/] {detail['username']}\n"
        f"• [bold white]Created At:[/] {detail['created_at']}\n"
        f"• [bold white]CPU Load:[/] [bold yellow]{detail['cpu_percent']}%[/]\n"
        f"• [bold white]Memory (RSS):[/] [bold magenta]{detail['memory_mb']} MB[/] ({detail['memory_percent']}%)\n"
        f"• [bold white]Active Threads:[/] {detail['threads']}\n"
        f"• [bold white]Handles / FDs:[/] {detail['handles_or_fds']}\n"
        f"• [bold white]Executable Path:[/] {detail['exe']}\n"
        f"• [bold white]Command Line:[/] [dim]{detail['cmdline']}[/]"
    )
    console.print(Panel(info_text, title=f"[bold cyan]🔍 Detailed Telemetry: {detail['name']} (PID: {pid})[/]", border_style="cyan"))

    # Children
    if detail['children']:
        child_tbl = Table(title="[bold yellow]Child Processes[/]", expand=True)
        child_tbl.add_column("PID", width=10)
        child_tbl.add_column("Child Name", ratio=1)
        for c in detail['children']:
            child_tbl.add_row(str(c['pid']), c['name'])
        console.print(child_tbl)

    # Connections
    if detail['connections']:
        conn_tbl = Table(title="[bold blue]Open Sockets & Network Connections[/]", expand=True)
        conn_tbl.add_column("Type", width=8)
        conn_tbl.add_column("Local Address", width=24)
        conn_tbl.add_column("Remote Address", width=24)
        conn_tbl.add_column("State", width=14)
        for c in detail['connections']:
            conn_tbl.add_row(c['type'], c['local'], c['remote'] or "—", c['status'])
        console.print(conn_tbl)

def interactive_process_view():
    sort_by = "cpu_percent"
    limit = 25
    filter_term = None

    while True:
        console.clear()
        all_procs = process_mgr.get_process_list(limit=200, sort_by=sort_by)
        if filter_term:
            filtered = [p for p in all_procs if filter_term.lower() in p['name'].lower()]
        else:
            filtered = all_procs[:limit]

        console.print(render_process_table(filtered, sort_by=sort_by, filter_term=filter_term))

        console.print("\n[bold cyan]Process Manager Actions:[reset]")
        console.print(
            " [1] Refresh  "
            " [2] Change Sorting  "
            " [3] Search/Filter  "
            " [4] Inspect PID  "
            " [5] Terminate Process  "
            " [0] Back"
        )

        choice = Prompt.ask("\n[bold white]Select Option[/]", choices=["0", "1", "2", "3", "4", "5"], default="1")

        if choice == "0":
            break
        elif choice == "1":
            continue
        elif choice == "2":
            sort_choice = Prompt.ask(
                "[bold white]Sort by[/]",
                choices=["cpu", "mem_pct", "mem_mb", "name", "pid"],
                default="cpu"
            )
            mapping = {
                "cpu": "cpu_percent",
                "mem_pct": "memory_percent",
                "mem_mb": "memory_mb",
                "name": "name",
                "pid": "pid"
            }
            sort_by = mapping[sort_choice]
        elif choice == "3":
            search = Prompt.ask("[bold white]Enter process name substring (leave empty to reset)[/]", default="")
            filter_term = search.strip() if search.strip() else None
        elif choice == "4":
            pid_str = Prompt.ask("[bold white]Enter PID to inspect[/]")
            if pid_str.isdigit():
                inspect_process(int(pid_str))
                Prompt.ask("\n[dim]Press Enter to continue[/]")
        elif choice == "5":
            pid_str = Prompt.ask("[bold white]Enter PID to terminate[/]")
            if pid_str.isdigit():
                pid = int(pid_str)
                force = Confirm.ask(f"[bold red]Force kill (SIGKILL) PID {pid}?[/]", default=False)
                res = process_mgr.terminate_process(pid, force=force)
                if res.get("success"):
                    console.print(f"[bold green]✔ {res['message']}[/]")
                else:
                    console.print(f"[bold red]❌ {res.get('error')}[/]")
                Prompt.ask("\n[dim]Press Enter to continue[/]")
