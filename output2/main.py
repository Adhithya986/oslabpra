"""Main entry point and CLI driver for OS Guardian Terminal Edition."""

import sys
import argparse
from pathlib import Path

# Ensure local modules are found
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from ui.theme import console, get_banner
from ui.dashboard import run_live_dashboard
from ui.threat_view import display_threat_scan
from ui.process_view import interactive_process_view, render_process_table
from ui.network_view import display_network_view
from ui.persistence_view import display_persistence_view
from ui.report_view import generate_report
from core.process_manager import process_mgr

def interactive_menu():
    while True:
        console.clear()
        console.print(get_banner())

        menu_tbl = Table(title="[bold bright_white]SOC COMMAND OPERATIONS[/]", box=None, expand=True)
        menu_tbl.add_column("Key", width=8, style="bold cyan")
        menu_tbl.add_column("Module", width=36, style="bold white")
        menu_tbl.add_column("Description", ratio=1, style="dim white")

        menu_tbl.add_row("[1]", "⚡ Live Real-Time Dashboard", "Auto-refreshing split SOC telemetry console (CPU, RAM, Disks, Sockets)")
        menu_tbl.add_row("[2]", "🚨 Heuristic Threat & Anomaly Scan", "Detect masquerading binaries, temp executions, miners, and backdoors")
        menu_tbl.add_row("[3]", "⚙️ Interactive Process Explorer", "Search, sort, inspect process threads/sockets, and terminate rogue PIDs")
        menu_tbl.add_row("[4]", "🌐 Network Sockets & Port Monitor", "Enumerate listening services, active TCP/UDP sessions, and network adapters")
        menu_tbl.add_row("[5]", "🗂️ Startup Persistence & Hosts Audit", "Inspect Windows autorun registry keys and check hosts file for DNS hijacks")
        menu_tbl.add_row("[6]", "📄 Export Full Diagnostic Report", "Generate a timestamped, comprehensive JSON report for security auditing")
        menu_tbl.add_row("[0]", "🚪 Exit Sentinel Console", "Terminate OS Guardian session safely")

        console.print(Panel(menu_tbl, border_style="bright_blue"))

        choice = Prompt.ask("\n[bold cyan]Select Operational Module[/]", choices=["0", "1", "2", "3", "4", "5", "6"], default="1")

        if choice == "0":
            console.print("\n[bold cyan]Shutting down OS Guardian Terminal Console. Farewell![/]\n")
            sys.exit(0)
        elif choice == "1":
            run_live_dashboard()
        elif choice == "2":
            console.clear()
            display_threat_scan(interactive=True)
        elif choice == "3":
            interactive_process_view()
        elif choice == "4":
            console.clear()
            display_network_view(interactive=True)
        elif choice == "5":
            console.clear()
            display_persistence_view(interactive=True)
        elif choice == "6":
            console.clear()
            generate_report(interactive=True)

def main():
    parser = argparse.ArgumentParser(
        description="OS Guardian Terminal SOC Edition — System Health & Threat Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--live", "-l", action="store_true", help="Launch live full-screen real-time SOC dashboard")
    parser.add_argument("--scan", "-s", action="store_true", help="Execute immediate heuristic threat scan and print results")
    parser.add_argument("--processes", "-p", action="store_true", help="Print running processes table")
    parser.add_argument("--limit", type=int, default=25, help="Number of processes to display (default: 25)")
    parser.add_argument("--sort", default="cpu_percent", choices=["cpu_percent", "memory_percent", "memory_mb", "name", "pid"], help="Sort processes by metric")
    parser.add_argument("--network", "-n", action="store_true", help="Print active network sockets and adapters")
    parser.add_argument("--persistence", action="store_true", help="Audit autoruns registry keys and hosts file")
    parser.add_argument("--report", "-r", action="store_true", help="Generate and export JSON audit report")
    parser.add_argument("--output", type=str, default=None, help="Custom output path for exported report")
    parser.add_argument("--kill", type=int, metavar="PID", help="Terminate a process by PID")
    parser.add_argument("--force", action="store_true", help="Force kill process (SIGKILL) when used with --kill")

    args = parser.parse_args()

    # Direct CLI command handling
    if args.kill is not None:
        res = process_mgr.terminate_process(args.kill, force=args.force)
        if res.get("success"):
            console.print(f"[bold green]✔ {res['message']}[/]")
        else:
            console.print(f"[bold red]❌ {res.get('error')}[/]")
        return

    if args.live:
        run_live_dashboard()
        return

    if args.scan:
        display_threat_scan(interactive=False)
        return

    if args.processes:
        procs = process_mgr.get_process_list(limit=args.limit, sort_by=args.sort)
        console.print(render_process_table(procs, sort_by=args.sort))
        return

    if args.network:
        display_network_view(interactive=False)
        return

    if args.persistence:
        display_persistence_view(interactive=False)
        return

    if args.report:
        generate_report(output_path=args.output, interactive=False)
        return

    # If no flags passed, launch interactive terminal menu
    interactive_menu()

if __name__ == "__main__":
    main()
