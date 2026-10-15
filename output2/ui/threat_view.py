"""Dedicated Threat & Security Heuristics View for Terminal."""

from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt

from core.monitor import monitor
from core.threat_engine import threat_engine
from ui.theme import console, severity_badge, grade_badge

def display_threat_scan(interactive: bool = True):
    console.print("\n[bold cyan]🔍 Initializing Deep Heuristic Threat & Anomaly Scan...[/]")

    snapshot = monitor.snapshot()
    cpu_p = snapshot["cpu"]["overall_percent"]
    ram_p = snapshot["memory"]["ram"]["percent"]
    disk_p = snapshot["disk"]["partitions"][0]["percent"] if snapshot["disk"]["partitions"] else 0.0

    result = threat_engine.run_full_scan(cpu_p, ram_p, disk_p)
    threats = result["threats"]
    health = result["health"]

    # Security Health Score Panel
    score_display = grade_badge(health["grade"], health["score"])
    summary_text = (
        f"{score_display}\n\n"
        f"• [bold white]Security Health Score:[/] [cyan]{health['score']:.1f}%[/]\n"
        f"• [bold white]Security Grade:[/] [bold {health['color']}]{health['grade']}[/]\n"
        f"• [bold white]Status:[/] [bold {health['color']}]{health['status']}[/]\n"
        f"• [bold white]Active Anomalies Flagged:[/] [bold {'red' if threats else 'green'}]{len(threats)}[/]\n"
        f"• [bold white]Scan Timestamp:[/] {result['timestamp']}"
    )
    console.print(Panel(summary_text, title="[bold cyan]🛡️ Security Posture Assessment[/]", border_style=health["color"]))

    # Threats Table
    table = Table(title="[bold red]🚨 Heuristic Anomaly & Threat Detection Results[/]", expand=True)
    table.add_column("Severity", width=12, justify="center")
    table.add_column("Threat Classification", width=26, style="bold white")
    table.add_column("PID", width=8, style="cyan")
    table.add_column("Process Name", width=20, style="yellow")
    table.add_column("Details & Heuristic Signature", ratio=1)
    table.add_column("Recommended Action", width=24, style="bold red")

    if threats:
        for t in threats:
            table.add_row(
                severity_badge(t["severity"]),
                t["type"],
                str(t.get("pid", "N/A")),
                str(t.get("name", "Unknown")),
                t["details"],
                t["action"]
            )
    else:
        table.add_row(
            "[bold green]NOMINAL[/]",
            "[green]No Active Threats Found[/]",
            "—",
            "—",
            "[dim green]All inspected processes, directories, and listening ports conform to legitimate OS signatures.[/]",
            "[green]System Secured[/]"
        )

    console.print(table)

    # Remediation Recommendations
    rec_text = "\n".join([f" [bold cyan]•[/] {r}" for r in health["recommendations"]])
    console.print(Panel(rec_text, title="[bold yellow]💡 Remediation & Operational Advice[/]", border_style="yellow"))

    if interactive:
        Prompt.ask("\n[bold dim white]Press Enter to return to main menu[/]")
