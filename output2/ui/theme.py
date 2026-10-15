"""Theme, styling, ASCII banners, and UI helpers for Terminal OS Guardian."""

import sys

if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table

console = Console(legacy_windows=False)

BANNER_ART = r"""
 ██████╗ ███████╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
██╔═══██╗██╔════╝    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
██║   ██║███████╗    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
██║   ██║╚════██║    ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
╚██████╔╝███████║    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
 ╚═════╝ ╚══════╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

SUBTITLE = "🛡️  SMART SYSTEM HEALTH & HEURISTIC THREAT MONITOR — TERMINAL SOC v1.0.0"

def get_banner() -> Panel:
    text = Text(BANNER_ART, style="bold cyan")
    text.append(f"\n{SUBTITLE}\n", style="bold bright_white on dark_blue")
    return Panel(text, border_style="bright_blue", expand=True)

def make_meter(percent: float, width: int = 20) -> str:
    """Generate a clean terminal ASCII progress bar with color-coded threshold."""
    percent = max(0.0, min(100.0, percent))
    filled = int(round((percent / 100.0) * width))
    empty = width - filled

    if percent >= 90.0:
        fill_char = f"[bold red]{'█' * filled}[/]"
    elif percent >= 75.0:
        fill_char = f"[bold yellow]{'█' * filled}[/]"
    elif percent >= 50.0:
        fill_char = f"[bold cyan]{'█' * filled}[/]"
    else:
        fill_char = f"[bold green]{'█' * filled}[/]"

    empty_char = f"[dim white]{'░' * empty}[/]"
    return f"{fill_char}{empty_char} {percent:5.1f}%"

def severity_badge(severity: str) -> Text:
    sev = severity.upper()
    if sev == "CRITICAL":
        return Text(" CRITICAL ", style="bold white on red")
    elif sev == "HIGH":
        return Text(" HIGH ", style="bold white on dark_orange")
    elif sev == "MEDIUM":
        return Text(" MEDIUM ", style="bold black on yellow")
    elif sev == "LOW":
        return Text(" LOW ", style="bold black on bright_cyan")
    return Text(f" {sev} ", style="bold white on blue")

def grade_badge(grade: str, score: float) -> str:
    if grade in ("A+", "A"):
        return f"[bold black on bright_green] {grade} ({score}%) [/] [bold green]OPTIMAL & SECURE[/]"
    elif grade == "B":
        return f"[bold black on yellow] {grade} ({score}%) [/] [bold yellow]MODERATE LOAD[/]"
    elif grade == "C":
        return f"[bold white on dark_orange] {grade} ({score}%) [/] [bold dark_orange]ELEVATED RISK[/]"
    return f"[bold white on red] {grade} ({score}%) [/] [bold red]CRITICAL THREAT[/]"
