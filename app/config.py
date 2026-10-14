import os
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

APP_NAME = "OS Guardian"
APP_SUBTITLE = "Smart System Health & Threat Monitor"
VERSION = "1.0.0"

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8080

# Health Thresholds
CPU_HIGH_THRESHOLD = 80.0
CPU_CRITICAL_THRESHOLD = 92.0
RAM_HIGH_THRESHOLD = 85.0
RAM_CRITICAL_THRESHOLD = 95.0
DISK_HIGH_THRESHOLD = 90.0

# Threat & Anomaly Heuristics
SUSPICIOUS_PATHS = [
    r"\temp",
    r"\tmp",
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\users\public",
]

SUSPICIOUS_PORT_LIST = {
    4444: "Metasploit default listener",
    5555: "Suspicious Remote Shell / ADB",
    6666: "IRC / DarkComet Backdoor default",
    1337: "Elite Backdoor port",
    31337: "Back Orifice Trojan default",
    8888: "Suspicious HTTP Proxy / C2",
    9001: "Tor / suspicious alternate proxy",
    12345: "NetBus Trojan default",
}

LEGIT_SYSTEM_LOCATIONS = {
    "svchost.exe": [r"c:\windows\system32", r"c:\windows\syswow64"],
    "lsass.exe": [r"c:\windows\system32"],
    "csrss.exe": [r"c:\windows\system32"],
    "services.exe": [r"c:\windows\system32"],
    "smss.exe": [r"c:\windows\system32"],
    "winlogon.exe": [r"c:\windows\system32"],
    "explorer.exe": [r"c:\windows"],
}
