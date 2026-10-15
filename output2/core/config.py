"""Configuration, security thresholds, and threat signatures."""

import os
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "audit_reports"

APP_NAME = "OS GUARDIAN"
APP_SUBTITLE = "Smart System Health & Threat Monitor"
APP_EDITION = "Terminal SOC Edition"
VERSION = "1.0.0"

# Health Thresholds (%)
CPU_HIGH_THRESHOLD = 80.0
CPU_CRITICAL_THRESHOLD = 92.0
RAM_HIGH_THRESHOLD = 85.0
RAM_CRITICAL_THRESHOLD = 95.0
DISK_HIGH_THRESHOLD = 90.0

# Suspicious Execution Locations
SUSPICIOUS_PATHS = [
    r"\temp",
    r"\tmp",
    r"/tmp",
    r"/var/tmp",
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\users\public",
]

# Suspicious Listening Port Database
SUSPICIOUS_PORT_LIST = {
    4444: "Metasploit default C2 listener",
    5555: "Suspicious Remote Shell / ADB exploit",
    6666: "IRC / DarkComet Backdoor default",
    1337: "Elite Backdoor port",
    31337: "Back Orifice Trojan listener",
    8888: "Suspicious HTTP Proxy / Rogue listener",
    9001: "Tor / alternate rogue proxy",
    12345: "NetBus Trojan backdoor",
    44444: "Known Trojan / payload reverse shell",
}

# Legitimate OS System Locations for Masquerade Detection
LEGIT_SYSTEM_LOCATIONS = {
    "svchost.exe": [r"c:\windows\system32", r"c:\windows\syswow64"],
    "lsass.exe": [r"c:\windows\system32"],
    "csrss.exe": [r"c:\windows\system32"],
    "services.exe": [r"c:\windows\system32"],
    "smss.exe": [r"c:\windows\system32"],
    "winlogon.exe": [r"c:\windows\system32"],
    "explorer.exe": [r"c:\windows"],
}

# Cryptocurrency Miner Signatures
MINER_KEYWORDS = [
    "xmrig", "stratum", "ethminer", "nicehash", "cryptonight",
    "minerd", "cpuminer", "monero", "hashvault", "nanopool"
]
