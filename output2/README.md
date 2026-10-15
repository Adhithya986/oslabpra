# 🛡️ OS Guardian — Terminal SOC Edition

**OS Guardian (Terminal SOC Edition)** is a standalone, real-time operating system telemetry dashboard and heuristic threat monitoring console built entirely for the command line. Designed for security analysts, sysadmins, and OS lab evaluation, it renders all system telemetry, threat heuristics, process management, and persistence audits directly **across the terminal** without requiring a browser or web server.

---

## ⚡ Key Features (All Terminal-Native)

### 1. 📊 Live Real-Time SOC Dashboard (`python run.py --live`)
- **CPU Telemetry:** Real-time overall CPU percentage, core frequencies, and per-core utilization meters.
- **Memory & Swap:** RAM and paging meters showing used, free, and total volumes in GB.
- **Disk Storage & I/O:** Mount partition utilization bars, real-time read and write throughput (MB/s).
- **Network Bandwidth:** Live download/upload bandwidth (KB/s) and session transfer totals.
- **Security Health Score:** Dynamic score (0-100%) and letter grade ($A^+$ to $F$) with color-coded risk alerts.
- **Auto-Refreshing View:** Updates continuously at 1 Hz using `rich.live.Live` with smooth flicker-free rendering.

### 2. 🚨 Heuristic Threat & Anomaly Scanner (`python run.py --scan`)
- **Masquerading System Process Detection:** Identifies rogue binaries masquerading as legitimate Windows processes (e.g. `svchost.exe`, `lsass.exe`, `csrss.exe`) executing outside valid system directories like `System32`.
- **Suspicious Path Execution:** Flags processes executing from user-writable or temporary folders (`AppData\Local\Temp`, `\Temp`, `\tmp`).
- **Cryptomining & CPU Spikes:** Scans for known miner keywords (`xmrig`, `stratum`, `ethminer`, `monero`) and sustained abnormal CPU spikes ($\ge 90\%$).
- **Dangerous Port Listeners:** Detects open listening ports matching known vulnerability and backdoor vectors (Metasploit 4444, ADB 5555, DarkComet 6666, NetBus 12345, Back Orifice 31337).
- **Actionable Remediation Guidance:** Color-coded recommendations detailing exact mitigation steps.

### 3. ⚙️ Interactive Process Explorer (`python run.py --processes`)
- **Process Table:** View running processes with columns for PID, Name, CPU %, RAM %, RAM (MB), Threads, Username, and Status.
- **Custom Sorting:** Sort dynamically by CPU, Memory %, Memory (MB), Process Name, or PID.
- **Live Search & Filter:** Filter running processes by name substring in real time.
- **Deep Process Inspection:** View command-line arguments, binary path, active sockets, handles/FDs, and child processes.
- **Process Termination:** Terminate (SIGTERM) or force-kill (SIGKILL) rogue or runaway processes directly from the terminal.

### 4. 🌐 Active Sockets & Network Connections (`python run.py --network`)
- Real-time enumeration of established TCP/UDP sessions and listening ports mapped to PIDs and binary names.
- Automatic red-flag alert highlighting any socket matching known malicious listener signatures.
- Enumeration of all network adapters, IP addresses, MAC addresses, and connection status.

### 5. 🗂️ Startup Persistence & Hosts File Auditor (`python run.py --persistence`)
- Audits Windows `HKCU` and `HKLM` `Run` autorun registry keys for binaries executing from temporary or writable paths.
- Inspects `C:\Windows\System32\drivers\etc\hosts` (or `/etc/hosts`) for rogue DNS redirection entries.

### 6. 📄 JSON Diagnostic Report Generator (`python run.py --report`)
- Exports full hardware telemetry, security scoring, process list, and network sockets into a structured, timestamped JSON report inside `audit_reports/`.

---

## 📁 Project Architecture

```
output2/
├── run.py                 # Application launcher
├── main.py                # Primary CLI driver & interactive menu
├── requirements.txt       # Dependencies (psutil, rich, colorama)
├── README.md              # Documentation
├── audit_reports/         # Generated diagnostic reports (auto-created)
├── core/
│   ├── __init__.py
│   ├── config.py          # Threat rules, port database, thresholds
│   ├── monitor.py         # Psutil-based hardware telemetry engine
│   ├── threat_engine.py   # Heuristic threat analysis & security scoring
│   ├── process_manager.py # Process inspection, sorting, and kill handlers
│   └── network_monitor.py # Active socket analyzer & interface telemetry
└── ui/
    ├── __init__.py
    ├── theme.py           # Console setup, UTF-8 handler, ASCII banner, gauges
    ├── dashboard.py       # Live continuous real-time SOC dashboard
    ├── threat_view.py     # Heuristic threat scanner & recommendations screen
    ├── process_view.py    # Process explorer, search filter & inspection screen
    ├── network_view.py    # Network socket inspector view
    ├── persistence_view.py# Startup persistence & hosts auditor view
    └── report_view.py     # Diagnostic report generation & exporter
```

---

## 🚀 Quick Start Guide

### 1. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2. Launch Interactive SOC Menu
```powershell
python run.py
```
This displays the cyber SOC ASCII banner and an interactive operational menu:
```
[1] ⚡ Live Real-Time Dashboard
[2] 🚨 Heuristic Threat & Anomaly Scan
[3] ⚙️ Interactive Process Explorer
[4] 🌐 Network Sockets & Port Monitor
[5] 🗂️ Startup Persistence & Hosts Audit
[6] 📄 Export Full Diagnostic Report
[0] 🚪 Exit Sentinel Console
```

### 3. Direct CLI Command Flags
You can also invoke any feature directly from the terminal without entering the menu:

```powershell
# Launch the live continuous dashboard directly
python run.py --live

# Execute immediate security threat scan
python run.py --scan

# List top 20 processes sorted by memory
python run.py --processes --limit 20 --sort memory_percent

# List active network connections and listening sockets
python run.py --network

# Audit startup autorun registry keys and hosts file
python run.py --persistence

# Generate a diagnostic JSON report
python run.py --report

# Terminate a runaway process by PID
python run.py --kill 1234

# Force-kill a rogue process
python run.py --kill 1234 --force
```
