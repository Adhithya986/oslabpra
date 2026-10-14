# 🛡️ OS Guardian — Smart System Health & Threat Monitor

**OS Guardian** is a modern, high-performance operating system telemetry dashboard and heuristic threat monitoring platform. Built for system administrators, security analysts, and developers, OS Guardian delivers real-time hardware telemetry alongside continuous threat detection, rogue process identification, and Windows persistence auditing.

---

## ⚡ Key Features

### 1. 📊 Real-Time System Health Telemetry
- **CPU Metrics:** Overall utilization percentage, dynamic clock frequencies, and per-core utilization heatbars.
- **Memory & Swap:** Real-time RAM (used / total in GB) and paging/swap utilization with visual warning thresholds.
- **Disk I/O & Storage:** Live Read/Write throughput speeds (MB/s) and mount partition fill meters.
- **Network Bandwidth:** Real-time upload and download speeds (KB/s) and total session data transfer volume.
- **Hardware & Host Profile:** Hostname, OS version/build, CPU architecture, core counts, and live system uptime.

### 2. 🚨 Heuristic Threat & Anomaly Detection Engine
- **Masquerading Process Detection:** Identifies rogue processes disguising themselves with legitimate Windows system names (e.g. `svchost.exe`, `csrss.exe`, `lsass.exe`) executing outside official directories like `System32`.
- **Suspicious Path Execution:** Detects processes executing from user-writable or temporary directories (`AppData\Local\Temp`, `\Temp`, `\tmp`) — a primary vector for droppers and payload execution.
- **Cryptojacking & Resource Spikes:** Flags binaries exhibiting known miner keywords (`xmrig`, `stratum`, `ethminer`) or sustained abnormal 90%+ CPU spikes.
- **Dangerous Port & Listener Detection:** Detects open listening ports matching known vulnerability and backdoor vectors (e.g., Metasploit 4444, ADB shells 5555, DarkComet 6666, NetBus, etc.).
- **Windows Persistence Audit:** Inspects `HKCU` and `HKLM` `Run` registry autorun keys for suspicious startup binaries.
- **Dynamic System Health Score (0-100%):** Computes an automated security posture score ($A^+$ to $F$) with actionable remediation guidance.

### 3. ⚙️ Interactive Process Manager
- Live searchable and sortable table of running processes (sort by CPU %, Memory, PID, or Name).
- **Deep Process Inspection:** View process command-line arguments, execution paths, thread counts, creation time, child processes, and open network sockets.
- **Process Termination:** Terminate or kill unresponsive or rogue processes directly from the dashboard.

### 4. 🌐 Active Sockets & Network Connections
- Real-time enumeration of established TCP/UDP network connections and listening sockets mapped to their owning process names and PIDs.

### 5. 📄 Diagnostic Report Exporter
- One-click export of system diagnostics, security posture, top processes, and metrics snapshot into structured JSON.

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Windows 10/11 (or Linux/macOS for core cross-platform features)

### 1. Installation
Install the required dependencies:
```powershell
pip install -r requirements.txt
```

### 2. Launch the Application
Run the launcher script:
```powershell
python run.py
```
> This will start the FastAPI backend server and automatically open your default web browser to `http://127.0.0.1:8080`.

### 3. Command Line Options
```powershell
# Run on a custom port
python run.py --port 9090

# Listen on all network interfaces
python run.py --host 0.0.0.0 --port 8080

# Run in headless mode (without automatically opening the browser)
python run.py --no-browser
```

---

## 📁 Project Architecture

```
ospra/
├── app/
│   ├── __init__.py
│   ├── config.py             # Detection rules, port lists, and thresholds
│   ├── monitor.py            # Psutil-based system telemetry engine
│   ├── threat_engine.py      # Heuristic threat analysis & security scoring
│   ├── process_manager.py    # Process enumeration, inspection & kill handlers
│   ├── websocket_manager.py  # WebSocket client broadcast manager
│   ├── api.py                # REST API endpoints
│   ├── main.py               # FastAPI server application
│   └── static/
│       ├── index.html        # Modern Cyber SOC dark-mode dashboard
│       ├── css/
│       │   └── style.css     # Glassmorphism styling and animations
│       └── js/
│           ├── app.js        # Main UI controller & WebSocket handler
│           ├── charts.js     # Chart.js real-time rolling telemetry
│           ├── processes.js  # Process management & modal handlers
│           └── threats.js    # Threat scanner & persistence audit view
├── run.py                    # Application launcher with CLI arguments
├── requirements.txt          # Python dependencies
└── README.md                 # Complete documentation
```

---

## 🔌 API Endpoints Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/` | `GET` | Main Web Dashboard |
| `/docs` | `GET` | Interactive Swagger API documentation |
| `/ws/live` | `WebSocket` | Real-time continuous telemetry stream (1.0s interval) |
| `/api/system/summary` | `GET` | Full system overview, static hardware specs, and health posture |
| `/api/system/metrics` | `GET` | Current CPU, Memory, Disk, and Network telemetry snapshot |
| `/api/processes` | `GET` | Filtered and sorted list of running processes |
| `/api/processes/{pid}` | `GET` | Deep inspection of a process (threads, arguments, sockets) |
| `/api/processes/{pid}/kill` | `POST` | Terminate or kill a process |
| `/api/threats/scan` | `GET` | Run on-demand heuristic threat and anomaly scan |
| `/api/threats/persistence` | `GET` | Audit Windows registry startup keys and hosts file |
| `/api/network/connections` | `GET` | List active network connections mapped to processes |
| `/api/report` | `GET` | Export full system diagnostic report |

---

## 🔒 Security Best Practices
- Running OS Guardian with Administrator privileges enables terminating protected processes and reading restricted network socket owners.
- When running in shared network environments, bind to `127.0.0.1` unless firewall rules are configured.
