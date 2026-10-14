// Main Application Logic for OS Guardian
let ws = null;
let audioAlertsEnabled = false;
let audioCtx = null;
let lastKnownThreatCount = 0;

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    initWebSocket();
    fetchInitialSummary();
    fetchProcesses();
    setupEventListeners();

    // Periodic process refresh every 4 seconds if on process tab
    setInterval(() => {
        const activeTab = document.querySelector('.tab-btn.active');
        if (activeTab && activeTab.dataset.tab === 'processes') {
            fetchProcesses();
        }
    }, 4000);
});

function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        console.log("[WS] Connected to OS Guardian telemetry stream");
        updateConnectionStatus(true);
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'METRICS_UPDATE') {
                handleLiveMetrics(data.metrics, data.security);
            }
        } catch (e) {
            console.error("Error processing telemetry packet:", e);
        }
    };

    ws.onclose = () => {
        console.warn("[WS] Disconnected. Reconnecting in 2 seconds...");
        updateConnectionStatus(false);
        setTimeout(initWebSocket, 2000);
    };

    ws.onerror = (err) => {
        console.error("[WS] Error:", err);
        ws.close();
    };
}

function updateConnectionStatus(connected) {
    const statusDot = document.getElementById('statusPulseDot');
    const statusText = document.getElementById('statusPulseText');
    if (statusDot && statusText) {
        if (connected) {
            statusDot.className = 'pulse-dot bg-emerald-500 shadow-emerald-500';
            statusText.innerText = 'LIVE TELEMETRY STREAM';
            statusText.className = 'text-emerald-400 font-semibold';
        } else {
            statusDot.className = 'w-2 h-2 rounded-full bg-rose-500 animate-ping';
            statusText.innerText = 'RECONNECTING...';
            statusText.className = 'text-rose-400 font-semibold';
        }
    }
}

async function fetchInitialSummary() {
    try {
        const res = await fetch('/api/system/summary');
        const data = await res.json();
        
        // Populate static system hardware badge
        const sys = data.system_info;
        if (sys) {
            document.getElementById('sysHostname').innerText = sys.hostname || 'Localhost';
            document.getElementById('sysOs').innerText = `${sys.os_name} ${sys.os_release} (${sys.machine})`;
            document.getElementById('sysCpuName').innerText = `${sys.processor || 'x86_64'} (${sys.cpu_physical_cores} Cores / ${sys.cpu_logical_cores} Threads)`;
            document.getElementById('sysUptime').innerText = sys.uptime_human || '0s';

            // Hardware Specs Tab
            const hwContainer = document.getElementById('hardwareSpecsContainer');
            if (hwContainer) {
                hwContainer.innerHTML = `
                    <div class="space-y-3">
                        <div class="flex justify-between border-b border-slate-800 pb-2"><span class="text-slate-400">Computer Name</span><span class="font-mono text-sky-400 font-medium">${sys.hostname}</span></div>
                        <div class="flex justify-between border-b border-slate-800 pb-2"><span class="text-slate-400">Operating System</span><span class="font-mono text-slate-200">${sys.os_name} ${sys.os_release} (Build ${sys.os_version})</span></div>
                        <div class="flex justify-between border-b border-slate-800 pb-2"><span class="text-slate-400">Architecture</span><span class="font-mono text-slate-200">${sys.machine}</span></div>
                        <div class="flex justify-between border-b border-slate-800 pb-2"><span class="text-slate-400">Processor</span><span class="font-mono text-slate-200">${sys.processor}</span></div>
                        <div class="flex justify-between border-b border-slate-800 pb-2"><span class="text-slate-400">Physical CPU Cores</span><span class="font-mono text-emerald-400 font-semibold">${sys.cpu_physical_cores}</span></div>
                        <div class="flex justify-between border-b border-slate-800 pb-2"><span class="text-slate-400">Logical Threads</span><span class="font-mono text-emerald-400 font-semibold">${sys.cpu_logical_cores}</span></div>
                        <div class="flex justify-between border-b border-slate-800 pb-2"><span class="text-slate-400">System Boot Time</span><span class="font-mono text-slate-300">${sys.boot_time}</span></div>
                    </div>
                `;
            }
        }

        // Render initial threats
        if (data.security) {
            renderThreatsView({
                threats: data.security.threats,
                threat_count: data.security.threat_count,
                recommendations: data.security.recommendations,
                health: data.security.health
            });
        }
    } catch (e) {
        console.error("Failed to load initial summary:", e);
    }
}

function handleLiveMetrics(metrics, security) {
    if (!metrics) return;

    // 1. Update Real-Time Charts
    updateChartsWithSnapshot(metrics);

    // 2. Health Score Radial Gauge & Status
    if (security && security.health) {
        const h = security.health;
        const scoreVal = h.score;
        const circle = document.getElementById('healthCircleGauge');
        const scoreElem = document.getElementById('healthScoreVal');
        const gradeElem = document.getElementById('healthGradeVal');
        const statusElem = document.getElementById('healthStatusText');

        if (scoreElem) scoreElem.innerText = `${scoreVal}%`;
        if (gradeElem) gradeElem.innerText = h.grade;
        if (statusElem) {
            statusElem.innerText = h.status;
            statusElem.style.color = h.color;
        }

        if (circle) {
            const circumference = 2 * Math.PI * 45; // r=45
            const offset = circumference - (scoreVal / 100) * circumference;
            circle.style.strokeDashoffset = offset;
            circle.style.stroke = h.color;
        }

        // Audio Alert on new threats
        if (security.threat_count > lastKnownThreatCount && lastKnownThreatCount !== 0) {
            playAlertSound();
            showNotification(`SECURITY ALERT: ${security.threat_count} threat indicators detected!`, 'error');
        }
        lastKnownThreatCount = security.threat_count;
    }

    // 3. CPU Card & Per-Core Heatmap
    const cpu = metrics.cpu;
    if (cpu) {
        document.getElementById('cpuTotalPercent').innerText = `${cpu.overall_percent}%`;
        document.getElementById('cpuFreqVal').innerText = cpu.current_freq_mhz > 0 ? `${cpu.current_freq_mhz} MHz` : 'Dynamic';
        const cpuBar = document.getElementById('cpuTotalBar');
        if (cpuBar) {
            cpuBar.style.width = `${cpu.overall_percent}%`;
            cpuBar.style.backgroundColor = cpu.overall_percent > 85 ? '#f43f5e' : (cpu.overall_percent > 60 ? '#f59e0b' : '#00f2fe');
        }

        // Render Per-Core Heat Bars
        const coreGrid = document.getElementById('cpuCoreGrid');
        if (coreGrid && cpu.per_core_percent) {
            coreGrid.innerHTML = cpu.per_core_percent.map((pct, idx) => {
                const color = pct > 85 ? '#f43f5e' : (pct > 60 ? '#f59e0b' : '#38bdf8');
                return `
                    <div class="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
                        <div class="flex justify-between text-[11px] mb-1">
                            <span class="text-slate-400">Core ${idx}</span>
                            <span class="font-mono font-semibold" style="color: ${color}">${pct}%</span>
                        </div>
                        <div class="metric-bar-bg">
                            <div class="metric-bar-fill" style="width: ${pct}%; background: ${color}"></div>
                        </div>
                    </div>
                `;
            }).join('');
        }
    }

    // 4. Memory Card
    const mem = metrics.memory;
    if (mem && mem.ram) {
        document.getElementById('ramPercentVal').innerText = `${mem.ram.percent}%`;
        document.getElementById('ramUsageText').innerText = `${mem.ram.used_gb} / ${mem.ram.total_gb} GB`;
        const ramBar = document.getElementById('ramTotalBar');
        if (ramBar) {
            ramBar.style.width = `${mem.ram.percent}%`;
            ramBar.style.backgroundColor = mem.ram.percent > 85 ? '#f43f5e' : (mem.ram.percent > 70 ? '#f59e0b' : '#a855f7');
        }

        if (mem.swap) {
            document.getElementById('swapUsageText').innerText = `Swap: ${mem.swap.used_gb} / ${mem.swap.total_gb} GB (${mem.swap.percent}%)`;
        }
    }

    // 5. Disk Card & Partitions
    const disk = metrics.disk;
    if (disk) {
        document.getElementById('diskReadSpeed').innerText = `${disk.read_speed_mb_s} MB/s`;
        document.getElementById('diskWriteSpeed').innerText = `${disk.write_speed_mb_s} MB/s`;

        // Render partition bars
        const partContainer = document.getElementById('partitionsContainer');
        if (partContainer && disk.partitions) {
            partContainer.innerHTML = disk.partitions.map(p => {
                const fillCol = p.percent > 90 ? '#f43f5e' : (p.percent > 75 ? '#f59e0b' : '#10b981');
                return `
                    <div class="space-y-1 text-xs">
                        <div class="flex justify-between text-slate-300">
                            <span><strong class="text-sky-400">${p.mountpoint}</strong> (${p.fstype})</span>
                            <span class="font-mono">${p.used_gb} GB / ${p.total_gb} GB <strong class="text-slate-100">(${p.percent}%)</strong></span>
                        </div>
                        <div class="metric-bar-bg">
                            <div class="metric-bar-fill" style="width: ${p.percent}%; background: ${fillCol}"></div>
                        </div>
                    </div>
                `;
            }).join('');
        }
    }

    // 6. Network Card
    const net = metrics.network;
    if (net) {
        document.getElementById('netDownSpeed').innerText = `${net.download_kb_s} KB/s`;
        document.getElementById('netUpSpeed').innerText = `${net.upload_kb_s} KB/s`;
        const totalGB = ((net.bytes_sent + net.bytes_recv) / (1024**3)).toFixed(2);
        document.getElementById('netTotalTransfer').innerText = `Total Session I/O: ${totalGB} GB`;
    }

    // 7. Battery & Power
    const battery = metrics.battery;
    if (battery && battery.has_battery) {
        const batElem = document.getElementById('batteryStatusBadge');
        if (batElem) {
            batElem.classList.remove('hidden');
            batElem.innerText = `🔋 ${battery.percent}% ${battery.power_plugged ? '(Plugged In)' : '(Discharging)'}`;
        }
    }

    // 8. Live Uptime Clock
    if (metrics.uptime) {
        const upElem = document.getElementById('sysUptime');
        if (upElem) upElem.innerText = metrics.uptime.uptime_human;
    }
}

function setupEventListeners() {
    // Navigation Tabs
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            tabButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const tabName = btn.dataset.tab;
            document.querySelectorAll('.tab-content-panel').forEach(panel => {
                panel.classList.add('hidden');
            });
            const targetPanel = document.getElementById(`tab-${tabName}`);
            if (targetPanel) targetPanel.classList.remove('hidden');

            if (tabName === 'processes') {
                fetchProcesses();
            } else if (tabName === 'network') {
                fetchNetworkConnections();
            } else if (tabName === 'threats') {
                triggerManualScan();
            }
        });
    });

    // Process search input
    const searchInput = document.getElementById('processSearchInput');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            processSearchTerm = e.target.value;
            renderProcessesTable();
        });
    }

    // Process sort dropdown
    const sortSelect = document.getElementById('processSortSelect');
    if (sortSelect) {
        sortSelect.addEventListener('change', (e) => {
            currentSortBy = e.target.value;
            fetchProcesses();
        });
    }

    // Audio alerts toggle
    const audioToggle = document.getElementById('audioAlertToggle');
    if (audioToggle) {
        audioToggle.addEventListener('click', () => {
            audioAlertsEnabled = !audioAlertsEnabled;
            audioToggle.innerText = audioAlertsEnabled ? '🔊 Audio Alerts: ON' : '🔈 Audio Alerts: OFF';
            audioToggle.className = audioAlertsEnabled ? 'btn-cyber text-emerald-400 border-emerald-500/40' : 'btn-cyber';
            if (audioAlertsEnabled) playAlertSound();
        });
    }
}

async function fetchNetworkConnections() {
    const tbody = document.getElementById('networkTableBody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-slate-400">Enumerating active network sockets...</td></tr>`;

    try {
        const res = await fetch('/api/network/connections');
        const data = await res.json();
        const conns = data.connections || [];

        if (conns.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-slate-500">No active network connections found.</td></tr>`;
            return;
        }

        tbody.innerHTML = conns.map(c => `
            <tr class="border-b border-slate-800/60 hover:bg-slate-800/40 transition">
                <td class="py-2 px-3 font-mono text-xs text-sky-400">${c.pid || '--'}</td>
                <td class="py-2 px-3 text-xs font-semibold text-slate-200">${escapeHtml(c.process_name)}</td>
                <td class="py-2 px-3 text-xs font-mono text-slate-300">${escapeHtml(c.local_addr || '*')}</td>
                <td class="py-2 px-3 text-xs font-mono text-amber-300">${escapeHtml(c.remote_addr || '*')}</td>
                <td class="py-2 px-3 text-xs">
                    <span class="px-2 py-0.5 rounded text-[11px] font-semibold ${c.status === 'ESTABLISHED' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-400'}">
                        ${c.status}
                    </span>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-rose-400">Failed to load network sockets.</td></tr>`;
    }
}

async function downloadReport() {
    try {
        const res = await fetch('/api/report');
        const data = await res.json();
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `OSGuardian_Report_${Date.now()}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
        showNotification("Diagnostic Health Report downloaded successfully!", "success");
    } catch (e) {
        showNotification("Failed to export report: " + e.message, "error");
    }
}

function playAlertSound() {
    try {
        if (!audioCtx) {
            audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        }
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.type = 'sine';
        osc.frequency.setValueAtTime(880, audioCtx.currentTime); // A5
        osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.25);
        gain.gain.setValueAtTime(0.2, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.25);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.25);
    } catch (e) {
        // audio context blocked until user gesture
    }
}

function showNotification(msg, type = 'info') {
    const toast = document.createElement('div');
    const bgCol = type === 'success' ? 'bg-emerald-600' : (type === 'error' ? 'bg-rose-600' : (type === 'warning' ? 'bg-amber-600' : 'bg-sky-600'));
    toast.className = `fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded-lg text-white font-medium text-xs shadow-xl transition-all duration-300 transform translate-y-4 opacity-0 ${bgCol}`;
    toast.innerText = msg;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.remove('translate-y-4', 'opacity-0');
    }, 10);

    setTimeout(() => {
        toast.classList.add('opacity-0', 'translate-y-4');
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.add('hidden');
}
