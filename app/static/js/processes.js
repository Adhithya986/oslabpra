// Process Manager Controller for OS Guardian
let currentSortBy = 'cpu_percent';
let processSearchTerm = '';
let currentProcessList = [];

async function fetchProcesses() {
    try {
        const response = await fetch(`/api/processes?limit=100&sort_by=${currentSortBy}`);
        const data = await response.json();
        currentProcessList = data.processes || [];
        renderProcessesTable();
    } catch (err) {
        console.error("Failed to fetch processes:", err);
    }
}

function renderProcessesTable() {
    const tbody = document.getElementById('processesTableBody');
    if (!tbody) return;

    let filtered = currentProcessList.filter(p => {
        if (!processSearchTerm) return true;
        const term = processSearchTerm.toLowerCase();
        return (
            p.name.toLowerCase().includes(term) ||
            p.pid.toString().includes(term) ||
            (p.user && p.user.toLowerCase().includes(term))
        );
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-slate-400">No matching processes found</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(p => {
        const cpuColor = p.cpu_percent > 50 ? 'text-rose-400 font-bold' : (p.cpu_percent > 15 ? 'text-amber-400' : 'text-slate-200');
        const memColor = p.memory_mb > 1000 ? 'text-purple-400 font-bold' : 'text-slate-200';

        return `
            <tr class="border-b border-slate-800/60 hover:bg-slate-800/40 transition">
                <td class="py-2.5 px-3 font-mono text-xs text-sky-400 font-semibold">${p.pid}</td>
                <td class="py-2.5 px-3">
                    <div class="font-medium text-slate-100 text-sm flex items-center gap-2">
                        <span>${escapeHtml(p.name)}</span>
                        ${p.cpu_percent > 70 ? '<span class="px-1.5 py-0.5 text-[10px] bg-rose-500/20 text-rose-300 rounded border border-rose-500/30">HIGH CPU</span>' : ''}
                    </div>
                    <div class="text-[11px] text-slate-400 truncate max-w-xs" title="${escapeHtml(p.exe || '')}">${escapeHtml(p.exe || 'N/A')}</div>
                </td>
                <td class="py-2.5 px-3 text-xs text-slate-400">${escapeHtml(p.user || 'SYSTEM')}</td>
                <td class="py-2.5 px-3 text-xs font-mono ${cpuColor}">${p.cpu_percent}%</td>
                <td class="py-2.5 px-3 text-xs font-mono ${memColor}">${p.memory_mb} MB <span class="text-slate-500">(${p.memory_percent}%)</span></td>
                <td class="py-2.5 px-3 text-xs text-slate-400">${p.create_time || '--'}</td>
                <td class="py-2.5 px-3 text-right">
                    <button onclick="inspectProcess(${p.pid})" class="text-xs px-2.5 py-1 rounded bg-slate-700/60 hover:bg-slate-700 text-sky-300 mr-1.5 transition">Inspect</button>
                    <button onclick="confirmKillProcess(${p.pid}, '${escapeHtml(p.name)}')" class="text-xs px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/40 text-rose-300 border border-rose-500/30 transition">Kill</button>
                </td>
            </tr>
        `;
    }).join('');
}

async function inspectProcess(pid) {
    try {
        const modal = document.getElementById('processInspectModal');
        const content = document.getElementById('processInspectContent');
        if (!modal || !content) return;

        content.innerHTML = `<div class="p-6 text-center text-slate-400">Loading process telemetry for PID ${pid}...</div>`;
        modal.classList.remove('hidden');

        const res = await fetch(`/api/processes/${pid}`);
        const data = await res.json();

        if (data.error) {
            content.innerHTML = `<div class="p-6 text-rose-400">Error inspecting process: ${escapeHtml(data.error)}</div>`;
            return;
        }

        content.innerHTML = `
            <div class="space-y-4">
                <div class="flex items-center justify-between border-b border-slate-700/60 pb-3">
                    <div>
                        <h4 class="text-lg font-bold text-sky-400">${escapeHtml(data.name)} (PID: ${data.pid})</h4>
                        <p class="text-xs text-slate-400 font-mono">${escapeHtml(data.exe || 'Path unavailable')}</p>
                    </div>
                    <span class="px-2.5 py-1 rounded-full text-xs font-semibold uppercase ${data.status === 'running' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-700 text-slate-300'}">
                        ${data.status}
                    </span>
                </div>

                <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                    <div class="bg-slate-800/60 p-2.5 rounded-lg border border-slate-700/40">
                        <span class="text-slate-400 block mb-1">User</span>
                        <span class="font-semibold text-slate-200">${escapeHtml(data.username || 'N/A')}</span>
                    </div>
                    <div class="bg-slate-800/60 p-2.5 rounded-lg border border-slate-700/40">
                        <span class="text-slate-400 block mb-1">Memory (RSS)</span>
                        <span class="font-semibold text-purple-300">${data.memory_mb} MB</span>
                    </div>
                    <div class="bg-slate-800/60 p-2.5 rounded-lg border border-slate-700/40">
                        <span class="text-slate-400 block mb-1">Threads</span>
                        <span class="font-semibold text-slate-200">${data.num_threads}</span>
                    </div>
                    <div class="bg-slate-800/60 p-2.5 rounded-lg border border-slate-700/40">
                        <span class="text-slate-400 block mb-1">Started</span>
                        <span class="font-semibold text-slate-200">${data.create_time}</span>
                    </div>
                </div>

                <div>
                    <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">Command Line Arguments</span>
                    <pre class="bg-slate-900/90 p-2.5 rounded text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap border border-slate-800">${escapeHtml(data.cmdline || 'None')}</pre>
                </div>

                <div>
                    <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">Active Sockets / Connections (${data.connections ? data.connections.length : 0})</span>
                    <div class="max-h-36 overflow-y-auto bg-slate-900/80 rounded border border-slate-800 text-xs">
                        ${data.connections && data.connections.length > 0 ? `
                            <table class="w-full text-left font-mono">
                                <thead class="bg-slate-800 text-slate-400">
                                    <tr>
                                        <th class="p-1.5">Local</th>
                                        <th class="p-1.5">Remote</th>
                                        <th class="p-1.5">Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.connections.map(c => `
                                        <tr class="border-t border-slate-800/60">
                                            <td class="p-1.5 text-sky-300">${c.laddr || '*'}</td>
                                            <td class="p-1.5 text-amber-300">${c.raddr || '*'}</td>
                                            <td class="p-1.5 text-slate-400">${c.status}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        ` : '<div class="p-3 text-slate-500 italic">No open network connections.</div>'}
                    </div>
                </div>

                <div class="flex justify-end gap-2 pt-3 border-t border-slate-700/60">
                    <button onclick="closeModal('processInspectModal')" class="px-4 py-1.5 rounded text-xs bg-slate-700 hover:bg-slate-600 text-slate-200">Close</button>
                    <button onclick="closeModal('processInspectModal'); confirmKillProcess(${data.pid}, '${escapeHtml(data.name)}')" class="px-4 py-1.5 rounded text-xs bg-rose-600 hover:bg-rose-500 text-white font-medium">Terminate Process</button>
                </div>
            </div>
        `;
    } catch (e) {
        console.error("Inspect error:", e);
    }
}

function confirmKillProcess(pid, name) {
    if (confirm(`Are you sure you want to terminate process "${name}" (PID: ${pid})?`)) {
        killProcess(pid, false);
    }
}

async function killProcess(pid, force = false) {
    try {
        const res = await fetch(`/api/processes/${pid}/kill?force=${force}`, { method: 'POST' });
        const result = await res.json();
        if (result.success) {
            showNotification(`Process ${pid} terminated successfully!`, 'success');
            fetchProcesses();
        } else {
            showNotification(`Failed to terminate PID ${pid}: ${result.error}`, 'error');
        }
    } catch (err) {
        showNotification(`Error terminating PID ${pid}: ${err.message}`, 'error');
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
