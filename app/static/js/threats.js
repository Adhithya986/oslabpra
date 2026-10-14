// Threat & Security Monitor Controller for OS Guardian

async function triggerManualScan() {
    const scanBtn = document.getElementById('manualScanBtn');
    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.innerHTML = `<span class="animate-spin inline-block mr-1">↻</span> Scanning System...`;
    }

    try {
        const res = await fetch('/api/threats/scan');
        const data = await res.json();
        renderThreatsView(data);
        showNotification(`Threat scan complete: ${data.threat_count} potential indicators found.`, data.threat_count > 0 ? 'warning' : 'success');
    } catch (err) {
        showNotification(`Threat scan failed: ${err.message}`, 'error');
    } finally {
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.innerHTML = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg> Run Deep Threat Scan`;
        }
    }
}

function renderThreatsView(threatData) {
    if (!threatData) return;

    // Render Threat Cards
    const container = document.getElementById('threatsListContainer');
    const badgeCount = document.getElementById('threatBadgeCount');
    const threats = threatData.threats || [];

    if (badgeCount) {
        badgeCount.innerText = threats.length;
        badgeCount.className = `px-2 py-0.5 rounded-full text-xs font-bold ${threats.length > 0 ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'}`;
    }

    if (container) {
        if (threats.length === 0) {
            container.innerHTML = `
                <div class="p-8 text-center bg-slate-900/40 rounded-xl border border-slate-800/80">
                    <div class="w-12 h-12 mx-auto mb-3 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                    </div>
                    <h4 class="text-base font-semibold text-slate-200 mb-1">System Integrity Clean</h4>
                    <p class="text-xs text-slate-400 max-w-md mx-auto">No rogue processes, masquerading binaries, unauthorized listeners, or cryptojacking signatures detected.</p>
                </div>
            `;
        } else {
            container.innerHTML = threats.map(t => {
                const sevColor = t.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
                                 t.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                                 'bg-sky-500/20 text-sky-300 border-sky-500/40';

                return `
                    <div class="p-4 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition flex flex-col md:flex-row md:items-center justify-between gap-4">
                        <div class="space-y-1">
                            <div class="flex items-center gap-2">
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase border ${sevColor}">${t.severity}</span>
                                <h5 class="text-sm font-bold text-slate-100">${escapeHtml(t.type)}</h5>
                                ${t.pid ? `<span class="text-xs font-mono text-sky-400 bg-sky-950/60 px-2 py-0.5 rounded border border-sky-800">PID: ${t.pid}</span>` : ''}
                            </div>
                            <p class="text-xs text-slate-300">${escapeHtml(t.details)}</p>
                            <p class="text-[11px] font-mono text-slate-400 truncate max-w-xl">Target: ${escapeHtml(t.path || t.name)}</p>
                        </div>
                        <div class="flex items-center gap-2 shrink-0">
                            ${t.pid ? `<button onclick="confirmKillProcess(${t.pid}, '${escapeHtml(t.name)}')" class="px-3 py-1.5 rounded text-xs bg-rose-600 hover:bg-rose-500 text-white font-medium shadow-sm transition">Terminate Process</button>` : ''}
                            <span class="text-xs px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300">${escapeHtml(t.action || 'Remediation Advised')}</span>
                        </div>
                    </div>
                `;
            }).join('');
        }
    }

    // Render Persistence Items
    const persistContainer = document.getElementById('persistenceListContainer');
    if (persistContainer && threatData.startup_items) {
        if (threatData.startup_items.length === 0) {
            persistContainer.innerHTML = `<div class="p-4 text-xs text-slate-400">No startup autorun entries found or non-Windows system.</div>`;
        } else {
            persistContainer.innerHTML = threatData.startup_items.map(item => `
                <div class="p-3 bg-slate-900/60 rounded-lg border ${item.is_suspicious ? 'border-amber-500/40 bg-amber-950/10' : 'border-slate-800/80'} text-xs flex justify-between items-center">
                    <div class="space-y-0.5 truncate mr-3">
                        <div class="flex items-center gap-2">
                            <span class="font-bold text-sky-300">${escapeHtml(item.name)}</span>
                            <span class="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-slate-400">${item.key}</span>
                            ${item.is_suspicious ? '<span class="text-[10px] bg-amber-500/20 text-amber-300 px-1.5 py-0.5 rounded border border-amber-500/30">WARNING</span>' : ''}
                        </div>
                        <div class="text-[11px] font-mono text-slate-400 truncate" title="${escapeHtml(item.command)}">${escapeHtml(item.command)}</div>
                    </div>
                </div>
            `).join('');
        }
    }

    // Render Recommendations
    const recContainer = document.getElementById('recommendationsContainer');
    if (recContainer && threatData.recommendations) {
        recContainer.innerHTML = threatData.recommendations.map(r => `
            <li class="flex items-start gap-2 text-xs text-slate-300">
                <span class="text-sky-400 mt-0.5">▸</span>
                <span>${escapeHtml(r)}</span>
            </li>
        `).join('');
    }
}
