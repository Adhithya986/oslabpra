// Real-time Chart.js controllers for OS Guardian
const MAX_DATA_POINTS = 30;

let cpuChart = null;
let memoryChart = null;
let networkChart = null;
let diskChart = null;

const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 400 },
    plugins: {
        legend: {
            display: true,
            labels: { color: '#94a3b8', font: { size: 11, family: 'inherit' }, boxWidth: 12 }
        },
        tooltip: {
            backgroundColor: 'rgba(15, 23, 42, 0.9)',
            titleColor: '#38bdf8',
            borderColor: 'rgba(56, 189, 248, 0.3)',
            borderWidth: 1,
            bodyColor: '#f8fafc',
            padding: 8
        }
    },
    scales: {
        x: {
            display: false,
            grid: { display: false }
        },
        y: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#64748b', font: { size: 10 } }
        }
    }
};

function initCharts() {
    const timeLabels = Array(MAX_DATA_POINTS).fill('');

    // CPU Chart
    const cpuCtx = document.getElementById('cpuChartCanvas')?.getContext('2d');
    if (cpuCtx) {
        cpuChart = new Chart(cpuCtx, {
            type: 'line',
            data: {
                labels: [...timeLabels],
                datasets: [{
                    label: 'CPU Usage %',
                    data: Array(MAX_DATA_POINTS).fill(0),
                    borderColor: '#00f2fe',
                    backgroundColor: 'rgba(0, 242, 254, 0.08)',
                    borderWidth: 2,
                    tension: 0.35,
                    fill: true,
                    pointRadius: 0
                }]
            },
            options: {
                ...chartOptions,
                scales: {
                    ...chartOptions.scales,
                    y: { ...chartOptions.scales.y, min: 0, max: 100 }
                }
            }
        });
    }

    // Memory Chart
    const memCtx = document.getElementById('memoryChartCanvas')?.getContext('2d');
    if (memCtx) {
        memoryChart = new Chart(memCtx, {
            type: 'line',
            data: {
                labels: [...timeLabels],
                datasets: [{
                    label: 'RAM Usage %',
                    data: Array(MAX_DATA_POINTS).fill(0),
                    borderColor: '#a855f7',
                    backgroundColor: 'rgba(168, 85, 247, 0.08)',
                    borderWidth: 2,
                    tension: 0.35,
                    fill: true,
                    pointRadius: 0
                }]
            },
            options: {
                ...chartOptions,
                scales: {
                    ...chartOptions.scales,
                    y: { ...chartOptions.scales.y, min: 0, max: 100 }
                }
            }
        });
    }

    // Network Chart
    const netCtx = document.getElementById('networkChartCanvas')?.getContext('2d');
    if (netCtx) {
        networkChart = new Chart(netCtx, {
            type: 'line',
            data: {
                labels: [...timeLabels],
                datasets: [
                    {
                        label: 'Download (KB/s)',
                        data: Array(MAX_DATA_POINTS).fill(0),
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.08)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0
                    },
                    {
                        label: 'Upload (KB/s)',
                        data: Array(MAX_DATA_POINTS).fill(0),
                        borderColor: '#f59e0b',
                        backgroundColor: 'rgba(245, 158, 11, 0.05)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0
                    }
                ]
            },
            options: chartOptions
        });
    }

    // Disk I/O Chart
    const diskCtx = document.getElementById('diskChartCanvas')?.getContext('2d');
    if (diskCtx) {
        diskChart = new Chart(diskCtx, {
            type: 'line',
            data: {
                labels: [...timeLabels],
                datasets: [
                    {
                        label: 'Read (MB/s)',
                        data: Array(MAX_DATA_POINTS).fill(0),
                        borderColor: '#38bdf8',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: false,
                        pointRadius: 0
                    },
                    {
                        label: 'Write (MB/s)',
                        data: Array(MAX_DATA_POINTS).fill(0),
                        borderColor: '#fb7185',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: false,
                        pointRadius: 0
                    }
                ]
            },
            options: chartOptions
        });
    }
}

function updateChartsWithSnapshot(metrics) {
    if (!metrics) return;

    // Update CPU Chart
    if (cpuChart) {
        const cpuData = cpuChart.data.datasets[0].data;
        cpuData.push(metrics.cpu.overall_percent);
        if (cpuData.length > MAX_DATA_POINTS) cpuData.shift();
        cpuChart.update('none');
    }

    // Update Memory Chart
    if (memoryChart) {
        const memData = memoryChart.data.datasets[0].data;
        memData.push(metrics.memory.ram.percent);
        if (memData.length > MAX_DATA_POINTS) memData.shift();
        memoryChart.update('none');
    }

    // Update Network Chart
    if (networkChart) {
        const downData = networkChart.data.datasets[0].data;
        const upData = networkChart.data.datasets[1].data;
        downData.push(metrics.network.download_kb_s);
        upData.push(metrics.network.upload_kb_s);
        if (downData.length > MAX_DATA_POINTS) downData.shift();
        if (upData.length > MAX_DATA_POINTS) upData.shift();
        networkChart.update('none');
    }

    // Update Disk Chart
    if (diskChart) {
        const readData = diskChart.data.datasets[0].data;
        const writeData = diskChart.data.datasets[1].data;
        readData.push(metrics.disk.read_speed_mb_s);
        writeData.push(metrics.disk.write_speed_mb_s);
        if (readData.length > MAX_DATA_POINTS) readData.shift();
        if (writeData.length > MAX_DATA_POINTS) writeData.shift();
        diskChart.update('none');
    }
}
