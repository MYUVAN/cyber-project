// Chart.js Theme Configurations for Cyberpunk Theme
const cyberColors = {
    cyan: '#00f0ff',
    green: '#39ff14',
    yellow: '#ffae00',
    orange: '#ff5f00',
    red: '#ff0055',
    grid: 'rgba(255, 255, 255, 0.08)',
    text: '#94a3b8'
};

Chart.defaults.color = cyberColors.text;
Chart.defaults.borderColor = cyberColors.grid;
Chart.defaults.font.family = "'Inter', sans-serif";

// Helper to init charts on Dashboard
function initDashboardCharts(data) {
    // 1. Risk Score Distribution (Doughnut)
    const ctxRisk = document.getElementById('riskDistributionChart');
    if (ctxRisk) {
        new Chart(ctxRisk, {
            type: 'doughnut',
            data: {
                labels: ['Low (0-30)', 'Medium (31-60)', 'High (61-80)', 'Critical (81-100)'],
                datasets: [{
                    data: [data.risk_counts.low, data.risk_counts.medium, data.risk_counts.high, data.risk_counts.critical],
                    backgroundColor: [
                        'rgba(57, 255, 20, 0.2)',
                        'rgba(255, 174, 0, 0.2)',
                        'rgba(255, 95, 0, 0.2)',
                        'rgba(255, 0, 85, 0.2)'
                    ],
                    borderColor: [
                        cyberColors.green,
                        cyberColors.yellow,
                        cyberColors.orange,
                        cyberColors.red
                    ],
                    borderWidth: 1.5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    }

    // 2. Malware Category Distribution (Horizontal Bar)
    const ctxCategory = document.getElementById('categoryDistributionChart');
    if (ctxCategory) {
        new Chart(ctxCategory, {
            type: 'bar',
            data: {
                labels: Object.keys(data.category_counts),
                datasets: [{
                    label: 'Files Analyzed',
                    data: Object.values(data.category_counts),
                    backgroundColor: 'rgba(0, 240, 255, 0.2)',
                    borderColor: cyberColors.cyan,
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { grid: { color: cyberColors.grid }, ticks: { stepSize: 1 } },
                    y: { grid: { display: false } }
                }
            }
        });
    }

    // 3. IOC Type Count (Vertical Bar)
    const ctxIOC = document.getElementById('iocCountChart');
    if (ctxIOC) {
        new Chart(ctxIOC, {
            type: 'bar',
            data: {
                labels: ['IPs', 'Domains', 'URLs', 'Emails'],
                datasets: [{
                    data: [data.ioc_counts.IP || 0, data.ioc_counts.Domain || 0, data.ioc_counts.URL || 0, data.ioc_counts.Email || 0],
                    backgroundColor: [
                        'rgba(0, 240, 255, 0.2)',
                        'rgba(57, 255, 20, 0.2)',
                        'rgba(255, 174, 0, 0.2)',
                        'rgba(255, 0, 85, 0.2)'
                    ],
                    borderColor: [
                        cyberColors.cyan,
                        cyberColors.green,
                        cyberColors.yellow,
                        cyberColors.red
                    ],
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { grid: { display: false } },
                    y: { grid: { color: cyberColors.grid }, ticks: { stepSize: 1 } }
                }
            }
        });
    }

    // 4. MITRE ATT&CK Technique Prevalence (Polar Area)
    const ctxMitre = document.getElementById('mitrePrevalenceChart');
    if (ctxMitre) {
        const labels = Object.keys(data.mitre_counts);
        const counts = Object.values(data.mitre_counts);
        
        new Chart(ctxMitre, {
            type: 'polarArea',
            data: {
                labels: labels.length > 0 ? labels : ['No Techniques Mapped'],
                datasets: [{
                    data: counts.length > 0 ? counts : [0],
                    backgroundColor: [
                        'rgba(255, 0, 85, 0.2)',
                        'rgba(0, 240, 255, 0.2)',
                        'rgba(255, 174, 0, 0.2)',
                        'rgba(57, 255, 20, 0.2)',
                        'rgba(168, 85, 247, 0.2)'
                    ],
                    borderColor: [
                        cyberColors.red,
                        cyberColors.cyan,
                        cyberColors.yellow,
                        cyberColors.green,
                        '#a855f7'
                    ],
                    borderWidth: 1.5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                },
                scales: {
                    r: {
                        grid: { color: cyberColors.grid },
                        angleLines: { color: cyberColors.grid },
                        ticks: { backdropColor: 'transparent', stepSize: 1 }
                    }
                }
            }
        });
    }
}

// Helper to init half-doughnut threat gauge on Analysis page
function initThreatGauge(score) {
    const ctxGauge = document.getElementById('threatGaugeChart');
    if (ctxGauge) {
        let gaugeColor = cyberColors.green;
        let gaugeBg = 'rgba(57, 255, 20, 0.15)';
        
        if (score > 80) {
            gaugeColor = cyberColors.red;
            gaugeBg = 'rgba(255, 0, 85, 0.15)';
        } else if (score > 60) {
            gaugeColor = cyberColors.orange;
            gaugeBg = 'rgba(255, 95, 0, 0.15)';
        } else if (score > 30) {
            gaugeColor = cyberColors.yellow;
            gaugeBg = 'rgba(255, 174, 0, 0.15)';
        }
        
        new Chart(ctxGauge, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [gaugeColor, 'rgba(255,255,255,0.03)'],
                    borderWidth: 0,
                    borderRadius: score === 100 ? [20, 20] : [20, 0]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                circumference: 180,
                rotation: -90,
                cutout: '82%',
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false }
                }
            }
        });
    }
}
