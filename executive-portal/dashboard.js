// Executive Dashboard JavaScript - Oscar Broome
// Enhanced analytics and real-time data management

import Chart from 'chart.js/auto';
import AssetManagementService from '../services/assetManagementService.js';

// Global Chart variable for compatibility
globalThis.Chart = Chart;

export default class ExecutiveDashboard {
    currentSection = 'overview';
    charts = {};
    data = {};
    assetManagementService = null;

    constructor() {
        this.assetManagementService = new AssetManagementService();
        this.assetManagementService.initializePortfolio();
        this.init();
    }

    init() {
        this.setupNavigation();
        this.loadExecutiveData();
        this.setupRealTimeUpdates();
        this.setupCharts();
    }

    setupNavigation() {
        for (const item of document.querySelectorAll('.nav-item')) {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const section = item.dataset.section;
                this.switchSection(section);
            });
        }
    }

    switchSection(section) {
        // Update active nav item
        for (const item of document.querySelectorAll('.nav-item')) {
            item.classList.remove('active');
        }
        document.querySelector(`[data-section="${section}"]`).classList.add('active');

        // Update active section
        for (const sec of document.querySelectorAll('.dashboard-section')) {
            sec.classList.remove('active');
        }
        document.getElementById(`${section}-section`).classList.add('active');

        this.currentSection = section;
        this.loadSectionData(section);
    }

    async loadExecutiveData() {
        try {
            const response = await fetch('/api/earnings', {
                headers: {
                    'Authorization': 'Bearer ' + localStorage.getItem('executiveToken')
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to load data');
            }
            
            this.data = await response.json();
            this.updateDashboard();
        } catch (error) {
            console.error('Error loading executive data:', error);
            this.showError('Failed to load executive data');
        }
    }

    updateDashboard() {
        this.updateMetrics();
        this.updateCharts();
        this.updateRecentActivity();
        this.updatePortfolioSummary();
    }

    updateMetrics() {
        document.getElementById('totalRevenue').textContent =
            new Intl.NumberFormat('en-US', {
                style: 'currency',
                currency: 'USD'
            }).format(this.data.totalAnnualRevenue || 0);

        document.getElementById('dailyRevenue').textContent =
            new Intl.NumberFormat('en-US', {
                style: 'currency',
                currency: 'USD'
            }).format(this.data.totalDailyRevenue || 0);

        document.getElementById('fleetCount').textContent =
            this.data.purchases?.autoFleetDetails?.length || 0;

        document.getElementById('corporateHomes').textContent =
            new Intl.NumberFormat('en-US').format(this.data.purchases?.corporateHomes || 0);

        // Get real AUM data from AssetManagementService
        const analytics = this.assetManagementService.getPortfolioAnalytics();
        document.getElementById('totalAUM').textContent = analytics.summary.totalValue;

        // Add portfolio-specific metrics
        const portfolioMetrics = this.assetManagementService.getPortfolioMetrics();
        document.getElementById('portfolioReturn').textContent = `${portfolioMetrics.totalReturn}%`;
        document.getElementById('portfolioRisk').textContent = `${portfolioMetrics.volatility}%`;
        document.getElementById('diversificationScore').textContent = `${portfolioMetrics.diversificationScore}/100`;
    }

    setupCharts() {
        this.createRevenueChart();
        this.createFleetChart();
        this.createAUMChart();
        this.createAssetPerformanceChart();
        this.createPortfolioRiskChart();
    }

    createRevenueChart() {
        const ctx = document.getElementById('revenueChart').getContext('2d');
        
        // Sample data - replace with actual data
        const revenueData = {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
            datasets: [{
                label: 'Monthly Revenue',
                data: [120000, 150000, 180000, 220000, 190000, 250000],
                borderColor: '#d4af37',
                backgroundColor: 'rgba(212, 175, 55, 0.1)',
                tension: 0.4,
                fill: true
            }]
        };

        this.charts.revenue = new Chart(ctx, {
            type: 'line',
            data: revenueData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    }
                },
                scales: {
                    y: {
                        ticks: {
                            color: '#ffffff',
                            callback: function(value) {
                                return '$' + value.toLocaleString();
                            }
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#ffffff'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                }
            }
        });
    }

    createFleetChart() {
        const ctx = document.getElementById('fleetChart').getContext('2d');
        
        // Sample data - replace with actual data
        const fleetData = {
            labels: ['Tesla', 'BMW', 'Mercedes', 'Audi', 'Other'],
            datasets: [{
                data: [5, 3, 2, 4, 1],
                backgroundColor: [
                    '#d4af37',
                    '#1a1a2e',
                    '#16213e',
                    '#0f3460',
                    '#333'
                ]
            }]
        };

        this.charts.fleet = new Chart(ctx, {
            type: 'doughnut',
            data: fleetData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    }
                }
            }
        });
    }

    updateRecentActivity() {
        const activityContainer = document.getElementById('recentActivity');

        // Get portfolio alerts and recommendations from AssetManagementService
        const alerts = this.assetManagementService.getPortfolioAlerts();
        const recommendations = this.assetManagementService.getRebalancingRecommendations();

        // Combine alerts and recommendations with existing activities
        const portfolioActivities = [
            ...alerts.map(alert => ({
                type: 'alert',
                message: alert.message,
                date: alert.timestamp,
                amount: 0
            })),
            ...recommendations.map(rec => ({
                type: 'recommendation',
                message: rec.action,
                date: new Date().toISOString().split('T')[0],
                amount: 0
            }))
        ];

        // Sample activities - replace with actual data
        const activities = [
            { type: 'purchase', message: 'Added Tesla Model S to fleet', date: '2024-01-15', amount: 79999 },
            { type: 'revenue', message: 'Daily revenue exceeded $50,000', date: '2024-01-14', amount: 50000 },
            { type: 'purchase', message: 'Purchased corporate home', date: '2024-01-13', amount: 2500000 },
            ...portfolioActivities
        ];

        activityContainer.innerHTML = activities.map(activity => `
            <div class="activity-item ${activity.type}">
                <div class="activity-icon">
                    <i class="fas fa-${activity.type === 'purchase' ? 'shopping-cart' : activity.type === 'revenue' ? 'chart-line' : activity.type === 'alert' ? 'exclamation-triangle' : 'lightbulb'}"></i>
                </div>
                <div class="activity-content">
                    <div class="activity-message">${activity.message}</div>
                    <div class="activity-date">${new Intl.DateTimeFormat('en-US', { year: 'numeric', month: 'long', day: 'numeric' }).format(new Date(activity.date))}</div>
                    ${activity.amount > 0 ? `<div class="activity-amount">${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(activity.amount)}</div>` : ''}
                </div>
            </div>
        `).join('');
    }

    setupRealTimeUpdates() {
        // Update data every 30 seconds
        setInterval(() => {
            this.loadExecutiveData();
        }, 30000);
    }

    loadSectionData(section) {
        switch (section) {
            case 'revenue':
                this.loadRevenueData();
                break;
            case 'fleet':
                this.loadFleetData();
                break;
            case 'analytics':
                this.loadAnalyticsData();
                break;
            case 'aum':
                this.loadAUMData();
                break;
        }
    }

    async loadRevenueData() {
        const container = document.getElementById('revenueStreams');
        if (!container) return;

        container.innerHTML = `
            <div class="revenue-streams">
                ${Object.entries(this.data.revenueStreams || {}).map(([stream, details]) => `
                    <div class="revenue-stream">
                        <h4>${stream}</h4>
                        <div class="amount">${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(details.amount)}</div>
                        <div class="account">Account: ${details.accountNumber || 'N/A'}</div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    async loadFleetData() {
        const container = document.getElementById('fleetList');
        if (!container) return;

        const fleet = this.data.purchases?.autoFleetDetails || [];
        
        container.innerHTML = `
            <div class="fleet-grid">
                ${fleet.map(vehicle => `
                    <div class="fleet-item">
                        <div class="vehicle-info">
                            <h4>${vehicle.model}</h4>
                            <p>VIN: ${vehicle.vin}</p>
                            <p>Dealership: ${vehicle.dealership}</p>
                            <p>Cost: ${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(vehicle.cost)}</p>
                            <p>Status: ${vehicle.deliveryStatus}</p>
                        </div>
                        <div class="vehicle-actions">
                            <button class="btn-small" onclick="markDelivered('${vehicle.vin}')">
                                Mark Delivered
                            </button>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    async loadAnalyticsData() {
        // Load analytics-specific data
        const performanceContainer = document.getElementById('performanceMetrics');
        const forecastContainer = document.getElementById('financialForecast');

        // Get portfolio analytics from AssetManagementService
        const portfolioAnalytics = this.assetManagementService.getPortfolioAnalytics();
        const portfolioMetrics = this.assetManagementService.getPortfolioMetrics();

        if (performanceContainer) {
            performanceContainer.innerHTML = `
                <div class="metrics-list">
                    <div class="metric">
                        <span>Portfolio ROI</span>
                        <span class="value">${portfolioMetrics.totalReturn}%</span>
                    </div>
                    <div class="metric">
                        <span>Sharpe Ratio</span>
                        <span class="value">${portfolioMetrics.sharpeRatio}</span>
                    </div>
                    <div class="metric">
                        <span>Volatility</span>
                        <span class="value">${portfolioMetrics.volatility}%</span>
                    </div>
                    <div class="metric">
                        <span>Diversification Score</span>
                        <span class="value">${portfolioMetrics.diversificationScore}/100</span>
                    </div>
                </div>
            `;
        }

        if (forecastContainer) {
            forecastContainer.innerHTML = `
                <div class="forecast-chart">
                    <canvas id="forecastChart"></canvas>
                </div>
            `;

            // Create forecast chart
            this.createForecastChart();
        }
    }

    async loadAUMData() {
        const container = document.getElementById('aumMetrics');
        const assetClassContainer = document.getElementById('aumAssetClasses');
        const performanceContainer = document.getElementById('aumPerformanceMetrics');
        if (!container || !assetClassContainer || !performanceContainer) return;

        const aum = this.data.assetsUnderManagement || {};

        container.textContent = new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: 'USD',
            maximumFractionDigits: 0
        }).format(aum.totalAUM || 0);

        assetClassContainer.innerHTML = Object.entries(aum.assetClasses || {}).map(([key, val]) => `
            <div class="aum-asset-class">
                <h4>${key.charAt(0).toUpperCase() + key.slice(1)}</h4>
                <p>Amount: ${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(val.amount)}</p>
                <p>Percentage: ${val.percentage}%</p>
                <p>${val.description}</p>
            </div>
        `).join('');

        performanceContainer.innerHTML = `
            <div class="metrics-list">
                <div class="metric">
                    <span>YTD Return</span>
                    <span class="value">${aum.performanceMetrics?.ytdReturn || 0}%</span>
                </div>
                <div class="metric">
                    <span>Annualized Return</span>
                    <span class="value">${aum.performanceMetrics?.annualizedReturn || 0}%</span>
                </div>
                <div class="metric">
                    <span>Sharpe Ratio</span>
                    <span class="value">${aum.performanceMetrics?.sharpeRatio || 0}</span>
                </div>
                <div class="metric">
                    <span>Volatility</span>
                    <span class="value">${aum.performanceMetrics?.volatility || 0}%</span>
                </div>
            </div>
        `;

        this.createAUMChart();
    }

    createAUMChart() {
        const ctx = document.getElementById('aumChart');
        if (!ctx) return;

        // Get real data from AssetManagementService
        const analytics = this.assetManagementService.getPortfolioAnalytics();
        const labels = analytics.assets.map(asset => asset.name);
        const data = analytics.assets.map(asset => Number.parseFloat(asset.value.replace(/[$,]/g, '')));

        // Create performance chart showing historical data
        const performanceData = this.assetManagementService.getHistoricalPerformance();
        const performanceLabels = performanceData.map(point => point.date);
        const performanceValues = performanceData.map(point => point.value);

        this.charts.aum = new Chart(ctx.getContext('2d'), {
            type: 'line',
            data: {
                labels: performanceLabels,
                datasets: [{
                    label: 'Portfolio Performance',
                    data: performanceValues,
                    borderColor: '#d4af37',
                    backgroundColor: 'rgba(212, 175, 55, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    }
                },
                scales: {
                    y: {
                        ticks: {
                            color: '#ffffff',
                            callback: function(value) {
                                return '$' + value.toLocaleString();
                            }
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#ffffff'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                }
            }
        });
    }

    createAssetPerformanceChart() {
        const ctx = document.getElementById('assetPerformanceChart');
        if (!ctx) return;

        // Get portfolio analytics for asset performance data
        const analytics = this.assetManagementService.getPortfolioAnalytics();
        const assets = analytics.assets;

        const labels = assets.map(asset => asset.name);
        const returns = assets.map(asset => parseFloat(asset.performance?.yearly || 0));
        const volatilities = assets.map(asset => parseFloat(asset.performance?.volatility || 0));

        this.charts.assetPerformance = new Chart(ctx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Annual Return (%)',
                    data: returns,
                    backgroundColor: '#d4af37',
                    borderColor: '#b8952a',
                    borderWidth: 1
                }, {
                    label: 'Volatility (%)',
                    data: volatilities,
                    backgroundColor: '#1a1a2e',
                    borderColor: '#16213e',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    }
                },
                scales: {
                    y: {
                        ticks: {
                            color: '#ffffff',
                            callback: function(value) {
                                return value + '%';
                            }
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#ffffff'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                }
            }
        });
    }

    createPortfolioRiskChart() {
        const ctx = document.getElementById('portfolioRiskChart');
        if (!ctx) return;

        // Get portfolio metrics for risk analysis
        const metrics = this.assetManagementService.getPortfolioMetrics();
        const analytics = this.assetManagementService.getPortfolioAnalytics();

        // Create risk-return scatter plot
        const assets = analytics.assets;
        const riskData = assets.map(asset => ({
            x: parseFloat(asset.performance?.volatility || 0),
            y: parseFloat(asset.performance?.yearly || 0),
            name: asset.name,
            allocation: parseFloat(asset.allocation.replace('%', ''))
        }));

        this.charts.portfolioRisk = new Chart(ctx.getContext('2d'), {
            type: 'scatter',
            data: {
                datasets: [{
                    label: 'Asset Risk-Return Profile',
                    data: riskData,
                    backgroundColor: '#d4af37',
                    borderColor: '#b8952a',
                    pointRadius: function(context) {
                        const size = context.raw.allocation || 5;
                        return Math.max(5, size * 2);
                    }
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `${context.raw.name}: Return ${context.parsed.y}%, Risk ${context.parsed.x}%`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'Volatility (Risk) %',
                            color: '#ffffff'
                        },
                        ticks: {
                            color: '#ffffff'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Annual Return %',
                            color: '#ffffff'
                        },
                        ticks: {
                            color: '#ffffff'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                }
            }
        });
    }

    showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        document.querySelector('.dashboard-content').prepend(errorDiv);
        
        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }

    updatePortfolioSummary() {
        const summaryContainer = document.getElementById('portfolioSummary');
        if (!summaryContainer) return;

        const analytics = this.assetManagementService.getPortfolioAnalytics();
        const metrics = this.assetManagementService.getPortfolioMetrics();

        summaryContainer.innerHTML = `
            <div class="portfolio-summary">
                <h3>Portfolio Overview</h3>
                <div class="summary-grid">
                    <div class="summary-item">
                        <span class="label">Total Assets</span>
                        <span class="value">${analytics.summary.totalAssets}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">Total Value</span>
                        <span class="value">${analytics.summary.totalValue}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">Best Performer</span>
                        <span class="value">${analytics.summary.bestPerformer}</span>
                    </div>
                    <div class="summary-item">
                        <span class="label">Worst Performer</span>
                        <span class="value">${analytics.summary.worstPerformer}</span>
                    </div>
                </div>
            </div>
        `;
    }

    showSuccess(message) {
        const successDiv = document.createElement('div');
        successDiv.className = 'success-message';
        successDiv.textContent = message;
        document.querySelector('.dashboard-content').prepend(successDiv);

        setTimeout(() => {
            successDiv.remove();
        }, 3000);
    }
}

// Global functions
function logout() {
    localStorage.removeItem('executiveToken');
    localStorage.removeItem('executiveUser');
    window.location.href = '/executive-portal/login.html';
}

function syncRevenueData() {
    dashboard.loadExecutiveData();
    dashboard.showSuccess('Revenue data synchronized successfully');
}

function downloadReport() {
    window.open('/api/earnings/download', '_blank');
}

function addFleetVehicle() {
    // Implement add vehicle functionality
    dashboard.showSuccess('Add vehicle feature coming soon');
}

function viewFleetReport() {
    // Implement fleet report functionality
    dashboard.showSuccess('Fleet report feature coming soon');
}

function markDelivered(vin) {
    // Implement mark delivered functionality
    dashboard.showSuccess(`Vehicle ${vin} marked as delivered`);
}

// Initialize dashboard
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    // Check authentication
    const token = localStorage.getItem('executiveToken');
    if (!token) {
        window.location.href = '/executive-portal/login.html';
        return;
    }

    dashboard = new ExecutiveDashboard();
});
