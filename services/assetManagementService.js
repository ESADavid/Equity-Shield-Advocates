/**
 * ASSET MANAGEMENT SERVICE
 * Manages investment assets, portfolio analytics, and wealth optimization
 * Provides comprehensive asset tracking and performance analysis
 */

import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class AssetManagementService {
  constructor() {
    this.portfolio = new Map();
    this.assetClasses = new Map();
    this.performanceHistory = new Map();
    this.riskMetrics = new Map();
    this.marketData = new Map();
    this.rebalancingRules = new Map();
  }

  /**
   * Initialize asset portfolio
   * @param {Array} portfolioData - Array of portfolio assets
   */
  initializePortfolio(portfolioData = []) {
    // Default portfolio if none provided
    const defaultPortfolio = [
      {
        id: 'us-equities',
        name: 'US Large Cap Equities',
        type: 'equity',
        region: 'US',
        value: 25000000,
        currency: 'USD',
        allocation: 0.35,
        benchmark: 'S&P 500',
        holdings: [
          { symbol: 'AAPL', shares: 50000, price: 150, value: 7500000 },
          { symbol: 'MSFT', shares: 30000, price: 200, value: 6000000 },
          { symbol: 'GOOGL', shares: 15000, price: 200, value: 3000000 }
        ],
        performance: {
          daily: 0.012,
          weekly: 0.034,
          monthly: 0.045,
          quarterly: 0.089,
          yearly: 0.128,
          volatility: 0.18,
          sharpeRatio: 0.71
        }
      },
      {
        id: 'international-equities',
        name: 'International Equities',
        type: 'equity',
        region: 'International',
        value: 15000000,
        currency: 'USD',
        allocation: 0.20,
        benchmark: 'MSCI World ex-US',
        holdings: [
          { symbol: 'TSM', shares: 20000, price: 80, value: 1600000 },
          { symbol: 'ASML.AS', shares: 5000, price: 400, value: 2000000 }
        ],
        performance: {
          daily: .008,
          weekly: .022,
          monthly: .031,
          quarterly: .065,
          yearly: .095,
          volatility: .22,
          sharpeRatio: .43
        }
      },
      {
        id: 'fixed-income',
        name: 'Fixed Income Portfolio',
        type: 'fixed_income',
        region: 'Global',
        value: 20000000,
        currency: 'USD',
        allocation: 0.25,
        benchmark: 'Bloomberg Barclays Global Aggregate',
        holdings: [
          { name: 'US Treasury 10Y', value: 10000000, yield: .045, duration: 8.5 },
          { name: 'US Treasury 30Y', value: 5000000, yield: .048, duration: 18.2 },
          { name: 'Corporate Bonds', value: 5000000, yield: .038, duration: 6.8 }
        ],
        performance: {
          daily: .003,
          weekly: .008,
          monthly: .012,
          quarterly: .028,
          yearly: .042,
          volatility: .08,
          sharpeRatio: .53
        }
      },
      {
        id: 'alternative-investments',
        name: 'Alternative Investments',
        type: 'alternative',
        region: 'Global',
        value: 10000000,
        currency: 'USD',
        allocation: .12,
        benchmark: 'HFRX Global Hedge Fund Index',
        holdings: [
          { name: 'Private Equity Fund A', value: 4000000, vintage: 2020 },
          { name: 'Real Estate Fund', value: 3000000, vintage: 2021 },
          { name: 'Infrastructure Fund', value: 3000000, vintage: 2019 }
        ],
        performance: {
          daily: .005,
          weekly: .015,
          monthly: .025,
          quarterly: .045,
          yearly: .089,
          volatility: .15,
          sharpeRatio: .59
        }
      },
      {
        id: 'cash-equivalents',
        name: 'Cash & Cash Equivalents',
        type: 'cash',
        region: 'US',
        value: 5000000,
        currency: 'USD',
        allocation: 0.08,
        benchmark: '3-Month T-Bill',
        holdings: [
          { name: 'Money Market Fund', value: 3000000, yield: .052 },
          { name: 'Commercial Paper', value: 2000000, yield: .048 }
        ],
        performance: {
          daily: .001,
          weekly: .003,
          monthly: .005,
          quarterly: .012,
          yearly: .025,
          volatility: .02,
          sharpeRatio: 1.25
        }
      }
    ];

    const portfolioToInitialize = portfolioData.length > 0 ? portfolioData : defaultPortfolio;

    for (const asset of portfolioToInitialize) {
      this.portfolio.set(asset.id, {
        ...asset,
        lastUpdated: new Date().toISOString(),
        createdAt: new Date().toISOString()
      });

      // Initialize performance history
      this.performanceHistory.set(asset.id, []);
    }

    console.log(`Initialized portfolio with ${portfolioToInitialize.length} asset classes`);
  }

  /**
   * Get complete portfolio
   * @returns {Array} Array of portfolio assets
   */
  getPortfolio() {
    return Array.from(this.portfolio.values()).map(asset => ({
      ...asset,
      value: this.formatCurrency(asset.value, asset.currency),
      allocation: (asset.allocation * 100).toFixed(2) + '%'
    }));
  }

  /**
   * Get asset by ID
   * @param {string} assetId - Asset ID
   * @returns {Object|null} Asset object or null
   */
  getAsset(assetId) {
    const asset = this.portfolio.get(assetId);
    if (!asset) return null;

    return {
      ...asset,
      value: this.formatCurrency(asset.value, asset.currency),
      allocation: (asset.allocation * 100).toFixed(2) + '%'
    };
  }

  /**
   * Update asset value and performance
   * @param {string} assetId - Asset ID
   * @param {number} newValue - New asset value
   * @param {Object} performanceData - Performance metrics
   * @returns {Object} Update result
   */
  updateAsset(assetId, newValue, performanceData = {}) {
    const asset = this.portfolio.get(assetId);
    if (!asset) {
      return { success: false, error: 'Asset not found' };
    }

    const oldValue = asset.value;
    const change = newValue - oldValue;
    const changePercent = oldValue > 0 ? (change / oldValue) * 100 : 0;

    asset.value = newValue;
    asset.lastUpdated = new Date().toISOString();

    // Update performance data
    if (performanceData && Object.keys(performanceData).length > 0) {
      asset.performance = { ...asset.performance, ...performanceData };
    }

    // Record performance history
    const historyEntry = {
      timestamp: new Date().toISOString(),
      value: newValue,
      change: change,
      changePercent: changePercent,
      performance: { ...asset.performance }
    };

    const history = this.performanceHistory.get(assetId) || [];
    history.push(historyEntry);

    // Keep only last 1000 entries
    this.performanceHistory.set(assetId, history.slice(-1000));

    return {
      success: true,
      asset: this.getAsset(assetId),
      oldValue: this.formatCurrency(oldValue, asset.currency),
      newValue: this.formatCurrency(newValue, asset.currency),
      change: this.formatCurrency(change, asset.currency),
      changePercent: changePercent.toFixed(2) + '%'
    };
  }

  /**
   * Get portfolio analytics
   * @returns {Object} Portfolio analytics
   */
  getPortfolioAnalytics() {
    const assets = Array.from(this.portfolio.values());
    const totalValue = assets.reduce((sum, asset) => sum + asset.value, 0);

    // Calculate weighted performance metrics
    const weightedReturn = assets.reduce((sum, asset) => {
      return sum + (asset.performance?.yearly || 0) * asset.allocation;
    }, 0);

    const weightedVolatility = assets.reduce((sum, asset) => {
      return sum + (asset.performance?.volatility || 0) * asset.allocation;
    }, 0);

    const weightedSharpe = assets.reduce((sum, asset) => {
      return sum + (asset.performance?.sharpeRatio || 0) * asset.allocation;
    }, 0);

    // Asset allocation analysis
    const allocationByType = {};
    const allocationByRegion = {};

    for (const asset of assets) {
      // By type
      if (!allocationByType[asset.type]) {
        allocationByType[asset.type] = { value: 0, percentage: 0 };
      }
      allocationByType[asset.type].value += asset.value;
      allocationByType[asset.type].percentage += asset.allocation;

      // By region
      if (!allocationByRegion[asset.region]) {
        allocationByRegion[asset.region] = { value: 0, percentage: 0 };
      }
      allocationByRegion[asset.region].value += asset.value;
      allocationByRegion[asset.region].percentage += asset.allocation;
    }

    // Risk metrics
    const riskMetrics = {
      totalValue: this.formatCurrency(totalValue, 'USD'),
      totalReturn: (weightedReturn * 100).toFixed(2) + '%',
      volatility: (weightedVolatility * 100).toFixed(2) + '%',
      sharpeRatio: weightedSharpe.toFixed(2),
      diversificationRatio: this.calculateDiversificationRatio(assets),
      maxDrawdown: this.calculateMaxDrawdown(),
      valueAtRisk: this.calculateVaR(assets)
    };

    return {
      summary: riskMetrics,
      allocationByType,
      allocationByRegion,
      assets: assets.map(asset => ({
        id: asset.id,
        name: asset.name,
        type: asset.type,
        region: asset.region,
        value: this.formatCurrency(asset.value, 'USD'),
        allocation: (asset.allocation * 100).toFixed(2) + '%',
        performance: asset.performance
      })),
      lastUpdated: new Date().toISOString()
    };
  }

  /**
   * Calculate diversification ratio
   * @param {Array} assets - Portfolio assets
   * @returns {number} Diversification ratio
   */
  calculateDiversificationRatio(assets) {
    if (assets.length === 0) return 0;

    const totalValue = assets.reduce((sum, asset) => sum + asset.value, 0);
    const weights = assets.map(asset => asset.value / totalValue);
    const herfindahlIndex = weights.reduce((sum, weight) => sum + weight * weight, 0);

    // Diversification ratio = 1 / sqrt(Herfindahl Index)
    return (1 / Math.sqrt(herfindahlIndex)).toFixed(2);
  }

  /**
   * Calculate maximum drawdown
   * @returns {string} Maximum drawdown percentage
   */
  calculateMaxDrawdown() {
    // Simplified calculation - in real implementation would use historical data
    const maxDrawdown = .15; // 15% example
    return (maxDrawdown * 100).toFixed(2) + '%';
  }

  /**
   * Calculate Value at Risk (VaR)
   * @param {Array} assets - Portfolio assets
   * @returns {string} VaR value
   */
  calculateVaR(assets) {
    const totalValue = assets.reduce((sum, asset) => sum + asset.value, 0);
    const portfolioVolatility = assets.reduce((sum, asset) => {
      return sum + (asset.performance?.volatility || 0) * asset.allocation;
    }, 0);

    // Simplified VaR calculation (95% confidence, 1-day)
    const var95 = totalValue * portfolioVolatility * 1.645; // 1.645 = 95% confidence z-score
    return this.formatCurrency(var95, 'USD');
  }

  /**
   * Get asset performance history
   * @param {string} assetId - Asset ID
   * @param {number} days - Number of days of history
   * @returns {Array} Performance history
   */
  getAssetHistory(assetId, days = 90) {
    const history = this.performanceHistory.get(assetId) || [];
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);

    return history
      .filter(entry => new Date(entry.timestamp) >= cutoffDate)
      .map(entry => ({
        ...entry,
        value: this.formatCurrency(entry.value, 'USD'),
        change: this.formatCurrency(entry.change, 'USD'),
        changePercent: entry.changePercent.toFixed(2) + '%'
      }));
  }

  /**
   * Rebalance portfolio
   * @param {Object} targetAllocations - Target allocation percentages
   * @returns {Object} Rebalancing result
   */
  rebalancePortfolio(targetAllocations) {
    const assets = Array.from(this.portfolio.values());
    const totalValue = assets.reduce((sum, asset) => sum + asset.value, 0);

    const rebalancingActions = [];
    let totalAdjustment = 0;

    for (const asset of assets) {
      const targetAllocation = targetAllocations[asset.id] || asset.allocation;
      const targetValue = totalValue * targetAllocation;
      const currentValue = asset.value;
      const adjustment = targetValue - currentValue;

      if (Math.abs(adjustment) > 1000) { // Only rebalance if difference > $1000
        rebalancingActions.push({
          assetId: asset.id,
          assetName: asset.name,
          currentValue: this.formatCurrency(currentValue, 'USD'),
          targetValue: this.formatCurrency(targetValue, 'USD'),
          adjustment: this.formatCurrency(adjustment, 'USD'),
          adjustmentPercent: ((adjustment / currentValue) * 100).toFixed(2) + '%'
        });

        totalAdjustment += Math.abs(adjustment);
      }
    }

    return {
      success: true,
      totalValue: this.formatCurrency(totalValue, 'USD'),
      rebalancingActions,
      totalAdjustment: this.formatCurrency(totalAdjustment, 'USD'),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Generate investment recommendations
   * @returns {Array} Investment recommendations
   */
  generateRecommendations() {
    const assets = Array.from(this.portfolio.values());
    const recommendations = [];

    for (const asset of assets) {
      const performance = asset.performance || {};

      // Check if asset is underperforming
      if (performance.yearly < .05) { // Less than 5% annual return
        recommendations.push({
          type: 'underperforming',
          assetId: asset.id,
          assetName: asset.name,
          currentReturn: (performance.yearly * 100).toFixed(2) + '%',
          recommendation: 'Consider reducing allocation or replacing with better performing asset',
          priority: 'medium'
        });
      }

      // Check volatility
      if (performance.volatility > .25) { // High volatility
        recommendations.push({
          type: 'high_volatility',
          assetId: asset.id,
          assetName: asset.name,
          volatility: (performance.volatility * 100).toFixed(2) + '%',
          recommendation: 'Consider hedging or reducing exposure to reduce portfolio risk',
          priority: 'high'
        });
      }

      // Check allocation vs target
      const targetAllocation = this.getTargetAllocation(asset.type);
      const allocationDiff = Math.abs(asset.allocation - targetAllocation);

      if (allocationDiff > .05) { // More than 5% deviation
        recommendations.push({
          type: 'allocation_drift',
          assetId: asset.id,
          assetName: asset.name,
          currentAllocation: (asset.allocation * 100).toFixed(2) + '%',
          targetAllocation: (targetAllocation * 100).toFixed(2) + '%',
          recommendation: 'Rebalance to maintain target allocation',
          priority: 'low'
        });
      }
    }

    return recommendations;
  }

  /**
   * Get target allocation for asset type
   * @param {string} assetType - Asset type
   * @returns {number} Target allocation percentage
   */
  getTargetAllocation(assetType) {
    const targets = {
      'equity': .55,
      'fixed_income': .30,
      'alternative': .1,
      'cash': .05
    };

    return targets[assetType] || .1;
  }

  /**
   * Update market data
   * @param {Object} marketData - Market data updates
   */
  updateMarketData(marketData) {
    for (const [symbol, data] of Object.entries(marketData)) {
      this.marketData.set(symbol, {
        ...data,
        lastUpdated: new Date().toISOString()
      });
    }
  }

  /**
   * Get market data
   * @param {string} symbol - Market symbol
   * @returns {Object|null} Market data or null
   */
  getMarketData(symbol) {
    return this.marketData.get(symbol) || null;
  }

  /**
   * Format currency value
   * @param {number} value - Numeric value
   * @param {string} currency - Currency code
   * @returns {string} Formatted currency string
   */
  formatCurrency(value, currency = 'USD') {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency
    }).format(value);
  }

  /**
   * Export asset management data
   * @returns {Object} Complete asset management data
   */
  exportAssetData() {
    return {
      portfolio: Array.from(this.portfolio.values()),
      performanceHistory: Object.fromEntries(this.performanceHistory),
      analytics: this.getPortfolioAnalytics(),
      recommendations: this.generateRecommendations(),
      marketData: Object.fromEntries(this.marketData),
      exportTimestamp: new Date().toISOString()
    };
  }

  /**
   * Get service health status
   * @returns {Object} Health status
   */
  getHealthStatus() {
    return {
      status: 'healthy',
      portfolioAssets: this.portfolio.size,
      performanceRecords: Array.from(this.performanceHistory.values())
        .reduce((sum, history) => sum + history.length, 0),
      marketDataPoints: this.marketData.size,
      lastUpdate: new Date().toISOString()
    };
  }
}

export default AssetManagementService;
