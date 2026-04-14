const logger = require('../config/logger');

class EnhancedMLService {
  constructor() {
    this.rules = {
      revenue: {
        threshold: 10000,
        growth: 0.05,
      },
      risk: {
        high: 0.8,
        medium: 0.5,
        low: 0.2,
      },
    };
  }

  predictRevenue(data) {
    logger.info('Using rule-based revenue prediction');
    const baseRevenue = data.currentRevenue || 0;
    const growthFactor =
      baseRevenue > this.rules.revenue.threshold
        ? this.rules.revenue.growth
        : 0.02;
    return baseRevenue * (1 + growthFactor);
  }

  classifyRisk(data) {
    logger.info('Using rule-based risk classification');
    const score = data.score || 0;
    if (score > this.rules.risk.high) return 'high';
    if (score > this.rules.risk.medium) return 'medium';
    return 'low';
  }

  optimizePortfolio(data) {
    logger.info('Using rule-based portfolio optimization');
    // Simple diversification rule
    const assets = data.assets || [];
    const total = assets.reduce((sum, asset) => sum + asset.value, 0);
    return assets.map((asset) => ({
      ...asset,
      allocation: total > 0 ? asset.value / total : 0,
    }));
  }
}

module.exports = new EnhancedMLService();
