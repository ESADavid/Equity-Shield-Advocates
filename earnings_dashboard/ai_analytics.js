import { transpose, multiply, inv } from 'mathjs';

// Enhanced historical data: last 24 months revenue with seasonal patterns
const historicalData = [
  1000000, 1050000, 1100000, 1080000, 1150000, 1200000, 1180000, 1250000,
  1300000, 1280000, 1350000, 1400000, 1420000, 1380000, 1450000, 1500000,
  1480000, 1550000, 1600000, 1580000, 1650000, 1700000, 1680000, 1750000,
];

// Risk factors and market conditions
const riskFactors = {
  marketVolatility: 0.15,
  economicIndicators: 0.12,
  competitivePressure: 0.08,
  regulatoryChanges: 0.05,
};

class AdvancedAnalytics {
  constructor() {
    this.models = {};
    this.predictions = {};
    this.alerts = [];
  }

  // Linear Regression Model
  trainLinearRegression() {
    if (this.models.linear) return this.models.linear;

    const X = historicalData.map((_, i) => [1, i]);
    const Y = historicalData.map((v) => [v]);

    const XT = transpose(X);
    const XTX = multiply(XT, X);
    const XTY = multiply(XT, Y);
    const beta = multiply(inv(XTX), XTY);

    this.models.linear = {
      intercept: beta[0][0],
      slope: beta[1][0],
      r2: this.calculateR2(X, Y, beta),
    };

    return this.models.linear;
  }

  // Seasonal ARIMA-like Model (simplified)
  trainSeasonalModel() {
    if (this.models.seasonal) return this.models.seasonal;

    const seasonalPeriod = 12; // Monthly seasonality
    const seasonalComponents = [];

    for (let i = 0; i < seasonalPeriod; i++) {
      const seasonalData = historicalData.filter(
        (_, idx) => idx % seasonalPeriod === i
      );
      const avg = seasonalData.reduce((a, b) => a + b, 0) / seasonalData.length;
      seasonalComponents.push(avg);
    }

    const overallMean =
      historicalData.reduce((a, b) => a + b, 0) / historicalData.length;
    const seasonalIndices = seasonalComponents.map(
      (comp) => comp / overallMean
    );

    this.models.seasonal = {
      period: seasonalPeriod,
      indices: seasonalIndices,
      mean: overallMean,
    };

    return this.models.seasonal;
  }

  // Advanced Anomaly Detection using Multiple Methods
  detectAnomalies(data = historicalData) {
    const anomalies = {
      statistical: this.statisticalAnomalyDetection(data),
      trend: this.trendAnomalyDetection(data),
      seasonal: this.seasonalAnomalyDetection(data),
      overall: false,
    };

    // Combine anomaly detection methods
    anomalies.overall =
      anomalies.statistical || anomalies.trend || anomalies.seasonal;

    return anomalies;
  }

  statisticalAnomalyDetection(data) {
    const mean = data.reduce((a, b) => a + b) / data.length;
    const variance =
      data.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / data.length;
    const stdDev = Math.sqrt(variance);

    const currentValue = data[data.length - 1];
    const zScore = Math.abs((currentValue - mean) / stdDev);

    return zScore > 3; // 3 standard deviations
  }

  trendAnomalyDetection(data) {
    const recent = data.slice(-3);
    const trend = recent
      .map((val, idx) => val - (idx > 0 ? recent[idx - 1] : 0))
      .slice(1);

    const avgTrend = trend.reduce((a, b) => a + b, 0) / trend.length;
    const currentTrend = recent[recent.length - 1] - recent[recent.length - 2];

    return Math.abs(currentTrend - avgTrend) > Math.abs(avgTrend) * 2;
  }

  seasonalAnomalyDetection(data) {
    if (!this.models.seasonal) this.trainSeasonalModel();

    const currentMonth = (data.length - 1) % 12;
    const expectedValue =
      this.models.seasonal.mean * this.models.seasonal.indices[currentMonth];
    const actualValue = data[data.length - 1];

    const deviation = Math.abs(actualValue - expectedValue) / expectedValue;
    return deviation > 0.15; // 15% deviation from seasonal expectation
  }

  // Multiple Prediction Methods
  generatePredictions(horizon = 6) {
    const predictions = {
      linear: this.predictLinear(horizon),
      seasonal: this.predictSeasonal(horizon),
      ensemble: this.predictEnsemble(horizon),
      confidence: this.calculateConfidenceIntervals(horizon),
    };

    return predictions;
  }

  predictLinear(months = 1) {
    if (!this.models.linear) this.trainLinearRegression();

    const predictions = [];
    for (let i = 1; i <= months; i++) {
      const monthIndex = historicalData.length + i - 1;
      const prediction =
        this.models.linear.intercept + this.models.linear.slope * monthIndex;
      predictions.push(Math.round(prediction));
    }

    return predictions;
  }

  predictSeasonal(months = 1) {
    if (!this.models.seasonal) this.trainSeasonalModel();

    const predictions = [];
    for (let i = 1; i <= months; i++) {
      const monthIndex = (historicalData.length + i - 1) % 12;
      const seasonalMultiplier = this.models.seasonal.indices[monthIndex];
      const basePrediction = this.models.seasonal.mean * seasonalMultiplier;

      // Add trend component
      const trendAdjustment = (i - 1) * 20000; // Simplified trend
      predictions.push(Math.round(basePrediction + trendAdjustment));
    }

    return predictions;
  }

  predictEnsemble(months = 1) {
    const linearPreds = this.predictLinear(months);
    const seasonalPreds = this.predictSeasonal(months);

    const ensemblePreds = linearPreds.map((linear, idx) => {
      const seasonal = seasonalPreds[idx];
      // Weighted average: 60% linear, 40% seasonal
      return Math.round(linear * 0.6 + seasonal * 0.4);
    });

    return ensemblePreds;
  }

  calculateConfidenceIntervals(months = 1) {
    const predictions = this.predictEnsemble(months);
    const intervals = [];

    for (let i = 0; i < months; i++) {
      const basePrediction = predictions[i];
      const uncertainty = basePrediction * 0.1; // 10% uncertainty

      intervals.push({
        lower: Math.round(basePrediction - uncertainty),
        upper: Math.round(basePrediction + uncertainty),
        confidence: 0.9,
      });
    }

    return intervals;
  }

  // Risk Assessment
  assessRisks() {
    this.calculateVolatility();

    const riskScore =
      Object.values(riskFactors).reduce((a, b) => a + b, 0) *
      this.calculateVolatility();

    return {
      overallRisk: riskScore,
      factors: riskFactors,
      volatility: this.calculateVolatility(),
      recommendations: this.generateRiskRecommendations(riskScore),
    };
  }

  calculateVolatility() {
    const returns = [];
    for (let i = 1; i < historicalData.length; i++) {
      const return_pct =
        (historicalData[i] - historicalData[i - 1]) / historicalData[i - 1];
      returns.push(return_pct);
    }

    const meanReturn = returns.reduce((a, b) => a + b, 0) / returns.length;
    const variance =
      returns.reduce((a, b) => a + Math.pow(b - meanReturn, 2), 0) /
      returns.length;

    return Math.sqrt(variance);
  }

  generateRiskRecommendations(riskScore) {
    const recommendations = [];

    if (riskScore > 0.3) {
      recommendations.push(
        'High risk detected - Consider diversifying revenue streams'
      );
      recommendations.push('Implement additional hedging strategies');
    } else if (riskScore > 0.2) {
      recommendations.push('Moderate risk - Monitor market conditions closely');
      recommendations.push('Review contingency plans');
    } else {
      recommendations.push(
        'Risk levels acceptable - Continue current strategies'
      );
    }

    return recommendations;
  }

  // Predictive Alerts
  generateAlerts() {
    const alerts = [];
    const anomalies = this.detectAnomalies();
    const predictions = this.generatePredictions(3);
    const risks = this.assessRisks();

    if (anomalies.overall) {
      alerts.push({
        type: 'warning',
        message: 'Revenue anomaly detected - investigate recent transactions',
        severity: 'high',
      });
    }

    if (
      predictions.ensemble[0] <
      historicalData[historicalData.length - 1] * 0.95
    ) {
      alerts.push({
        type: 'caution',
        message: 'Predicted revenue decline - review business strategies',
        severity: 'medium',
      });
    }

    if (risks.overallRisk > 0.25) {
      alerts.push({
        type: 'risk',
        message: 'Elevated risk levels - consider risk mitigation measures',
        severity: 'high',
      });
    }

    return alerts;
  }

  calculateR2(X, Y, beta) {
    const yMean = Y.reduce((a, b) => a + b[0], 0) / Y.length;
    const yPredicted = X.map((row) => beta[0][0] + beta[1][0] * row[1]);

    const ssRes = Y.reduce(
      (sum, y, i) => sum + Math.pow(y[0] - yPredicted[i], 2),
      0
    );
    const ssTot = Y.reduce((sum, y) => sum + Math.pow(y[0] - yMean, 2), 0);

    return 1 - ssRes / ssTot;
  }
}

// Singleton instance
const analyticsEngine = new AdvancedAnalytics();

// Export functions for backward compatibility and enhanced features
export function trainModel() {
  return analyticsEngine.trainLinearRegression();
}

export function predictNextMonth() {
  const predictions = analyticsEngine.predictEnsemble(1);
  return predictions[0];
}

export function detectAnomaly(currentRevenue) {
  const anomalies = analyticsEngine.detectAnomalies([
    ...historicalData.slice(0, -1),
    currentRevenue,
  ]);
  return anomalies.overall;
}

export function getAnalytics() {
  const currentRevenue = historicalData[historicalData.length - 1];
  const predictions = analyticsEngine.generatePredictions(6);
  const anomalies = analyticsEngine.detectAnomalies();
  const risks = analyticsEngine.assessRisks();
  const alerts = analyticsEngine.generateAlerts();

  return {
    currentRevenue,
    predictions: {
      nextMonth: predictions.ensemble[0],
      threeMonth: predictions.ensemble.slice(0, 3),
      sixMonth: predictions.ensemble,
      confidenceIntervals: predictions.confidence,
    },
    anomalies: {
      detected: anomalies.overall,
      details: anomalies,
    },
    riskAssessment: risks,
    alerts: alerts,
    historicalData,
    models: {
      linear: analyticsEngine.models.linear,
      seasonal: analyticsEngine.models.seasonal,
    },
    metadata: {
      lastUpdated: new Date().toISOString(),
      dataPoints: historicalData.length,
      predictionHorizon: 6,
    },
  };
}

// Enhanced exports for advanced features
export { analyticsEngine };
export function getAdvancedAnalytics() {
  return analyticsEngine;
}
