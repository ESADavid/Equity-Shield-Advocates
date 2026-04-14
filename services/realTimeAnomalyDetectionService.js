const logger = require('../config/logger');

class RealTimeAnomalyDetectionService {
  constructor() {
    this.thresholds = {
      transactionAmount: 10000,
      frequency: 10, // transactions per minute
      geographicSpread: 5, // different locations
      timeWindow: 60000, // 1 minute in milliseconds
    };
    this.alerts = [];
    this.monitoringData = new Map();
  }

  // Manual anomaly detection based on rules
  detectAnomalies(transaction, userHistory = []) {
    logger.info('Using manual anomaly detection');
    const anomalies = [];

    // Check transaction amount
    if (transaction.amount > this.thresholds.transactionAmount) {
      anomalies.push({
        type: 'high_amount',
        severity: 'medium',
        description: 'Transaction amount exceeds normal threshold',
        confidence: 0.8,
      });
    }

    // Check transaction frequency
    const recentTransactions = userHistory.filter(
      (t) => Date.now() - t.timestamp < this.thresholds.timeWindow
    );

    if (recentTransactions.length > this.thresholds.frequency) {
      anomalies.push({
        type: 'high_frequency',
        severity: 'high',
        description: 'Unusual transaction frequency detected',
        confidence: 0.9,
      });
    }

    // Check geographic spread
    const locations = new Set(recentTransactions.map((t) => t.location));
    if (locations.size > this.thresholds.geographicSpread) {
      anomalies.push({
        type: 'geographic_spread',
        severity: 'medium',
        description: 'Transactions from multiple geographic locations',
        confidence: 0.7,
      });
    }

    // Check for unusual patterns
    const unusualPatterns = this.detectUnusualPatterns(
      transaction,
      userHistory
    );
    anomalies.push(...unusualPatterns);

    return {
      anomalies,
      riskScore: this.calculateRiskScore(anomalies),
      recommendation: this.generateRecommendation(anomalies),
    };
  }

  detectUnusualPatterns(transaction, userHistory) {
    const patterns = [];

    // Check for round number amounts (potential money laundering indicator)
    if (transaction.amount % 1000 === 0 && transaction.amount > 5000) {
      patterns.push({
        type: 'round_amount',
        severity: 'low',
        description: 'Round number transaction amount',
        confidence: 0.6,
      });
    }

    // Check for time-based anomalies (e.g., transactions at unusual hours)
    const hour = new Date(transaction.timestamp).getHours();
    if (hour < 6 || hour > 22) {
      patterns.push({
        type: 'unusual_timing',
        severity: 'low',
        description: 'Transaction at unusual hour',
        confidence: 0.5,
      });
    }

    return patterns;
  }

  calculateRiskScore(anomalies) {
    const severityWeights = {
      high: 1.0,
      medium: 0.6,
      low: 0.3,
    };

    let totalScore = 0;
    let totalWeight = 0;

    anomalies.forEach((anomaly) => {
      const weight = severityWeights[anomaly.severity] || 0.5;
      totalScore += anomaly.confidence * weight;
      totalWeight += weight;
    });

    return totalWeight > 0 ? totalScore / totalWeight : 0;
  }

  generateRecommendation(anomalies) {
    if (anomalies.length === 0) {
      return 'Transaction appears normal - proceed with standard processing';
    }

    const highSeverity = anomalies.filter((a) => a.severity === 'high').length;
    const mediumSeverity = anomalies.filter(
      (a) => a.severity === 'medium'
    ).length;

    if (highSeverity > 0) {
      return 'High risk detected - recommend manual review and potential hold';
    } else if (mediumSeverity > 1) {
      return 'Medium risk detected - recommend enhanced verification';
    } else {
      return 'Low risk detected - proceed with caution and monitoring';
    }
  }

  // Monitor system health manually
  monitorSystemHealth(metrics) {
    logger.info('Manual system health monitoring');
    const issues = [];

    if (metrics.cpu > 90) {
      issues.push({
        type: 'high_cpu',
        severity: 'high',
        description: 'CPU usage above 90%',
      });
    }

    if (metrics.memory > 85) {
      issues.push({
        type: 'high_memory',
        severity: 'medium',
        description: 'Memory usage above 85%',
      });
    }

    if (metrics.errorRate > 0.05) {
      issues.push({
        type: 'high_error_rate',
        severity: 'high',
        description: 'Error rate above 5%',
      });
    }

    return {
      status: issues.length > 0 ? 'warning' : 'healthy',
      issues,
      timestamp: new Date().toISOString(),
    };
  }

  // Log monitoring data for manual review
  logMonitoringData(data) {
    const key = `${data.type}_${Date.now()}`;
    this.monitoringData.set(key, {
      ...data,
      timestamp: new Date().toISOString(),
    });

    // Keep only last 1000 entries
    if (this.monitoringData.size > 1000) {
      const firstKey = this.monitoringData.keys().next().value;
      this.monitoringData.delete(firstKey);
    }
  }

  // Get monitoring summary
  getMonitoringSummary() {
    const summary = {
      totalEntries: this.monitoringData.size,
      recentAlerts: [],
      systemStatus: 'monitoring',
    };

    // Get last 10 entries
    const entries = Array.from(this.monitoringData.values()).slice(-10);
    summary.recentAlerts = entries.filter((entry) => entry.type === 'alert');

    return summary;
  }
}

module.exports = new RealTimeAnomalyDetectionService();
