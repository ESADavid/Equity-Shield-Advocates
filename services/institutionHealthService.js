import logger from '../config/logger.js';

// Institution health monitoring and optimization service
class InstitutionHealthService {
  constructor() {
    this.institutionStats = new Map();
    this.healthThresholds = {
      minAttempts: 5, // Minimum attempts to consider reliable
      successRateThreshold: 0.7, // 70% success rate threshold
      recentWindow: 24 * 60 * 60 * 1000, // 24 hours for recent performance
      healthCheckInterval: 60 * 60 * 1000, // Check every hour
    };

    // Popular institutions with known good performance (can be updated based on data)
    this.recommendedInstitutions = new Set([
      'ins_1', // Chase
      'ins_2', // Bank of America
      'ins_3', // Wells Fargo
      'ins_4', // Citibank
      'ins_5', // US Bank
      'ins_10', // Capital One
      'ins_12', // PNC Bank
      'ins_13', // TD Bank
      'ins_14', // Navy Federal Credit Union
      'ins_15', // Truist
    ]);

    // Start periodic health checks
    this.startHealthMonitoring();
  }

  // Record an institution interaction
  recordInstitutionInteraction(
    institutionId,
    success,
    responseTime,
    errorType = null
  ) {
    if (!institutionId) return;

    const current = this.institutionStats.get(institutionId) || {
      totalAttempts: 0,
      successfulAttempts: 0,
      failedAttempts: 0,
      averageResponseTime: 0,
      totalResponseTime: 0,
      lastAttempt: null,
      recentAttempts: [], // Last 100 attempts for trend analysis
      errorTypes: new Map(),
      successRate: 0,
      healthScore: 0,
      isHealthy: true,
      consecutiveFailures: 0,
      lastFailureTime: null,
    };

    current.totalAttempts++;
    current.lastAttempt = Date.now();

    if (success) {
      current.successfulAttempts++;
      current.consecutiveFailures = 0;
    } else {
      current.failedAttempts++;
      current.consecutiveFailures++;
      current.lastFailureTime = Date.now();

      if (errorType) {
        current.errorTypes.set(
          errorType,
          (current.errorTypes.get(errorType) || 0) + 1
        );
      }
    }

    // Update response time
    current.totalResponseTime += responseTime;
    current.averageResponseTime =
      current.totalResponseTime / current.totalAttempts;

    // Update recent attempts (keep last 100)
    current.recentAttempts.push({
      success,
      timestamp: Date.now(),
      responseTime,
    });
    if (current.recentAttempts.length > 100) {
      current.recentAttempts.shift();
    }

    // Calculate success rate
    current.successRate = current.successfulAttempts / current.totalAttempts;

    // Calculate health score (weighted combination of factors)
    current.healthScore = this.calculateHealthScore(current);

    // Determine if institution is healthy
    current.isHealthy = this.isInstitutionHealthy(current);

    this.institutionStats.set(institutionId, current);

    logger.debug(`Institution interaction recorded`, {
      institutionId,
      success,
      responseTime,
      successRate: current.successRate.toFixed(3),
      healthScore: current.healthScore.toFixed(3),
      isHealthy: current.isHealthy,
    });
  }

  // Calculate health score based on multiple factors
  calculateHealthScore(stats) {
    if (stats.totalAttempts < this.healthThresholds.minAttempts) {
      return 0.5; // Neutral score for institutions with insufficient data
    }

    let score = 0;

    // Success rate (40% weight)
    score += stats.successRate * 0.4;

    // Response time score (20% weight) - faster is better
    const responseTimeScore = Math.max(
      0,
      1 - stats.averageResponseTime / 30000
    ); // 30 seconds max
    score += responseTimeScore * 0.2;

    // Recent performance (20% weight) - last 10 attempts
    const recentAttempts = stats.recentAttempts.slice(-10);
    if (recentAttempts.length > 0) {
      const recentSuccessRate =
        recentAttempts.filter((a) => a.success).length / recentAttempts.length;
      score += recentSuccessRate * 0.2;
    }

    // Consecutive failures penalty (10% weight)
    const consecutiveFailurePenalty = Math.min(
      stats.consecutiveFailures * 0.1,
      0.1
    );
    score -= consecutiveFailurePenalty;

    // Recency bonus (10% weight) - recently successful institutions get slight boost
    const timeSinceLastSuccess = Date.now() - (stats.lastAttempt || 0);
    const recencyBonus =
      timeSinceLastSuccess < this.healthThresholds.recentWindow ? 0.1 : 0;
    score += recencyBonus;

    return Math.max(0, Math.min(1, score));
  }

  // Determine if an institution is healthy
  isInstitutionHealthy(stats) {
    // Must have minimum attempts
    if (stats.totalAttempts < this.healthThresholds.minAttempts) {
      return true; // Assume healthy until proven otherwise
    }

    // Success rate above threshold
    if (stats.successRate < this.healthThresholds.successRateThreshold) {
      return false;
    }

    // Not too many consecutive failures
    if (stats.consecutiveFailures > 3) {
      return false;
    }

    // Recent performance check (last 5 attempts)
    const recentAttempts = stats.recentAttempts.slice(-5);
    if (recentAttempts.length >= 3) {
      const recentSuccessRate =
        recentAttempts.filter((a) => a.success).length / recentAttempts.length;
      if (recentSuccessRate < 0.5) {
        return false;
      }
    }

    return true;
  }

  // Get institution health status
  getInstitutionHealth(institutionId) {
    const stats = this.institutionStats.get(institutionId);
    if (!stats) {
      return {
        institutionId,
        status: 'unknown',
        attempts: 0,
        message: 'No data available for this institution',
      };
    }

    return {
      institutionId,
      status: stats.isHealthy ? 'healthy' : 'unhealthy',
      attempts: stats.totalAttempts,
      successRate: stats.successRate,
      healthScore: stats.healthScore,
      averageResponseTime: stats.averageResponseTime,
      lastAttempt: stats.lastAttempt,
      consecutiveFailures: stats.consecutiveFailures,
      recommended: this.recommendedInstitutions.has(institutionId),
    };
  }

  // Get top performing institutions
  getTopPerformingInstitutions(limit = 10, minAttempts = 5) {
    return Array.from(this.institutionStats.entries())
      .filter(
        ([, stats]) => stats.totalAttempts >= minAttempts && stats.isHealthy
      )
      .sort(([, a], [, b]) => b.healthScore - a.healthScore)
      .slice(0, limit)
      .map(([institutionId, stats]) => ({
        institutionId,
        successRate: stats.successRate,
        healthScore: stats.healthScore,
        attempts: stats.totalAttempts,
        averageResponseTime: stats.averageResponseTime,
        recommended: this.recommendedInstitutions.has(institutionId),
      }));
  }

  // Get institution recommendations for a user
  getInstitutionRecommendations(userContext = {}) {
    const { preferredInstitutions = [], excludeUnhealthy = true } = userContext;

    let candidates = Array.from(this.institutionStats.entries());

    // Filter out unhealthy institutions if requested
    if (excludeUnhealthy) {
      candidates = candidates.filter(([, stats]) => stats.isHealthy);
    }

    // Prioritize preferred institutions
    const preferred = candidates.filter(([id]) =>
      preferredInstitutions.includes(id)
    );
    const others = candidates.filter(
      ([id]) => !preferredInstitutions.includes(id)
    );

    // Sort by health score
    const sortByHealth = (a, b) => b[1].healthScore - a[1].healthScore;

    preferred.sort(sortByHealth);
    others.sort(sortByHealth);

    // Combine results
    const recommendations = [
      ...preferred.map(([id, stats]) => ({
        institutionId: id,
        ...this.getInstitutionHealth(id),
        preferred: true,
      })),
      ...others
        .slice(0, 10)
        .map(([id, stats]) => ({
          institutionId: id,
          ...this.getInstitutionHealth(id),
          preferred: false,
        })),
    ];

    // Add recommended institutions that don't have stats yet
    const recommendedWithoutStats = Array.from(this.recommendedInstitutions)
      .filter((id) => !this.institutionStats.has(id))
      .slice(0, 5)
      .map((id) => ({
        institutionId: id,
        status: 'recommended',
        attempts: 0,
        successRate: 0,
        healthScore: 0.8, // Assume good performance for recommended institutions
        averageResponseTime: 0,
        lastAttempt: null,
        consecutiveFailures: 0,
        recommended: true,
        preferred: false,
      }));

    return [...recommendations, ...recommendedWithoutStats];
  }

  // Get fallback institutions for when primary institution fails
  getFallbackInstitutions(primaryInstitutionId, limit = 3) {
    return Array.from(this.institutionStats.entries())
      .filter(
        ([id, stats]) =>
          id !== primaryInstitutionId &&
          stats.isHealthy &&
          stats.totalAttempts >= 10
      )
      .sort(([, a], [, b]) => b.successRate - a.successRate)
      .slice(0, limit)
      .map(([id]) => id);
  }

  // Get overall health statistics
  getHealthStatistics() {
    const allStats = Array.from(this.institutionStats.values());
    const healthyCount = allStats.filter((s) => s.isHealthy).length;
    const totalCount = allStats.length;

    const avgSuccessRate =
      allStats.length > 0
        ? allStats.reduce((sum, s) => sum + s.successRate, 0) / allStats.length
        : 0;

    const avgResponseTime =
      allStats.length > 0
        ? allStats.reduce((sum, s) => sum + s.averageResponseTime, 0) /
          allStats.length
        : 0;

    return {
      totalInstitutions: totalCount,
      healthyInstitutions: healthyCount,
      unhealthyInstitutions: totalCount - healthyCount,
      averageSuccessRate: avgSuccessRate,
      averageResponseTime: avgResponseTime,
      healthRate: totalCount > 0 ? healthyCount / totalCount : 0,
      timestamp: Date.now(),
    };
  }

  // Start periodic health monitoring
  startHealthMonitoring() {
    setInterval(() => {
      this.performHealthCheck();
    }, this.healthThresholds.healthCheckInterval);
  }

  // Perform periodic health check
  performHealthCheck() {
    const stats = this.getHealthStatistics();

    logger.info('Institution health check completed', {
      totalInstitutions: stats.totalInstitutions,
      healthyRate: `${(stats.healthRate * 100).toFixed(1)}%`,
      averageSuccessRate: `${(stats.averageSuccessRate * 100).toFixed(1)}%`,
      averageResponseTime: `${stats.averageResponseTime.toFixed(0)}ms`,
    });

    // Log unhealthy institutions
    const unhealthyInstitutions = Array.from(this.institutionStats.entries())
      .filter(([, stats]) => !stats.isHealthy)
      .map(([id, stats]) => ({
        institutionId: id,
        successRate: stats.successRate,
        consecutiveFailures: stats.consecutiveFailures,
      }));

    if (unhealthyInstitutions.length > 0) {
      logger.warn('Unhealthy institutions detected', { unhealthyInstitutions });
    }
  }

  // Clean up old data
  cleanupOldData(maxAge = 30 * 24 * 60 * 60 * 1000) {
    // 30 days
    const cutoff = Date.now() - maxAge;
    let cleaned = 0;

    for (const [institutionId, stats] of this.institutionStats.entries()) {
      // Remove old recent attempts
      stats.recentAttempts = stats.recentAttempts.filter(
        (attempt) => attempt.timestamp > cutoff
      );

      // If no recent data and low attempt count, consider removing
      if (
        stats.recentAttempts.length === 0 &&
        stats.totalAttempts < 10 &&
        stats.lastAttempt < cutoff
      ) {
        this.institutionStats.delete(institutionId);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.info(`Cleaned up ${cleaned} old institution records`);
    }

    return cleaned;
  }

  // Export health data for backup/analysis
  exportHealthData() {
    return {
      institutionStats: Object.fromEntries(this.institutionStats),
      healthThresholds: this.healthThresholds,
      recommendedInstitutions: Array.from(this.recommendedInstitutions),
      exportTimestamp: Date.now(),
    };
  }

  // Import health data
  importHealthData(data) {
    if (data.institutionStats) {
      this.institutionStats = new Map(Object.entries(data.institutionStats));
    }
    if (data.recommendedInstitutions) {
      this.recommendedInstitutions = new Set(data.recommendedInstitutions);
    }

    logger.info('Institution health data imported', {
      institutionsImported: this.institutionStats.size,
      recommendedImported: this.recommendedInstitutions.size,
    });
  }
}

const institutionHealthService = new InstitutionHealthService();

// Periodic cleanup
setInterval(
  () => {
    institutionHealthService.cleanupOldData();
  },
  24 * 60 * 60 * 1000
); // Daily cleanup

export default institutionHealthService;
