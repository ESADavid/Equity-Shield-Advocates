import logger from '../config/logger.js';

// Conversion analytics tracking for Plaid Link optimization
class PlaidAnalyticsService {
  constructor() {
    this.conversionMetrics = {
      linkTokensCreated: 0,
      publicTokensExchanged: 0,
      successfulConnections: 0,
      failedConnections: 0,
      conversionRate: 0,
      averageConnectionTime: 0,
      institutionSuccessRates: new Map(),
      errorTypes: new Map(),
      userJourneyTimes: new Map(),
      retryAttempts: 0,
      fallbackSuccesses: 0,
    };

    this.activeConnections = new Map(); // Track ongoing connections
    this.institutionHealth = new Map(); // Track institution performance
  }

  // Track link token creation
  trackLinkTokenCreation(userId, products, options = {}) {
    this.conversionMetrics.linkTokensCreated++;

    const trackingId = `link_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    this.activeConnections.set(trackingId, {
      userId,
      products,
      options,
      createdAt: Date.now(),
      stage: 'link_token_created',
      institutionId: options.institutionId,
    });

    logger.info('Link token created for conversion tracking', {
      trackingId,
      userId,
      products,
      institutionId: options.institutionId,
    });

    return trackingId;
  }

  // Track public token exchange
  trackPublicTokenExchange(trackingId, publicToken, metadata = {}) {
    const connection = this.activeConnections.get(trackingId);
    if (connection) {
      connection.stage = 'public_token_exchanged';
      connection.publicToken = publicToken;
      connection.metadata = metadata;
      connection.exchangedAt = Date.now();

      this.conversionMetrics.publicTokensExchanged++;

      logger.info('Public token exchanged', {
        trackingId,
        userId: connection.userId,
        timeToExchange: connection.exchangedAt - connection.createdAt,
      });
    }
  }

  // Track successful connection
  trackSuccessfulConnection(trackingId, accessToken, itemId, accounts = []) {
    const connection = this.activeConnections.get(trackingId);
    if (connection) {
      connection.stage = 'connection_successful';
      connection.accessToken = accessToken;
      connection.itemId = itemId;
      connection.accounts = accounts;
      connection.completedAt = Date.now();

      this.conversionMetrics.successfulConnections++;

      // Update institution success rate
      this.updateInstitutionSuccessRate(connection.institutionId, true);

      // Calculate conversion metrics
      this.updateConversionMetrics();

      const totalTime = connection.completedAt - connection.createdAt;
      logger.info('Connection successful', {
        trackingId,
        userId: connection.userId,
        institutionId: connection.institutionId,
        totalTime,
        accountsCount: accounts.length,
      });

      // Clean up after successful connection
      setTimeout(() => {
        this.activeConnections.delete(trackingId);
      }, 300000); // Keep for 5 minutes for analytics
    }
  }

  // Track failed connection
  trackFailedConnection(trackingId, error, errorType = 'unknown') {
    const connection = this.activeConnections.get(trackingId);
    if (connection) {
      connection.stage = 'connection_failed';
      connection.error = error;
      connection.errorType = errorType;
      connection.failedAt = Date.now();

      this.conversionMetrics.failedConnections++;

      // Update institution success rate
      this.updateInstitutionSuccessRate(connection.institutionId, false);

      // Track error types
      this.conversionMetrics.errorTypes.set(
        errorType,
        (this.conversionMetrics.errorTypes.get(errorType) || 0) + 1
      );

      // Calculate conversion metrics
      this.updateConversionMetrics();

      logger.warn('Connection failed', {
        trackingId,
        userId: connection.userId,
        institutionId: connection.institutionId,
        errorType,
        error: error.message,
        timeToFailure: connection.failedAt - connection.createdAt,
      });
    }
  }

  // Track retry attempts
  trackRetryAttempt(
    trackingId,
    attemptNumber,
    strategy = 'exponential_backoff'
  ) {
    this.conversionMetrics.retryAttempts++;

    const connection = this.activeConnections.get(trackingId);
    if (connection) {
      if (!connection.retries) connection.retries = [];
      connection.retries.push({
        attempt: attemptNumber,
        strategy,
        timestamp: Date.now(),
      });

      logger.info('Retry attempt tracked', {
        trackingId,
        attemptNumber,
        strategy,
        userId: connection.userId,
      });
    }
  }

  // Track fallback success
  trackFallbackSuccess(
    trackingId,
    originalInstitutionId,
    fallbackInstitutionId
  ) {
    this.conversionMetrics.fallbackSuccesses++;

    const connection = this.activeConnections.get(trackingId);
    if (connection) {
      connection.fallbackUsed = true;
      connection.originalInstitutionId = originalInstitutionId;
      connection.fallbackInstitutionId = fallbackInstitutionId;

      logger.info('Fallback successful', {
        trackingId,
        originalInstitutionId,
        fallbackInstitutionId,
        userId: connection.userId,
      });
    }
  }

  // Update institution success rate
  updateInstitutionSuccessRate(institutionId, success) {
    if (!institutionId) return;

    const current = this.institutionHealth.get(institutionId) || {
      attempts: 0,
      successes: 0,
      failures: 0,
      successRate: 0,
      lastAttempt: null,
    };

    current.attempts++;
    if (success) {
      current.successes++;
    } else {
      current.failures++;
    }
    current.successRate = current.successes / current.attempts;
    current.lastAttempt = Date.now();

    this.institutionHealth.set(institutionId, current);
  }

  // Update overall conversion metrics
  updateConversionMetrics() {
    const totalAttempts = this.conversionMetrics.linkTokensCreated;
    const totalSuccesses = this.conversionMetrics.successfulConnections;

    this.conversionMetrics.conversionRate =
      totalAttempts > 0 ? (totalSuccesses / totalAttempts) * 100 : 0;

    // Calculate average connection time from successful connections
    const successfulConnections = Array.from(
      this.activeConnections.values()
    ).filter(
      (conn) =>
        conn.stage === 'connection_successful' &&
        conn.completedAt &&
        conn.createdAt
    );

    if (successfulConnections.length > 0) {
      const totalTime = successfulConnections.reduce(
        (sum, conn) => sum + (conn.completedAt - conn.createdAt),
        0
      );
      this.conversionMetrics.averageConnectionTime =
        totalTime / successfulConnections.length;
    }
  }

  // Get conversion analytics
  getConversionAnalytics(timeframe = 'all') {
    this.updateConversionMetrics();

    const analytics = {
      ...this.conversionMetrics,
      activeConnections: this.activeConnections.size,
      institutionHealth: Object.fromEntries(this.institutionHealth),
      topErrorTypes: Object.fromEntries(
        Array.from(this.conversionMetrics.errorTypes.entries())
          .sort(([, a], [, b]) => b - a)
          .slice(0, 10)
      ),
      timestamp: Date.now(),
    };

    return analytics;
  }

  // Get institution recommendations based on success rates
  getInstitutionRecommendations(limit = 5) {
    return Array.from(this.institutionHealth.entries())
      .filter(([, stats]) => stats.attempts >= 5) // Minimum attempts for reliability
      .sort(([, a], [, b]) => b.successRate - a.successRate)
      .slice(0, limit)
      .map(([institutionId, stats]) => ({
        institutionId,
        successRate: stats.successRate,
        attempts: stats.attempts,
        lastAttempt: stats.lastAttempt,
      }));
  }

  // Get conversion funnel data
  getConversionFunnel() {
    const stages = {
      link_tokens_created: this.conversionMetrics.linkTokensCreated,
      public_tokens_exchanged: this.conversionMetrics.publicTokensExchanged,
      connections_successful: this.conversionMetrics.successfulConnections,
      connections_failed: this.conversionMetrics.failedConnections,
    };

    return {
      stages,
      conversion_rates: {
        token_exchange_rate:
          stages.link_tokens_created > 0
            ? (stages.public_tokens_exchanged / stages.link_tokens_created) *
              100
            : 0,
        overall_conversion_rate:
          stages.link_tokens_created > 0
            ? (stages.connections_successful / stages.link_tokens_created) * 100
            : 0,
        success_rate:
          stages.connections_successful + stages.connections_failed > 0
            ? (stages.connections_successful /
                (stages.connections_successful + stages.connections_failed)) *
              100
            : 0,
      },
    };
  }

  // Clean up old connection tracking data
  cleanupOldData(maxAge = 24 * 60 * 60 * 1000) {
    // 24 hours
    const cutoff = Date.now() - maxAge;
    let cleaned = 0;

    for (const [trackingId, connection] of this.activeConnections.entries()) {
      if (connection.createdAt < cutoff) {
        this.activeConnections.delete(trackingId);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.info(`Cleaned up ${cleaned} old connection tracking records`);
    }

    return cleaned;
  }

  // Reset metrics (for testing or manual reset)
  resetMetrics() {
    this.conversionMetrics = {
      linkTokensCreated: 0,
      publicTokensExchanged: 0,
      successfulConnections: 0,
      failedConnections: 0,
      conversionRate: 0,
      averageConnectionTime: 0,
      institutionSuccessRates: new Map(),
      errorTypes: new Map(),
      userJourneyTimes: new Map(),
      retryAttempts: 0,
      fallbackSuccesses: 0,
    };

    this.activeConnections.clear();
    this.institutionHealth.clear();

    logger.info('Conversion metrics reset');
  }
}

const plaidAnalyticsService = new PlaidAnalyticsService();

// Periodic cleanup of old data
setInterval(
  () => {
    plaidAnalyticsService.cleanupOldData();
  },
  60 * 60 * 1000
); // Clean up every hour

export default plaidAnalyticsService;
