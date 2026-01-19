import { jest } from '@jest/globals';
import plaidAnalyticsService from '../services/plaidAnalyticsService.js';
import institutionHealthService from '../services/institutionHealthService.js';

// Mock logger to avoid console output during tests
jest.mock('../config/logger.js', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

describe('Plaid Link Conversion Optimization Tests', () => {
  beforeEach(() => {
    // Reset services before each test
    plaidAnalyticsService.resetMetrics();
    // Note: institutionHealthService doesn't have a reset method, but we can test with fresh instances
  });

  describe('PlaidAnalyticsService', () => {
    test('should track link token creation', () => {
      const trackingId = plaidAnalyticsService.trackLinkTokenCreation('user123', ['transactions']);

      expect(trackingId).toBeDefined();
      expect(typeof trackingId).toBe('string');

      const analytics = plaidAnalyticsService.getConversionAnalytics();
      expect(analytics.linkTokensCreated).toBe(1);
    });

    test('should track public token exchange', () => {
      const trackingId = plaidAnalyticsService.trackLinkTokenCreation('user123', ['transactions']);
      plaidAnalyticsService.trackPublicTokenExchange(trackingId, 'public-token-123');

      const analytics = plaidAnalyticsService.getConversionAnalytics();
      expect(analytics.publicTokensExchanged).toBe(1);
    });

    test('should track successful connection', () => {
      const trackingId = plaidAnalyticsService.trackLinkTokenCreation('user123', ['transactions']);
      plaidAnalyticsService.trackPublicTokenExchange(trackingId, 'public-token-123');
      plaidAnalyticsService.trackSuccessfulConnection(trackingId, 'access-token-123', 'item-123', []);

      const analytics = plaidAnalyticsService.getConversionAnalytics();
      expect(analytics.connectionsSuccessful).toBe(1);
      expect(analytics.conversionRate).toBe(100);
    });

    test('should track failed connection', () => {
      const trackingId = plaidAnalyticsService.trackLinkTokenCreation('user123', ['transactions']);
      plaidAnalyticsService.trackFailedConnection(trackingId, new Error('Connection failed'), 'network_error');

      const analytics = plaidAnalyticsService.getConversionAnalytics();
      expect(analytics.connectionsFailed).toBe(1);
      expect(analytics.conversionRate).toBe(0);
    });

    test('should track retry attempts', () => {
      const trackingId = plaidAnalyticsService.trackLinkTokenCreation('user123', ['transactions']);
      plaidAnalyticsService.trackRetryAttempt(trackingId, 1, 'exponential_backoff');

      const analytics = plaidAnalyticsService.getConversionAnalytics();
      expect(analytics.retryAttempts).toBe(1);
    });

    test('should track fallback success', () => {
      const trackingId = plaidAnalyticsService.trackLinkTokenCreation('user123', ['transactions']);
      plaidAnalyticsService.trackFallbackSuccess(trackingId, 'ins_bad', 'ins_good');

      const analytics = plaidAnalyticsService.getConversionAnalytics();
      expect(analytics.fallbackSuccesses).toBe(1);
    });

    test('should calculate conversion funnel correctly', () => {
      // Create multiple tracking scenarios
      const trackingId1 = plaidAnalyticsService.trackLinkTokenCreation('user1', ['transactions']);
      const trackingId2 = plaidAnalyticsService.trackLinkTokenCreation('user2', ['transactions']);
      const trackingId3 = plaidAnalyticsService.trackLinkTokenCreation('user3', ['transactions']);

      plaidAnalyticsService.trackPublicTokenExchange(trackingId1, 'public-token-1');
      plaidAnalyticsService.trackPublicTokenExchange(trackingId2, 'public-token-2');

      plaidAnalyticsService.trackSuccessfulConnection(trackingId1, 'access-1', 'item-1', []);
      plaidAnalyticsService.trackFailedConnection(trackingId2, new Error('Failed'), 'auth_error');

      const funnel = plaidAnalyticsService.getConversionFunnel();
      expect(funnel.stages.link_tokens_created).toBe(3);
      expect(funnel.stages.public_tokens_exchanged).toBe(2);
      expect(funnel.stages.connections_successful).toBe(1);
      expect(funnel.stages.connections_failed).toBe(1);
      expect(funnel.conversion_rates.token_exchange_rate).toBeCloseTo(66.67, 1);
      expect(funnel.conversion_rates.overall_conversion_rate).toBeCloseTo(33.33, 1);
    });

    test('should update institution success rates', () => {
      const trackingId1 = plaidAnalyticsService.trackLinkTokenCreation('user1', ['transactions'], { institutionId: 'ins_1' });
      const trackingId2 = plaidAnalyticsService.trackLinkTokenCreation('user2', ['transactions'], { institutionId: 'ins_1' });

      plaidAnalyticsService.trackSuccessfulConnection(trackingId1, 'access-1', 'item-1', []);
      plaidAnalyticsService.trackFailedConnection(trackingId2, new Error('Failed'), 'auth_error');

      const health = plaidAnalyticsService.getInstitutionHealth('ins_1');
      expect(health.successRate).toBe(0.5);
      expect(health.attempts).toBe(2);
    });
  });

  describe('InstitutionHealthService', () => {
    test('should record institution interactions', () => {
      institutionHealthService.recordInstitutionInteraction('ins_1', true, 1500);

      const health = institutionHealthService.getInstitutionHealth('ins_1');
      expect(health.status).toBe('healthy');
      expect(health.successRate).toBe(1);
      expect(health.averageResponseTime).toBe(1500);
    });

    test('should calculate health score correctly', () => {
      // Record multiple interactions
      institutionHealthService.recordInstitutionInteraction('ins_1', true, 1000);
      institutionHealthService.recordInstitutionInteraction('ins_1', true, 1200);
      institutionHealthService.recordInstitutionInteraction('ins_1', false, 2000);

      const health = institutionHealthService.getInstitutionHealth('ins_1');
      expect(health.successRate).toBeCloseTo(0.667, 2);
      expect(health.averageResponseTime).toBe(1400);
    });

    test('should mark unhealthy institutions', () => {
      // Record many failures
      for (let i = 0; i < 8; i++) {
        institutionHealthService.recordInstitutionInteraction('ins_bad', false, 5000);
      }

      const health = institutionHealthService.getInstitutionHealth('ins_bad');
      expect(health.status).toBe('unhealthy');
      expect(health.successRate).toBe(0);
    });

    test('should get top performing institutions', () => {
      // Set up test data
      institutionHealthService.recordInstitutionInteraction('ins_good', true, 1000);
      institutionHealthService.recordInstitutionInteraction('ins_good', true, 1100);
      institutionHealthService.recordInstitutionInteraction('ins_good', true, 1200);

      institutionHealthService.recordInstitutionInteraction('ins_ok', true, 1500);
      institutionHealthService.recordInstitutionInteraction('ins_ok', false, 2000);

      institutionHealthService.recordInstitutionInteraction('ins_bad', false, 5000);
      institutionHealthService.recordInstitutionInteraction('ins_bad', false, 6000);

      const topPerformers = institutionHealthService.getTopPerformingInstitutions(2);
      expect(topPerformers.length).toBe(2);
      expect(topPerformers[0].institutionId).toBe('ins_good');
      expect(topPerformers[1].institutionId).toBe('ins_ok');
    });

    test('should provide institution recommendations', () => {
      // Set up test data
      institutionHealthService.recordInstitutionInteraction('ins_1', true, 1000);
      institutionHealthService.recordInstitutionInteraction('ins_1', true, 1100);
      institutionHealthService.recordInstitutionInteraction('ins_2', true, 1200);
      institutionHealthService.recordInstitutionInteraction('ins_2', false, 1500);

      const recommendations = institutionHealthService.getInstitutionRecommendations();
      expect(recommendations.length).toBeGreaterThan(0);
      expect(recommendations[0]).toHaveProperty('institutionId');
      expect(recommendations[0]).toHaveProperty('successRate');
    });

    test('should get fallback institutions', () => {
      institutionHealthService.recordInstitutionInteraction('ins_1', true, 1000);
      institutionHealthService.recordInstitutionInteraction('ins_1', true, 1100);
      institutionHealthService.recordInstitutionInteraction('ins_2', true, 1200);
      institutionHealthService.recordInstitutionInteraction('ins_2', true, 1300);
      institutionHealthService.recordInstitutionInteraction('ins_3', false, 5000);

      const fallbacks = institutionHealthService.getFallbackInstitutions('ins_3');
      expect(fallbacks).toContain('ins_1');
      expect(fallbacks).toContain('ins_2');
      expect(fallbacks).not.toContain('ins_3');
    });

    test('should calculate overall health statistics', () => {
      institutionHealthService.recordInstitutionInteraction('ins_1', true, 1000);
      institutionHealthService.recordInstitutionInteraction('ins_2', false, 2000);
      institutionHealthService.recordInstitutionInteraction('ins_3', true, 1500);

      const stats = institutionHealthService.getHealthStatistics();
      expect(stats.totalInstitutions).toBe(3);
      expect(stats.healthyInstitutions).toBe(2);
      expect(stats.unhealthyInstitutions).toBe(1);
      expect(stats.averageSuccessRate).toBeCloseTo(0.667, 2);
    });
  });

  describe('Integration Tests', () => {
    test('should integrate analytics with institution health tracking', () => {
      // Simulate a complete user journey
      const trackingId = plaidAnalyticsService.trackLinkTokenCreation('user123', ['transactions'], { institutionId: 'ins_1' });
      plaidAnalyticsService.trackPublicTokenExchange(trackingId, 'public-token-123');
      plaidAnalyticsService.trackSuccessfulConnection(trackingId, 'access-token-123', 'item-123', [], 1500);

      // Check that institution health was updated
      const health = institutionHealthService.getInstitutionHealth('ins_1');
      expect(health.attempts).toBe(1);
      expect(health.successRate).toBe(1);

      // Check analytics
      const analytics = plaidAnalyticsService.getConversionAnalytics();
      expect(analytics.successfulConnections).toBe(1);
      expect(analytics.conversionRate).toBe(100);
    });

    test('should handle failed connections with institution health impact', () => {
      const trackingId = plaidAnalyticsService.trackLinkTokenCreation('user123', ['transactions'], { institutionId: 'ins_1' });
      plaidAnalyticsService.trackFailedConnection(trackingId, new Error('Connection timeout'), 'network_timeout', 10000);

      const health = institutionHealthService.getInstitutionHealth('ins_1');
      expect(health.attempts).toBe(1);
      expect(health.successRate).toBe(0);

      const analytics = plaidAnalyticsService.getConversionAnalytics();
      expect(analytics.failedConnections).toBe(1);
      expect(analytics.conversionRate).toBe(0);
    });

    test('should track retry attempts and fallback successes', () => {
      const trackingId = plaidAnalyticsService.trackLinkTokenCreation('user123', ['transactions'], { institutionId: 'ins_bad' });
      plaidAnalyticsService.trackRetryAttempt(trackingId, 1);
      plaidAnalyticsService.trackRetryAttempt(trackingId, 2);
      plaidAnalyticsService.trackFallbackSuccess(trackingId, 'ins_bad', 'ins_good');

      const analytics = plaidAnalyticsService.getConversionAnalytics();
      expect(analytics.retryAttempts).toBe(2);
      expect(analytics.fallbackSuccesses).toBe(1);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle missing institution IDs gracefully', () => {
      const trackingId = plaidAnalyticsService.trackLinkTokenCreation('user123', ['transactions']);
      plaidAnalyticsService.trackSuccessfulConnection(trackingId, 'access-token-123', 'item-123', []);

      const analytics = plaidAnalyticsService.getConversionAnalytics();
      expect(analytics.successfulConnections).toBe(1);
    });

    test('should handle unknown institution health queries', () => {
      const health = institutionHealthService.getInstitutionHealth('ins_unknown');
      expect(health.status).toBe('unknown');
      expect(health.attempts).toBe(0);
    });

    test('should handle empty institution recommendations', () => {
      const recommendations = institutionHealthService.getInstitutionRecommendations();
      expect(Array.isArray(recommendations)).toBe(true);
      // Should return recommended institutions even with no data
    });

    test('should handle concurrent operations safely', async () => {
      const operations = [];

      for (let i = 0; i < 10; i++) {
        operations.push(
          new Promise((resolve) => {
            const trackingId = plaidAnalyticsService.trackLinkTokenCreation(`user${i}`, ['transactions']);
            plaidAnalyticsService.trackSuccessfulConnection(trackingId, `access-${i}`, `item-${i}`, []);
            resolve();
          })
        );
      }

      await Promise.all(operations);

      const analytics = plaidAnalyticsService.getConversionAnalytics();
      expect(analytics.successfulConnections).toBe(10);
      expect(analytics.conversionRate).toBe(100);
    });
  });

  describe('Performance and Cleanup', () => {
    test('should cleanup old connection tracking data', () => {
      // Mock Date.now to simulate old data
      const originalNow = Date.now;
      Date.now = jest.fn(() => Date.now() - (48 * 60 * 60 * 1000)); // 48 hours ago

      const trackingId = plaidAnalyticsService.trackLinkTokenCreation('user123', ['transactions']);

      Date.now = originalNow; // Restore original

      const cleaned = plaidAnalyticsService.cleanupOldData(24 * 60 * 60 * 1000); // 24 hours
      expect(cleaned).toBe(1);
    });

    test('should handle large numbers of operations efficiently', () => {
      for (let i = 0; i < 1000; i++) {
        const trackingId = plaidAnalyticsService.trackLinkTokenCreation(`user${i}`, ['transactions']);
        if (i % 2 === 0) {
          plaidAnalyticsService.trackSuccessfulConnection(trackingId, `access-${i}`, `item-${i}`, []);
        } else {
          plaidAnalyticsService.trackFailedConnection(trackingId, new Error('Test error'), 'test_error');
        }
      }

      const analytics = plaidAnalyticsService.getConversionAnalytics();
      expect(analytics.linkTokensCreated).toBe(1000);
      expect(analytics.successfulConnections).toBe(500);
      expect(analytics.failedConnections).toBe(500);
    });
  });
});
