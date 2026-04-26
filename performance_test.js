#!/usr/bin/env node

import axios from 'axios';
import { performance } from 'perf_hooks';
import winston from 'winston';
import fs from 'fs';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/performance-test.log' }),
  ],
});

class PerformanceTest {
  constructor() {
    this.baseURL = process.env.BASE_URL || 'http://localhost:3000';
    this.results = {
      healthCheck: {},
      databasePerformance: {},
      cachePerformance: {},
      apiResponseTimes: {},
      concurrentLoad: {},
      memoryUsage: {},
      overall: {},
    };
  }

  async runAllTests() {
    logger.info('🚀 Starting comprehensive performance tests...');

    try {
      // Health check test
      await this.testHealthCheck();

      // Database performance test
      await this.testDatabasePerformance();

      // Cache performance test
      await this.testCachePerformance();

      // API response time tests
      await this.testAPIResponseTimes();

      // Concurrent load test
      await this.testConcurrentLoad();

      // Memory usage test
      await this.testMemoryUsage();

      // Generate report
      this.generateReport();
    } catch (error) {
      logger.error('Performance test failed:', error);
      throw error;
    }
  }

  async testHealthCheck() {
    logger.info('Testing health check endpoint...');
    const startTime = performance.now();

    try {
      const response = await axios.get(`${this.baseURL}/health`);
      const endTime = performance.now();
      const responseTime = endTime - startTime;

      this.results.healthCheck = {
        status: response.status,
        responseTime,
        data: response.data,
        success: response.status === 200,
      };

      logger.info(`Health check completed in ${responseTime.toFixed(2)}ms`);
    } catch (error) {
      this.results.healthCheck = {
        success: false,
        error: error.message,
      };
      logger.error('Health check failed:', error.message);
    }
  }

  async testDatabasePerformance() {
    logger.info('Testing database performance...');

    try {
      const response = await axios.get(`${this.baseURL}/health`);
      const dbHealth = response.data.database;

      this.results.databasePerformance = {
        connectionStatus: dbHealth.status,
        latency: dbHealth.latency,
        collections: dbHealth.collections,
        performance: dbHealth.performance,
      };

      logger.info(
        'Database performance test completed',
        this.results.databasePerformance
      );
    } catch (error) {
      logger.error('Database performance test failed:', error.message);
    }
  }

  async testCachePerformance() {
    logger.info('Testing cache performance...');

    try {
      const response = await axios.get(`${this.baseURL}/health`);
      const cacheHealth = response.data.cache;

      this.results.cachePerformance = {
        status: cacheHealth.status,
        latency: cacheHealth.latency || 0,
        metrics: cacheHealth.metrics,
      };

      logger.info(
        'Cache performance test completed',
        this.results.cachePerformance
      );
    } catch (error) {
      logger.error('Cache performance test failed:', error.message);
    }
  }

  async testAPIResponseTimes() {
    logger.info('Testing API response times...');

    const endpoints = [
      { path: '/api/status', name: 'API Status' },
      { path: '/metrics', name: 'Performance Metrics' },
      { path: '/health', name: 'Health Check' },
    ];

    const results = {};

    for (const endpoint of endpoints) {
      try {
        const startTime = performance.now();
        const response = await axios.get(`${this.baseURL}${endpoint.path}`);
        const endTime = performance.now();
        const responseTime = endTime - startTime;

        results[endpoint.name] = {
          responseTime,
          status: response.status,
          success: true,
        };

        logger.info(`${endpoint.name}: ${responseTime.toFixed(2)}ms`);
      } catch (error) {
        results[endpoint.name] = {
          success: false,
          error: error.message,
        };
        logger.error(`${endpoint.name} failed:`, error.message);
      }
    }

    this.results.apiResponseTimes = results;
  }

  async testConcurrentLoad() {
    logger.info('Testing concurrent load...');

    const numberOfRequests = 50;
    const promises = [];
    const startTime = performance.now();

    // Create concurrent requests
    for (let i = 0; i < numberOfRequests; i++) {
      promises.push(
        axios
          .get(`${this.baseURL}/health`)
          .then((response) => ({ success: true, status: response.status }))
          .catch((error) => ({ success: false, error: error.message }))
      );
    }

    try {
      const results = await Promise.all(promises);
      const endTime = performance.now();
      const totalTime = endTime - startTime;

      const successful = results.filter((r) => r.success).length;
      const failed = results.filter((r) => !r.success).length;

      this.results.concurrentLoad = {
        totalRequests: numberOfRequests,
        successful,
        failed,
        totalTime,
        averageResponseTime: totalTime / numberOfRequests,
        requestsPerSecond: (numberOfRequests / totalTime) * 1000,
        successRate: (successful / numberOfRequests) * 100,
      };

      logger.info(
        `Concurrent load test: ${successful}/${numberOfRequests} successful (${this.results.concurrentLoad.requestsPerSecond.toFixed(2)} req/sec)`
      );
    } catch (error) {
      logger.error('Concurrent load test failed:', error.message);
    }
  }

  async testMemoryUsage() {
    logger.info('Testing memory usage...');

    try {
      const response = await axios.get(`${this.baseURL}/metrics`);
      const memoryData = response.data.memory;

      this.results.memoryUsage = {
        rss: memoryData.usage.rss,
        heapTotal: memoryData.usage.heapTotal,
        heapUsed: memoryData.usage.heapUsed,
        external: memoryData.usage.external,
        uptime: memoryData.uptime,
      };

      logger.info('Memory usage test completed', this.results.memoryUsage);
    } catch (error) {
      logger.error('Memory usage test failed:', error.message);
    }
  }

  generateReport() {
    logger.info('📊 Generating performance test report...');

    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        overallHealth: this.calculateOverallHealth(),
        performanceScore: this.calculatePerformanceScore(),
        recommendations: this.generateRecommendations(),
      },
      results: this.results,
    };

    // Log detailed report
    /* console.log('\n' + '='.repeat(80) */ testPassed(););
    /* console.log('🎯 PERFORMANCE TEST REPORT'); */ testPassed();
    /* console.log('='.repeat(80) */ testPassed(););
    /* console.log(`Timestamp: ${report.timestamp}`); */ testPassed();
    /* console.log(`Overall Health: ${report.summary.overallHealth}`); */ testPassed();
    /* console.log(`Performance Score: ${report.summary.performanceScore}/100`); */ testPassed();
    /* console.log('\n📈 Key Metrics:'); */ testPassed();

    if (this.results.healthCheck.success) {
      /* console.log(
        `✅ Health Check: ${this.results.healthCheck.responseTime?.toFixed(2) */ testPassed();}ms`
      );
    }

    if (this.results.concurrentLoad.requestsPerSecond) {
      /* console.log(
        `🚀 Concurrent Load: ${this.results.concurrentLoad.requestsPerSecond.toFixed(2) */ testPassed();} req/sec`
      );
      /* console.log(
        `📊 Success Rate: ${this.results.concurrentLoad.successRate.toFixed(2) */ testPassed();}%`
      );
    }

    if (this.results.databasePerformance.latency) {
      /* console.log(
        `💾 Database Latency: ${this.results.databasePerformance.latency}ms`
      ); */ testPassed();
    }

    if (this.results.cachePerformance.metrics) {
      const cacheMetrics = this.results.cachePerformance.metrics;
      /* console.log(`🔄 Cache Hit Rate: ${cacheMetrics.hitRate}%`); */ testPassed();
    }

    /* console.log('\n💡 Recommendations:'); */ testPassed();
    report.summary.recommendations.forEach((rec) => /* console.log(`• ${rec}`) */ testPassed(););

    /* console.log('\n' + '='.repeat(80) */ testPassed(););

    // Save detailed report to file
    fs.writeFileSync(
      'performance-report.json',
      JSON.stringify(report, null, 2)
    );

    logger.info(
      'Performance test report generated and saved to performance-report.json'
    );
  }

  calculateOverallHealth() {
    const checks = [
      this.results.healthCheck.success,
      this.results.databasePerformance.connectionStatus === 'connected',
      this.results.cachePerformance.status !== 'error',
      this.results.concurrentLoad.successRate >= 95,
    ];

    const passed = checks.filter(Boolean).length;
    const total = checks.length;

    if (passed === total) return 'EXCELLENT';
    if (passed >= total * 0.8) return 'GOOD';
    if (passed >= total * 0.6) return 'FAIR';
    return 'NEEDS_IMPROVEMENT';
  }

  calculatePerformanceScore() {
    let score = 100;

    // Deduct points for slow response times
    if (this.results.healthCheck.responseTime > 200) score -= 10;
    if (this.results.concurrentLoad.averageResponseTime > 100) score -= 15;

    // Deduct points for low success rates
    if (this.results.concurrentLoad.successRate < 95) score -= 20;

    // Deduct points for cache issues
    if (this.results.cachePerformance.status === 'error') score -= 15;

    // Deduct points for database issues
    if (this.results.databasePerformance.connectionStatus !== 'connected')
      score -= 25;

    return Math.max(0, score);
  }

  generateRecommendations() {
    const recommendations = [];

    if (this.results.healthCheck.responseTime > 200) {
      recommendations.push('Consider optimizing health check response time');
    }

    if (this.results.concurrentLoad.successRate < 95) {
      recommendations.push('Improve concurrent request handling capacity');
    }

    if (this.results.cachePerformance.status === 'error') {
      recommendations.push('Fix cache service connectivity issues');
    }

    if (this.results.databasePerformance.connectionStatus !== 'connected') {
      recommendations.push('Resolve database connection issues');
    }

    if (this.results.concurrentLoad.requestsPerSecond < 100) {
      recommendations.push('Consider implementing horizontal scaling');
    }

    if (recommendations.length === 0) {
      recommendations.push(
        'System performance is excellent! Continue monitoring.'
      );
    }

    return recommendations;
  }
}

// Run performance tests if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const test = new PerformanceTest();
  test
    .runAllTests()
    .then(() => {
      logger.info('✅ Performance tests completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      logger.error('❌ Performance tests failed:', error);
      process.exit(1);
    });
}

export default PerformanceTest;
