import { performance, PerformanceObserver } from 'perf_hooks';
import v8 from 'v8';
import os from 'os';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class PerformanceMonitor {
  constructor(options = {}) {
    this.metrics = {
      startTime: Date.now(),
      uptime: 0,
      memory: {},
      cpu: {},
      eventLoop: {},
      gc: {},
      requests: {
        total: 0,
        active: 0,
        completed: 0,
        failed: 0,
        averageResponseTime: 0,
        responseTimes: [],
      },
      database: {
        connections: 0,
        queries: 0,
        slowQueries: 0,
        connectionPool: {},
      },
      cache: {
        hits: 0,
        misses: 0,
        hitRate: 0,
        size: 0,
      },
      alerts: [],
    };

    this.alerts = options.alerts || {
      memoryUsage: 80, // percentage
      cpuUsage: 70, // percentage
      responseTime: 1000, // milliseconds
      errorRate: 5, // percentage
    };

    this.snapshots = [];
    this.maxSnapshots = options.maxSnapshots || 100;

    this.setupPerformanceObservers();
    this.startMonitoring();
  }

  setupPerformanceObservers() {
    // Monitor garbage collection
    const gcObserver = new PerformanceObserver((list) => {
      const entries = list.getEntries();
      entries.forEach((entry) => {
        this.metrics.gc.lastGC = {
          type: entry.kind,
          duration: entry.duration,
          timestamp: Date.now(),
        };
      });
    });
    gcObserver.observe({ entryTypes: ['gc'] });

    // Monitor HTTP requests (if available)
    try {
      const httpObserver = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        entries.forEach((entry) => {
          if (entry.entryType === 'http') {
            this.metrics.requests.total++;
            this.metrics.requests.responseTimes.push(entry.duration);

            // Keep only last 1000 response times
            if (this.metrics.requests.responseTimes.length > 1000) {
              this.metrics.requests.responseTimes.shift();
            }

            // Calculate average response time
            this.metrics.requests.averageResponseTime =
              this.metrics.requests.responseTimes.reduce((a, b) => a + b, 0) /
              this.metrics.requests.responseTimes.length;
          }
        });
      });
      httpObserver.observe({ entryTypes: ['http'] });
    } catch (error) {
      // HTTP observer might not be available
    }
  }

  startMonitoring() {
    // Update metrics every 10 seconds
    this.monitoringInterval = setInterval(() => {
      this.updateMetrics();
      this.checkAlerts();
    }, 10000);

    // Take snapshots every minute
    this.snapshotInterval = setInterval(() => {
      this.takeSnapshot();
    }, 60000);
  }

  updateMetrics() {
    const now = Date.now();
    this.metrics.uptime = now - this.metrics.startTime;

    // Memory usage
    const memUsage = process.memoryUsage();
    this.metrics.memory = {
      rss: memUsage.rss,
      heapTotal: memUsage.heapTotal,
      heapUsed: memUsage.heapUsed,
      external: memUsage.external,
      heapUsedPercentage: (memUsage.heapUsed / memUsage.heapTotal) * 100,
    };

    // CPU usage
    const cpuUsage = process.cpuUsage();
    this.metrics.cpu = {
      user: cpuUsage.user / 1000, // microseconds to milliseconds
      system: cpuUsage.system / 1000,
      total: (cpuUsage.user + cpuUsage.system) / 1000,
    };

    // Event loop lag
    const start = performance.now();
    setImmediate(() => {
      this.metrics.eventLoop.lag = performance.now() - start;
    });

    // V8 heap statistics
    try {
      const heapStats = v8.getHeapStatistics();
      this.metrics.memory.v8 = {
        totalHeapSize: heapStats.total_heap_size,
        usedHeapSize: heapStats.used_heap_size,
        heapSizeLimit: heapStats.heap_size_limit,
        totalAvailableSize: heapStats.total_available_size,
      };
    } catch (error) {
      // V8 stats might not be available
    }
  }

  checkAlerts() {
    const alerts = [];

    // Memory usage alert
    if (this.metrics.memory.heapUsedPercentage > this.alerts.memoryUsage) {
      alerts.push({
        type: 'memory',
        severity: 'warning',
        message: `High memory usage: ${this.metrics.memory.heapUsedPercentage.toFixed(2)}%`,
        value: this.metrics.memory.heapUsedPercentage,
        threshold: this.alerts.memoryUsage,
        timestamp: Date.now(),
      });
    }

    // Response time alert
    if (this.metrics.requests.averageResponseTime > this.alerts.responseTime) {
      alerts.push({
        type: 'response_time',
        severity: 'warning',
        message: `High average response time: ${this.metrics.requests.averageResponseTime.toFixed(2)}ms`,
        value: this.metrics.requests.averageResponseTime,
        threshold: this.alerts.responseTime,
        timestamp: Date.now(),
      });
    }

    // Error rate alert
    const errorRate =
      this.metrics.requests.total > 0
        ? (this.metrics.requests.failed / this.metrics.requests.total) * 100
        : 0;

    if (errorRate > this.alerts.errorRate) {
      alerts.push({
        type: 'error_rate',
        severity: 'error',
        message: `High error rate: ${errorRate.toFixed(2)}%`,
        value: errorRate,
        threshold: this.alerts.errorRate,
        timestamp: Date.now(),
      });
    }

    this.metrics.alerts.push(...alerts);

    // Keep only last 100 alerts
    if (this.metrics.alerts.length > 100) {
      this.metrics.alerts = this.metrics.alerts.slice(-100);
    }

    return alerts;
  }

  takeSnapshot() {
    const snapshot = {
      timestamp: Date.now(),
      uptime: this.metrics.uptime,
      memory: { ...this.metrics.memory },
      cpu: { ...this.metrics.cpu },
      requests: { ...this.metrics.requests },
      database: { ...this.metrics.database },
      cache: { ...this.metrics.cache },
    };

    this.snapshots.push(snapshot);

    // Keep only max snapshots
    if (this.snapshots.length > this.maxSnapshots) {
      this.snapshots.shift();
    }
  }

  // Public API methods
  recordRequest(startTime, endTime, success = true) {
    this.metrics.requests.total++;
    this.metrics.requests.active++;

    const responseTime = endTime - startTime;
    this.metrics.requests.responseTimes.push(responseTime);

    if (success) {
      this.metrics.requests.completed++;
    } else {
      this.metrics.requests.failed++;
    }

    // Update average response time
    this.metrics.requests.averageResponseTime =
      this.metrics.requests.responseTimes.reduce((a, b) => a + b, 0) /
      this.metrics.requests.responseTimes.length;

    this.metrics.requests.active--;
  }

  recordDatabaseQuery(duration, slow = false) {
    this.metrics.database.queries++;
    if (slow) {
      this.metrics.database.slowQueries++;
    }
  }

  recordCacheOperation(hit = true) {
    if (hit) {
      this.metrics.cache.hits++;
    } else {
      this.metrics.cache.misses++;
    }

    const total = this.metrics.cache.hits + this.metrics.cache.misses;
    this.metrics.cache.hitRate =
      total > 0 ? (this.metrics.cache.hits / total) * 100 : 0;
  }

  updateDatabaseConnections(active, pool = {}) {
    this.metrics.database.connections = active;
    this.metrics.database.connectionPool = pool;
  }

  updateCacheSize(size) {
    this.metrics.cache.size = size;
  }

  getMetrics() {
    return { ...this.metrics };
  }

  getSnapshots() {
    return [...this.snapshots];
  }

  getAlerts(since = 0) {
    return this.metrics.alerts.filter((alert) => alert.timestamp > since);
  }

  generateReport() {
    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        uptime: this.formatUptime(this.metrics.uptime),
        totalRequests: this.metrics.requests.total,
        averageResponseTime: `${this.metrics.requests.averageResponseTime.toFixed(2)}ms`,
        memoryUsage: `${this.metrics.memory.heapUsedPercentage.toFixed(2)}%`,
        errorRate:
          this.metrics.requests.total > 0
            ? `${((this.metrics.requests.failed / this.metrics.requests.total) * 100).toFixed(2)}%`
            : '0%',
        cacheHitRate: `${this.metrics.cache.hitRate.toFixed(2)}%`,
      },
      alerts: this.metrics.alerts.slice(-10), // Last 10 alerts
      recommendations: this.generateRecommendations(),
    };

    return report;
  }

  generateRecommendations() {
    const recommendations = [];

    if (this.metrics.memory.heapUsedPercentage > 75) {
      recommendations.push(
        'Consider increasing memory limits or optimizing memory usage'
      );
    }

    if (this.metrics.requests.averageResponseTime > 500) {
      recommendations.push(
        'Consider optimizing slow endpoints or adding caching'
      );
    }

    if (this.metrics.cache.hitRate < 50) {
      recommendations.push(
        'Consider reviewing cache strategy to improve hit rate'
      );
    }

    const errorRate =
      this.metrics.requests.total > 0
        ? (this.metrics.requests.failed / this.metrics.requests.total) * 100
        : 0;

    if (errorRate > 2) {
      recommendations.push('Investigate and fix high error rates');
    }

    if (
      this.metrics.database.slowQueries >
      this.metrics.database.queries * 0.1
    ) {
      recommendations.push('Optimize slow database queries');
    }

    return recommendations;
  }

  formatUptime(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
    if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  }

  saveReport(filename = null) {
    const logsDir = path.join(__dirname, '..', 'logs');
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }

    if (!filename) {
      filename = `performance-report-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    }

    const filepath = path.join(logsDir, filename);
    const report = this.generateReport();

    fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
    return filepath;
  }

  stop() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }
    if (this.snapshotInterval) {
      clearInterval(this.snapshotInterval);
    }
  }
}

// Create singleton instance
const performanceMonitor = new PerformanceMonitor();

export default performanceMonitor;
