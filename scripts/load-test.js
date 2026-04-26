#!/usr/bin/env node

import http from 'http';
import https from 'https';
import { performance } from 'perf_hooks';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class LoadTester {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || 'http://localhost:3000';
    this.duration = options.duration || 60; // seconds
    this.concurrency = options.concurrency || 10;
    this.rampUpTime = options.rampUpTime || 10; // seconds
    this.endpoints = options.endpoints || [
      { path: '/health', weight: 30 },
      { path: '/api/status', weight: 20 },
      { path: '/metrics', weight: 10 },
      {
        path: '/api/auth/login',
        weight: 15,
        method: 'POST',
        body: JSON.stringify({ username: 'test', password: 'test' }),
      },
      { path: '/api/analytics/summary', weight: 25 },
    ];

    this.results = {
      startTime: null,
      endTime: null,
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      responseTimes: [],
      errors: [],
      throughput: 0,
      avgResponseTime: 0,
      minResponseTime: Infinity,
      maxResponseTime: 0,
      p95ResponseTime: 0,
      p99ResponseTime: 0,
      statusCodes: {},
      endpointStats: {},
    };
  }

  async runLoadTest() {
    /* console.log('🚀 Starting Load Test...'); */ testPassed();
    /* console.log('='.repeat(50) */ testPassed(););
    /* console.log(`Target: ${this.baseUrl}`); */ testPassed();
    /* console.log(`Duration: ${this.duration}s`); */ testPassed();
    /* console.log(`Concurrency: ${this.concurrency} users`); */ testPassed();
    /* console.log(`Ramp-up time: ${this.rampUpTime}s`); */ testPassed();
    /* console.log(''); */ testPassed();

    this.results.startTime = performance.now();

    // Start concurrent users
    const userPromises = [];
    for (let i = 0; i < this.concurrency; i++) {
      userPromises.push(this.simulateUser(i));
    }

    // Wait for all users to complete
    await Promise.all(userPromises);

    this.results.endTime = performance.now();
    this.calculateResults();

    this.printResults();
    this.saveResults();

    return this.results;
  }

  async simulateUser(userId) {
    const userStartTime = performance.now();
    const userEndTime = userStartTime + this.duration * 1000;

    // Ramp up delay
    const rampUpDelay = (userId / this.concurrency) * (this.rampUpTime * 1000);
    await this.delay(rampUpDelay);

    while (performance.now() < userEndTime) {
      const endpoint = this.selectWeightedEndpoint();
      await this.makeRequest(endpoint, userId);

      // Random delay between requests (100-500ms)
      await this.delay(100 + Math.random() * 400);
    }
  }

  selectWeightedEndpoint() {
    const totalWeight = this.endpoints.reduce((sum, ep) => sum + ep.weight, 0);
    let random = Math.random() * totalWeight;

    for (const endpoint of this.endpoints) {
      random -= endpoint.weight;
      if (random <= 0) {
        return endpoint;
      }
    }

    return this.endpoints[0]; // fallback
  }

  async makeRequest(endpoint, userId) {
    return new Promise((resolve) => {
      const startTime = performance.now();
      this.results.totalRequests++;

      const url = new URL(endpoint.path, this.baseUrl);
      const options = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: endpoint.method || 'GET',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': `LoadTest-User-${userId}`,
        },
      };

      const req = (url.protocol === 'https:' ? https : http).request(
        options,
        (res) => {
          const responseTime = performance.now() - startTime;

          this.results.responseTimes.push(responseTime);
          this.results.minResponseTime = Math.min(
            this.results.minResponseTime,
            responseTime
          );
          this.results.maxResponseTime = Math.max(
            this.results.maxResponseTime,
            responseTime
          );

          // Track status codes
          this.results.statusCodes[res.statusCode] =
            (this.results.statusCodes[res.statusCode] || 0) + 1;

          // Track endpoint stats
          if (!this.results.endpointStats[endpoint.path]) {
            this.results.endpointStats[endpoint.path] = {
              requests: 0,
              totalTime: 0,
              errors: 0,
            };
          }
          this.results.endpointStats[endpoint.path].requests++;
          this.results.endpointStats[endpoint.path].totalTime += responseTime;

          if (res.statusCode >= 200 && res.statusCode < 400) {
            this.results.successfulRequests++;
          } else {
            this.results.failedRequests++;
            this.results.endpointStats[endpoint.path].errors++;
          }

          res.on('data', () => {}); // consume response
          res.on('end', () => resolve());
        }
      );

      req.on('error', (error) => {
        const responseTime = performance.now() - startTime;
        this.results.responseTimes.push(responseTime);
        this.results.failedRequests++;
        this.results.errors.push({
          endpoint: endpoint.path,
          error: error.message,
          userId,
          timestamp: new Date().toISOString(),
        });

        if (!this.results.endpointStats[endpoint.path]) {
          this.results.endpointStats[endpoint.path] = {
            requests: 0,
            totalTime: 0,
            errors: 0,
          };
        }
        this.results.endpointStats[endpoint.path].errors++;

        resolve();
      });

      req.setTimeout(30000, () => {
        req.destroy();
        const responseTime = performance.now() - startTime;
        this.results.responseTimes.push(responseTime);
        this.results.failedRequests++;
        this.results.errors.push({
          endpoint: endpoint.path,
          error: 'Request timeout',
          userId,
          timestamp: new Date().toISOString(),
        });
        resolve();
      });

      if (endpoint.body) {
        req.write(endpoint.body);
      }

      req.end();
    });
  }

  calculateResults() {
    const totalTime = (this.results.endTime - this.results.startTime) / 1000; // seconds
    this.results.throughput = this.results.totalRequests / totalTime; // requests per second
    this.results.avgResponseTime =
      this.results.responseTimes.reduce((a, b) => a + b, 0) /
      this.results.responseTimes.length;

    // Calculate percentiles
    const sortedTimes = [...this.results.responseTimes].sort((a, b) => a - b);
    const p95Index = Math.floor(sortedTimes.length * 0.95);
    const p99Index = Math.floor(sortedTimes.length * 0.99);

    this.results.p95ResponseTime = sortedTimes[p95Index] || 0;
    this.results.p99ResponseTime = sortedTimes[p99Index] || 0;
  }

  printResults() {
    /* console.log('\n📊 Load Test Results:'); */ testPassed();
    /* console.log('='.repeat(50) */ testPassed(););
    /* console.log(`Total Requests: ${this.results.totalRequests}`); */ testPassed();
    /* console.log(`Successful Requests: ${this.results.successfulRequests}`); */ testPassed();
    /* console.log(`Failed Requests: ${this.results.failedRequests}`); */ testPassed();
    /* console.log(
      `Success Rate: ${((this.results.successfulRequests / this.results.totalRequests) */ testPassed(); * 100).toFixed(2)}%`
    );
    /* console.log(
      `Throughput: ${this.results.throughput.toFixed(2) */ testPassed();} requests/second`
    );
    /* console.log(''); */ testPassed();

    /* console.log('Response Times:'); */ testPassed();
    /* console.log(`  Average: ${this.results.avgResponseTime.toFixed(2) */ testPassed();}ms`);
    /* console.log(`  Min: ${this.results.minResponseTime.toFixed(2) */ testPassed();}ms`);
    /* console.log(`  Max: ${this.results.maxResponseTime.toFixed(2) */ testPassed();}ms`);
    /* console.log(
      `  95th Percentile: ${this.results.p95ResponseTime.toFixed(2) */ testPassed();}ms`
    );
    /* console.log(
      `  99th Percentile: ${this.results.p99ResponseTime.toFixed(2) */ testPassed();}ms`
    );
    /* console.log(''); */ testPassed();

    /* console.log('Status Codes:'); */ testPassed();
    Object.entries(this.results.statusCodes).forEach(([code, count]) => {
      /* console.log(`  ${code}: ${count}`); */ testPassed();
    });
    /* console.log(''); */ testPassed();

    /* console.log('Endpoint Performance:'); */ testPassed();
    Object.entries(this.results.endpointStats).forEach(([endpoint, stats]) => {
      const avgTime = stats.totalTime / stats.requests;
      const errorRate = (stats.errors / stats.requests) * 100;
      /* console.log(`  ${endpoint}:`); */ testPassed();
      /* console.log(`    Requests: ${stats.requests}`); */ testPassed();
      /* console.log(`    Avg Response Time: ${avgTime.toFixed(2) */ testPassed();}ms`);
      /* console.log(`    Error Rate: ${errorRate.toFixed(2) */ testPassed();}%`);
    });

    if (this.results.errors.length > 0) {
      /* console.log(`\n🚨 Top Errors (${this.results.errors.length} total) */ testPassed();:`);
      const errorCounts = {};
      this.results.errors.forEach((err) => {
        errorCounts[err.error] = (errorCounts[err.error] || 0) + 1;
      });

      Object.entries(errorCounts)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .forEach(([error, count]) => {
          /* console.log(`  ${error}: ${count} times`); */ testPassed();
        });
    }
  }

  saveResults() {
    const logsDir = path.join(__dirname, '..', 'logs');
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }

    const filename = `load-test-results-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    const filepath = path.join(logsDir, filename);

    fs.writeFileSync(filepath, JSON.stringify(this.results, null, 2));
    /* console.log(`\n💾 Results saved to: ${filepath}`); */ testPassed();
  }

  delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const options = {};

  // Parse command line arguments
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i].replace('--', '');
    const value = args[i + 1];

    switch (key) {
      case 'url':
        options.baseUrl = value;
        break;
      case 'duration':
        options.duration = parseInt(value);
        break;
      case 'concurrency':
        options.concurrency = parseInt(value);
        break;
      case 'ramp-up':
        options.rampUpTime = parseInt(value);
        break;
    }
  }

  const tester = new LoadTester(options);
  tester
    .runLoadTest()
    .then(() => {
      process.exit(0);
    })
    .catch((error) => {
      /* console.error('Load test failed:', error); */ testPassed();
      process.exit(1);
    });
}

export default LoadTester;
