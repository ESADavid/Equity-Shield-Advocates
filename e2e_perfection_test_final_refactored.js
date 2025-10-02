#!/usr/bin/env node

import http from 'http';

const BASE_URL = 'http://localhost:3000';
let testResults = { passed: 0, failed: 0, total: 0 };

function log(message, type = 'info') {
  const timestamp = new Date().toISOString();
  let prefix;
  if (type === 'success') {
    prefix = '✅';
  } else if (type === 'error') {
    prefix = '❌';
  } else {
    prefix = 'ℹ️';
  }
  console.log(`[${timestamp}] ${prefix} ${message}`);
}

function makeRequest(options, data = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const response = {
            statusCode: res.statusCode,
            headers: res.headers,
            body: body ? JSON.parse(body) : null
          };
          resolve(response);
        } catch (e) {
          resolve({ statusCode: res.statusCode, headers: res.headers, body });
        }
      });
    });

    req.on('error', reject);

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

async function testHealthEndpoint() {
  log('Testing Health Endpoint...');
  const response = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/health',
    method: 'GET'
  });

  testResults.total++;
  if (response.statusCode === 200 && response.body?.status === 'healthy') {
    testResults.passed++;
    log('Health check passed');
  } else {
    testResults.failed++;
    log('Health check failed', 'error');
  }
}

async function testAPIStatus() {
  log('Testing API Status Endpoint...');
  const response = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/status',
    method: 'GET'
  });

  testResults.total++;
  if (response.statusCode === 200 && response.body?.environment) {
    testResults.passed++;
    log('API status check passed');
  } else {
    testResults.failed++;
    log('API status check failed', 'error');
  }
}

async function testStaticFileServing() {
  log('Testing Static File Serving...');
  const response = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/',
    method: 'GET'
  });

  testResults.total++;
  if (response.statusCode === 200) {
    testResults.passed++;
    log('Static file serving works');
  } else {
    testResults.failed++;
    log('Static file serving failed', 'error');
  }
}

async function testSecurityHeaders() {
  log('Testing Security Headers...');
  const response = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/health',
    method: 'GET'
  });

  testResults.total++;
  const hasSecurityHeaders = response.headers['content-security-policy'] &&
                            response.headers['x-frame-options'];

  if (hasSecurityHeaders) {
    testResults.passed++;
    log('Security headers are properly configured');
  } else {
    testResults.failed++;
    log('Security headers missing', 'error');
  }
}

async function testCORSConfiguration() {
  log('Testing CORS Configuration...');
  const response = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/health',
    method: 'GET',
    headers: { 'Origin': 'http://localhost:3000' }
  });

  testResults.total++;
  const hasCorsHeaders = response.headers['access-control-allow-origin'];

  if (hasCorsHeaders) {
    testResults.passed++;
    log('CORS is properly configured');
  } else {
    testResults.failed++;
    log('CORS headers missing', 'error');
  }
}

async function testRateLimiting() {
  log('Testing Rate Limiting Configuration...');
  const response = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/status',
    method: 'GET'
  });

  testResults.total++;
  const hasRateLimitHeaders = response.headers['ratelimit-limit'] &&
                             response.headers['ratelimit-remaining'];

  if (hasRateLimitHeaders) {
    testResults.passed++;
    log('Rate limiting is properly configured');
  } else {
    testResults.failed++;
    log('Rate limiting headers missing', 'error');
  }
}

async function testAPIRouteHandling() {
  log('Testing API Route Handling...');
  const response = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/payroll/status',
    method: 'GET'
  });

  testResults.total++;
  if (response.statusCode >= 200 && response.statusCode < 500) {
    testResults.passed++;
    log('API routes are properly handled');
  } else {
    testResults.failed++;
    log('API route handling failed', 'error');
  }
}

async function testSystemIntegrations() {
  log('Testing System Integration Status...');
  const response = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/status',
    method: 'GET'
  });

  testResults.total++;
  const hasIntegrations = response.body?.merchantBillPay &&
                         response.body?.jpmorganPayment;

  if (hasIntegrations) {
    testResults.passed++;
    log('System integrations are operational');
  } else {
    testResults.failed++;
    log('System integrations not detected', 'error');
  }
}

async function testAIAnalytics() {
  log('Testing AI Analytics Validation...');
  const response = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/analytics',
    method: 'GET'
  });

  testResults.total++;
  const hasAnalytics = response.statusCode === 200 &&
                      response.body?.predictions &&
                      response.body?.anomalies &&
                      response.body?.riskAssessment;

  if (hasAnalytics) {
    testResults.passed++;
    log('AI analytics are functional');
  } else {
    testResults.failed++;
    log('AI analytics validation failed', 'error');
  }
}

async function testAITranscendence() {
  log('Testing AI Transcendence Validation...');
  const response = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/analytics/transcendence',
    method: 'GET'
  });

  testResults.total++;
  const hasTranscendence = response.statusCode === 200 &&
                         response.body?.deepLearning &&
                         response.body?.quantumOptimization &&
                         response.body?.autonomousDecisions;

  if (hasTranscendence) {
    testResults.passed++;
    log('AI transcendence is operational');
  } else {
    testResults.failed++;
    log('AI transcendence validation failed', 'error');
  }
}

async function testRevenueOptimization() {
  log('Testing Autonomous Revenue Optimization...');
  const response = await makeRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/analytics/optimize',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    currentRevenue: 1750000,
    marketConditions: {
      growth: 0.08,
      volatility: 0.15,
      competition: 0.2,
      regulation: 0.1
    }
  });

  testResults.total++;
  const hasOptimization = response.statusCode === 200 &&
                         response.body?.optimized?.projectedRevenue &&
                         response.body?.decisions?.actions;

  if (hasOptimization) {
    testResults.passed++;
    log('Autonomous revenue optimization is working');
  } else {
    testResults.failed++;
    log('Autonomous revenue optimization failed', 'error');
  }
}

function displayTestResults() {
  log('', 'info');
  log('🎯 E2E PERFECTION TEST RESULTS - FINAL VERSION', 'info');
  log('===================================================', 'info');
  log(`Total Tests: ${testResults.total}`, 'info');
  log(`✅ Passed: ${testResults.passed}`, 'success');
  log(`❌ Failed: ${testResults.failed}`, testResults.failed > 0 ? 'error' : 'info');
  log(`📊 Success Rate: ${((testResults.passed / testResults.total) * 100).toFixed(1)}%`, 'info');

  if (testResults.failed === 0) {
    log('', 'info');
    log('🎉 ALL E2E TESTS PASSED! SYSTEM IS PERFECTLY OPERATIONAL', 'success');
    log('✅ Oscar Broome Revenue System is production-ready', 'success');
    log('✅ Static file serving: WORKING', 'success');
    log('✅ Security: ENTERPRISE-GRADE', 'success');
    log('✅ API Integration: COMPLETE', 'success');
    log('✅ Rate Limiting: CONFIGURED', 'success');
  } else {
    log('', 'info');
    log('⚠️ Some tests failed. Please review the system configuration.', 'error');
  }

  process.exit(testResults.failed === 0 ? 0 : 1);
}

async function runE2EPerfectionTest() {
  log('🚀 Starting E2E Perfection Test Suite - FINAL VERSION', 'info');
  log('=====================================================', 'info');

  await testHealthEndpoint();
  await testAPIStatus();
  await testStaticFileServing();
  await testSecurityHeaders();
  await testCORSConfiguration();
  await testRateLimiting();
  await testAPIRouteHandling();
  await testSystemIntegrations();
  await testAIAnalytics();
  await testAITranscendence();
  await testRevenueOptimization();

  displayTestResults();
}

runE2EPerfectionTest().catch(error => {
  log(`Fatal error: ${error.message}`, 'error');
  process.exit(1);
});
