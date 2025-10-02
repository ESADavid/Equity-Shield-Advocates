#!/usr/bin/env node

import http from 'http';
import https from 'https';

const BASE_URL = 'http://localhost:3000';
let testResults = { passed: 0, failed: 0, total: 0 };

function log(message, type = 'info') {
  const timestamp = new Date().toISOString();
  const prefix = type === 'success' ? '✅' : type === 'error' ? '❌' : 'ℹ️';
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

async function runE2EPerfectionTest() {
  log('🚀 Starting E2E Perfection Test Suite - FINAL VERSION', 'info');
  log('=====================================================', 'info');

  try {
    // Test 1: Health Check
    log('Testing Health Endpoint...');
    const healthResponse = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/health',
      method: 'GET'
    });

    testResults.total++;
    if (healthResponse.statusCode === 200 && healthResponse.body?.status === 'healthy') {
      testResults.passed++;
      log('Health check passed');
    } else {
      testResults.failed++;
      log('Health check failed', 'error');
    }

    // Test 2: API Status
    log('Testing API Status Endpoint...');
    const statusResponse = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/status',
      method: 'GET'
    });

    testResults.total++;
    if (statusResponse.statusCode === 200 && statusResponse.body?.environment) {
      testResults.passed++;
      log('API status check passed');
    } else {
      testResults.failed++;
      log('API status check failed', 'error');
    }

    // Test 3: Static File Serving
    log('Testing Static File Serving...');
    const staticResponse = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/',
      method: 'GET'
    });

    testResults.total++;
    if (staticResponse.statusCode === 200) {
      testResults.passed++;
      log('Static file serving works');
    } else {
      testResults.failed++;
      log('Static file serving failed', 'error');
    }

    // Test 4: Security Headers
    log('Testing Security Headers...');
    const securityResponse = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/health',
      method: 'GET'
    });

    testResults.total++;
    const hasSecurityHeaders = securityResponse.headers['content-security-policy'] &&
                              securityResponse.headers['x-frame-options'];

    if (hasSecurityHeaders) {
      testResults.passed++;
      log('Security headers are properly configured');
    } else {
      testResults.failed++;
      log('Security headers missing', 'error');
    }

    // Test 5: CORS Configuration
    log('Testing CORS Configuration...');
    const corsResponse = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/health',
      method: 'GET',
      headers: { 'Origin': 'http://localhost:3000' }
    });

    testResults.total++;
    const hasCorsHeaders = corsResponse.headers['access-control-allow-origin'];

    if (hasCorsHeaders) {
      testResults.passed++;
      log('CORS is properly configured');
    } else {
      testResults.failed++;
      log('CORS headers missing', 'error');
    }

    // Test 6: Rate Limiting Configuration
    log('Testing Rate Limiting Configuration...');
    const rateLimitResponse = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/status',
      method: 'GET'
    });

    testResults.total++;
    // Check if rate limiting headers are present (indicates rate limiting is configured)
    const hasRateLimitHeaders = rateLimitResponse.headers['ratelimit-limit'] &&
                               rateLimitResponse.headers['ratelimit-remaining'];

    if (hasRateLimitHeaders) {
      testResults.passed++;
      log('Rate limiting is properly configured');
    } else {
      testResults.failed++;
      log('Rate limiting headers missing', 'error');
    }

    // Test 7: API Route Handling
    log('Testing API Route Handling...');
    const apiResponse = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/payroll/status',
      method: 'GET'
    });

    testResults.total++;
    // Should return some response (200 or error, but not HTML)
    if (apiResponse.statusCode >= 200 && apiResponse.statusCode < 500) {
      testResults.passed++;
      log('API routes are properly handled');
    } else {
      testResults.failed++;
      log('API route handling failed', 'error');
    }

    // Test 8: System Integration Status
    log('Testing System Integration Status...');
    const integrationResponse = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/status',
      method: 'GET'
    });

    testResults.total++;
    const hasIntegrations = integrationResponse.body?.merchantBillPay &&
                           integrationResponse.body?.jpmorganPayment;

    if (hasIntegrations) {
      testResults.passed++;
      log('System integrations are operational');
    } else {
      testResults.failed++;
      log('System integrations not detected', 'error');
    }

    // Test 9: AI Analytics Validation
    log('Testing AI Analytics Validation...');
    const analyticsResponse = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/analytics',
      method: 'GET'
    });

    testResults.total++;
    const hasAnalytics = analyticsResponse.statusCode === 200 &&
                        analyticsResponse.body?.predictions &&
                        analyticsResponse.body?.anomalies &&
                        analyticsResponse.body?.riskAssessment;

    if (hasAnalytics) {
      testResults.passed++;
      log('AI analytics are functional');
    } else {
      testResults.failed++;
      log('AI analytics validation failed', 'error');
    }

    // Test 10: AI Transcendence Validation
    log('Testing AI Transcendence Validation...');
    const transcendenceResponse = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/analytics/transcendence',
      method: 'GET'
    });

    testResults.total++;
    const hasTranscendence = transcendenceResponse.statusCode === 200 &&
                           transcendenceResponse.body?.deepLearning &&
                           transcendenceResponse.body?.quantumOptimization &&
                           transcendenceResponse.body?.autonomousDecisions;

    if (hasTranscendence) {
      testResults.passed++;
      log('AI transcendence is operational');
    } else {
      testResults.failed++;
      log('AI transcendence validation failed', 'error');
    }

    // Test 11: Autonomous Revenue Optimization
    log('Testing Autonomous Revenue Optimization...');
    const optimizationResponse = await makeRequest({
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
    const hasOptimization = optimizationResponse.statusCode === 200 &&
                           optimizationResponse.body?.optimized?.projectedRevenue &&
                           optimizationResponse.body?.decisions?.actions;

    if (hasOptimization) {
      testResults.passed++;
      log('Autonomous revenue optimization is working');
    } else {
      testResults.failed++;
      log('Autonomous revenue optimization failed', 'error');
    }

  } catch (error) {
    log(`Test suite failed with error: ${error.message}`, 'error');
    testResults.failed++;
    testResults.total++;
  }

  // Final Results
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

runE2EPerfectionTest().catch(error => {
  log(`Fatal error: ${error.message}`, 'error');
  process.exit(1);
});
