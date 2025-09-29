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
  log('🚀 Starting E2E Perfection Test Suite', 'info');
  log('=====================================', 'info');

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

    // Test 3: 404 Handling
    log('Testing 404 Error Handling...');
    const notFoundResponse = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/nonexistent-endpoint',
      method: 'GET'
    });

    testResults.total++;
    if (notFoundResponse.statusCode === 404) {
      testResults.passed++;
      log('404 handling works correctly');
    } else {
      testResults.failed++;
      log('404 handling failed', 'error');
    }

    // Test 4: Rate Limiting
    log('Testing Rate Limiting...');
    const rateLimitPromises = [];
    for (let i = 0; i < 15; i++) {
      rateLimitPromises.push(makeRequest({
        hostname: 'localhost',
        port: 3000,
        path: '/api/status',
        method: 'GET'
      }));
    }

    const rateLimitResults = await Promise.all(rateLimitPromises);
    const rateLimited = rateLimitResults.some(res => res.statusCode === 429);

    testResults.total++;
    if (rateLimited) {
      testResults.passed++;
      log('Rate limiting is working');
    } else {
      testResults.failed++;
      log('Rate limiting may not be working properly', 'error');
    }

    // Test 5: Security Headers
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

    // Test 6: CORS Headers
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

    // Test 7: Static File Serving
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

    // Test 8: Error Handling Middleware
    log('Testing Error Handling...');
    const errorResponse = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/payroll/invalid-endpoint',
      method: 'GET'
    });

    testResults.total++;
    // Should return 404 or appropriate error, not crash
    if (errorResponse.statusCode >= 400) {
      testResults.passed++;
      log('Error handling middleware works');
    } else {
      testResults.failed++;
      log('Error handling may not be working', 'error');
    }

  } catch (error) {
    log(`Test suite failed with error: ${error.message}`, 'error');
    testResults.failed++;
    testResults.total++;
  }

  // Final Results
  log('', 'info');
  log('🎯 E2E PERFECTION TEST RESULTS', 'info');
  log('================================', 'info');
  log(`Total Tests: ${testResults.total}`, 'info');
  log(`✅ Passed: ${testResults.passed}`, 'success');
  log(`❌ Failed: ${testResults.failed}`, testResults.failed > 0 ? 'error' : 'info');
  log(`📊 Success Rate: ${((testResults.passed / testResults.total) * 100).toFixed(1)}%`, 'info');

  if (testResults.failed === 0) {
    log('', 'info');
    log('🎉 ALL E2E TESTS PASSED! SYSTEM IS PERFECTLY OPERATIONAL', 'success');
    log('✅ Oscar Broome Revenue System is production-ready', 'success');
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
