#!/usr/bin/env node

/**
 * Phase 2 Endpoint Testing
 * Tests all Phase 2 API endpoints for basic functionality
 */

const http = require('http');

const BASE_URL = 'http://localhost:3000';
const results = {
  passed: [],
  failed: [],
  total: 0,
};

// Helper function to make HTTP requests
function makeRequest(method, path, data = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    const req = http.request(url, options, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: body ? JSON.parse(body) : null,
        });
      });
    });

    req.on('error', reject);

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

// Test function
async function testEndpoint(name, method, path, expectedStatus = 200) {
  results.total++;
  try {
    const response = await makeRequest(method, path);

    if (response.statusCode === expectedStatus) {
      results.passed.push(
        `✓ ${name}: ${method} ${path} (${response.statusCode})`
      );
      return true;
    } else {
      results.failed.push(
        `✗ ${name}: Expected ${expectedStatus}, got ${response.statusCode}`
      );
      return false;
    }
  } catch (error) {
    results.failed.push(`✗ ${name}: ${error.message}`);
    return false;
  }
}

// Main test function
async function runTests() {
  console.log('🧪 PHASE 2 ENDPOINT TESTING\n');
  console.log('='.repeat(60));

  // Wait for server to be ready
  console.log('\n⏳ Waiting for server to be ready...');
  let serverReady = false;
  for (let i = 0; i < 30; i++) {
    try {
      await makeRequest('GET', '/health');
      serverReady = true;
      console.log('✅ Server is ready!\n');
      break;
    } catch (error) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }

  if (!serverReady) {
    console.log('❌ Server did not start within 30 seconds');
    process.exit(1);
  }

  console.log('📋 Testing Phase 2 Endpoints...\n');

  // Test Partner Routes
  console.log('🤝 Partner System Endpoints:');
  await testEndpoint('Partner Health', 'GET', '/api/partners/health');
  await testEndpoint('Get Partners', 'GET', '/api/partners');
  await testEndpoint('Partner Statistics', 'GET', '/api/partners/statistics');

  // Test Citizen Portal Routes
  console.log('\n👥 Citizen Portal Endpoints:');
  await testEndpoint(
    'Citizen Portal Health',
    'GET',
    '/api/citizen-portal/health'
  );
  await testEndpoint(
    'Citizen Statistics',
    'GET',
    '/api/citizen-portal/statistics'
  );

  // Test UBI Payment Routes
  console.log('\n💵 UBI Payment Endpoints:');
  await testEndpoint('UBI Payment Health', 'GET', '/api/ubi-payments/health');
  await testEndpoint('Pending Payments', 'GET', '/api/ubi-payments/pending');

  // Test Multi-Channel Notification Routes
  console.log('\n📧 Notification Endpoints:');
  await testEndpoint(
    'Notification Health',
    'GET',
    '/api/notifications-v2/health'
  );
  await testEndpoint(
    'Notification Templates',
    'GET',
    '/api/notifications-v2/templates'
  );
  await testEndpoint(
    'Notification Statistics',
    'GET',
    '/api/notifications-v2/statistics'
  );

  // Test existing UBI Routes
  console.log('\n💰 UBI System Endpoints:');
  await testEndpoint('UBI Welcome', 'GET', '/api/ubi/welcome');
  await testEndpoint('UBI Health', 'GET', '/api/ubi/health');

  // Test existing Education Routes
  console.log('\n🎓 Education System Endpoints:');
  await testEndpoint('Education Welcome', 'GET', '/api/education/welcome');
  await testEndpoint('Education Courses', 'GET', '/api/education/courses');

  // Print results
  console.log('\n' + '='.repeat(60));
  console.log('\n📊 TEST RESULTS\n');

  if (results.passed.length > 0) {
    console.log('✅ PASSED TESTS:');
    results.passed.forEach((test) => console.log(`   ${test}`));
  }

  if (results.failed.length > 0) {
    console.log('\n❌ FAILED TESTS:');
    results.failed.forEach((test) => console.log(`   ${test}`));
  }

  console.log('\n' + '='.repeat(60));
  console.log('\n📈 SUMMARY\n');
  console.log(`   Total Tests: ${results.total}`);
  console.log(`   Passed: ${results.passed.length}`);
  console.log(`   Failed: ${results.failed.length}`);
  console.log(
    `   Success Rate: ${Math.round((results.passed.length / results.total) * 100)}%`
  );

  if (results.failed.length === 0) {
    console.log('\n🎉 ALL PHASE 2 ENDPOINTS WORKING! ✅');
    process.exit(0);
  } else {
    console.log('\n⚠️  SOME ENDPOINTS NEED ATTENTION');
    process.exit(1);
  }
}

// Run tests
runTests().catch((error) => {
  console.error('❌ Test execution failed:', error);
  process.exit(1);
});
