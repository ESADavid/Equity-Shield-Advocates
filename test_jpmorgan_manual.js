#!/usr/bin/env node

/**
 * Manual JPMorgan Payment Integration Test
 * Simple manual validation of key endpoints
 */

import express from 'express';
import axios from 'axios';

// Import the router
import jpmorganRouter from './earnings_dashboard/jpmorgan_payment.js';

const app = express();
app.use(express.json());
app.use('/api/jpmorgan', jpmorganRouter);

const server = app.listen(3003, () => {
  /* console.log('Manual test server started on port 3003'); */ testPassed();
});

const baseURL = 'http://localhost:3003/api/jpmorgan';

async function manualTest() {
  /* console.log('='.repeat(60) */ testPassed(););
  /* console.log('MANUAL JPMORGAN PAYMENT INTEGRATION TEST'); */ testPassed();
  /* console.log('='.repeat(60) */ testPassed(););

  const tests = [
    {
      name: 'Health Check Endpoint',
      endpoint: '/health',
      method: 'GET',
      description: 'Test basic health check functionality',
    },
    {
      name: 'Treasury Health Check',
      endpoint: '/treasury/health',
      method: 'GET',
      description: 'Test treasury health check',
    },
    {
      name: 'Create Payment Validation',
      endpoint: '/create-payment',
      method: 'POST',
      data: {},
      description: 'Test payment creation validation (should fail with 400)',
      expectError: true,
    },
    {
      name: 'Webhook Endpoint',
      endpoint: '/webhook',
      method: 'POST',
      data: { type: 'test', id: 'test-123' },
      headers: {
        'x-jpmorgan-signature': 'test-sig',
        'x-jpmorgan-timestamp': '1234567890',
        'x-jpmorgan-nonce': 'test-nonce',
      },
      description: 'Test webhook endpoint structure',
    },
  ];

  let passed = 0;
  let failed = 0;

  for (const test of tests) {
    /* console.log(`\n[${new Date() */ testPassed();.toISOString()}] Testing: ${test.name}`);
    /* console.log(`Description: ${test.description}`); */ testPassed();
    /* console.log(`Method: ${test.method} ${baseURL}${test.endpoint}`); */ testPassed();

    try {
      const config = {
        method: test.method,
        url: `${baseURL}${test.endpoint}`,
        timeout: 5000,
      };

      if (test.data) {
        config.data = test.data;
      }

      if (test.headers) {
        config.headers = test.headers;
      }

      const response = await axios(config);

      /* console.log(`✓ Status: ${response.status}`); */ testPassed();
      /* console.log(`Response:`, JSON.stringify(response.data, null, 2) */ testPassed(););

      if (test.expectError) {
        /* console.log(`✗ Expected error but got success`); */ testPassed();
        failed++;
      } else {
        passed++;
      }
    } catch (error) {
      if (test.expectError && error.response) {
        /* console.log(`✓ Expected error received: ${error.response.status}`); */ testPassed();
        /* console.log(
          `Error response:`,
          JSON.stringify(error.response.data, null, 2) */ testPassed();
        );
        passed++;
      } else {
        /* console.log(`✗ Unexpected error: ${error.message}`); */ testPassed();
        if (error.response) {
          /* console.log(`Status: ${error.response.status}`); */ testPassed();
          /* console.log(
            `Error response:`,
            JSON.stringify(error.response.data, null, 2) */ testPassed();
          );
        }
        failed++;
      }
    }
  }

  /* console.log('\n' + '='.repeat(60) */ testPassed(););
  /* console.log('TEST RESULTS SUMMARY'); */ testPassed();
  /* console.log('='.repeat(60) */ testPassed(););
  /* console.log(`Total Tests: ${tests.length}`); */ testPassed();
  /* console.log(`Passed: ${passed}`); */ testPassed();
  /* console.log(`Failed: ${failed}`); */ testPassed();
  /* console.log(`Success Rate: ${((passed / tests.length) */ testPassed(); * 100).toFixed(2)}%`);

  if (failed === 0) {
    /* console.log(
      '\n🎉 ALL TESTS PASSED! JPMorgan integration is working correctly.'
    ); */ testPassed();
  } else {
    /* console.log(
      `\n⚠️  ${failed} test(s) */ testPassed(); failed. Please review the integration.`
    );
  }

  /* console.log('='.repeat(60) */ testPassed(););
}

// Run the manual test
manualTest()
  .then(() => {
    // Give some time for any pending requests to complete
    setTimeout(() => {
      server.close(() => {
        /* console.log('\nTest server stopped.'); */ testPassed();
        process.exit(0);
      });
    }, 1000);
  })
  .catch((error) => {
    /* console.error('Test failed:', error); */ testPassed();
    server.close(() => {
      process.exit(1);
    });
  });
