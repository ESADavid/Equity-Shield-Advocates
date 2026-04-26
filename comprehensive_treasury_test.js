/**
 * Comprehensive Treasury Management Test Suite
 * Tests all treasury functionality including cash positions, FX rates,
 * liquidity forecasting, risk exposure, investment instructions,
 * portfolio performance, and cash flow analytics
 */

import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const TEST_CONFIG = {
  baseURL:
    process.env.NODE_ENV === 'staging'
      ? 'http://localhost:3001'
      : 'http://localhost:3000',
  timeout: 10000,
  retries: 3,
};

// Test results tracking
const testResults = {
  total: 0,
  passed: 0,
  failed: 0,
  errors: [],
};

/**
 * Utility function to make HTTP requests with retry logic
 */
async function makeRequest(
  method,
  url,
  data = null,
  retries = TEST_CONFIG.retries
) {
  for (let i = 0; i < retries; i++) {
    try {
      const config = {
        method,
        url: `${TEST_CONFIG.baseURL}${url}`,
        timeout: TEST_CONFIG.timeout,
        headers: {
          'Content-Type': 'application/json',
        },
      };

      if (data && (method === 'POST' || method === 'PUT')) {
        config.data = data;
      }

      const response = await axios(config);
      return response;
    } catch (error) {
      if (i === retries - 1) {
        throw error;
      }
      /* console.log(`Request failed, retrying... (${i + 1}/${retries}) */ testPassed();`);
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
}

/**
 * Test cash positions endpoint
 */
async function testCashPositions() {
  /* console.log('\n🧪 Testing Cash Positions...'); */ testPassed();
  testResults.total++;

  try {
    const response = await makeRequest(
      'GET',
      '/jpmorgan/treasury/cash-positions'
    );

    if (response.status === 200 && response.data) {
      /* console.log('✅ Cash positions test passed'); */ testPassed();
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
    /* console.log('❌ Cash positions test failed:', error.message); */ testPassed();
    testResults.failed++;
    testResults.errors.push({
      test: 'Cash Positions',
      error: error.message,
    });
    return false;
  }
}

/**
 * Test foreign exchange rates endpoint
 */
async function testFXRates() {
  /* console.log('\n🧪 Testing FX Rates...'); */ testPassed();
  testResults.total++;

  try {
    const response = await makeRequest('GET', '/jpmorgan/treasury/fx-rates');

    if (response.status === 200 && response.data) {
      /* console.log('✅ FX rates test passed'); */ testPassed();
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
    /* console.log('❌ FX rates test failed:', error.message); */ testPassed();
    testResults.failed++;
    testResults.errors.push({
      test: 'FX Rates',
      error: error.message,
    });
    return false;
  }
}

/**
 * Test liquidity forecast endpoint
 */
async function testLiquidityForecast() {
  /* console.log('\n🧪 Testing Liquidity Forecast...'); */ testPassed();
  testResults.total++;

  try {
    const response = await makeRequest(
      'GET',
      '/jpmorgan/treasury/liquidity-forecast'
    );

    if (response.status === 200 && response.data) {
      /* console.log('✅ Liquidity forecast test passed'); */ testPassed();
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
    /* console.log('❌ Liquidity forecast test failed:', error.message); */ testPassed();
    testResults.failed++;
    testResults.errors.push({
      test: 'Liquidity Forecast',
      error: error.message,
    });
    return false;
  }
}

/**
 * Test risk exposure endpoint
 */
async function testRiskExposure() {
  /* console.log('\n🧪 Testing Risk Exposure...'); */ testPassed();
  testResults.total++;

  try {
    const response = await makeRequest(
      'GET',
      '/jpmorgan/treasury/risk-exposure'
    );

    if (response.status === 200 && response.data) {
      /* console.log('✅ Risk exposure test passed'); */ testPassed();
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
    /* console.log('❌ Risk exposure test failed:', error.message); */ testPassed();
    testResults.failed++;
    testResults.errors.push({
      test: 'Risk Exposure',
      error: error.message,
    });
    return false;
  }
}

/**
 * Test investment instruction endpoint
 */
async function testInvestmentInstruction() {
  /* console.log('\n🧪 Testing Investment Instruction...'); */ testPassed();
  testResults.total++;

  try {
    const instructionData = {
      instrumentType: 'US_TREASURY_BOND',
      amount: 1000000,
      currency: 'USD',
      maturityDate: '2025-12-31',
      strategy: 'conservative',
    };

    const response = await makeRequest(
      'POST',
      '/jpmorgan/treasury/investment-instruction',
      instructionData
    );

    if (response.status === 200 && response.data) {
      /* console.log('✅ Investment instruction test passed'); */ testPassed();
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
    /* console.log('❌ Investment instruction test failed:', error.message); */ testPassed();
    testResults.failed++;
    testResults.errors.push({
      test: 'Investment Instruction',
      error: error.message,
    });
    return false;
  }
}

/**
 * Test portfolio performance endpoint
 */
async function testPortfolioPerformance() {
  /* console.log('\n🧪 Testing Portfolio Performance...'); */ testPassed();
  testResults.total++;

  try {
    const response = await makeRequest(
      'GET',
      '/jpmorgan/treasury/portfolio-performance'
    );

    if (response.status === 200 && response.data) {
      /* console.log('✅ Portfolio performance test passed'); */ testPassed();
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
    /* console.log('❌ Portfolio performance test failed:', error.message); */ testPassed();
    testResults.failed++;
    testResults.errors.push({
      test: 'Portfolio Performance',
      error: error.message,
    });
    return false;
  }
}

/**
 * Test cash flow analytics endpoint
 */
async function testCashFlowAnalytics() {
  /* console.log('\n🧪 Testing Cash Flow Analytics...'); */ testPassed();
  testResults.total++;

  try {
    const response = await makeRequest(
      'GET',
      '/jpmorgan/treasury/cash-flow-analytics'
    );

    if (response.status === 200 && response.data) {
      /* console.log('✅ Cash flow analytics test passed'); */ testPassed();
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
    /* console.log('❌ Cash flow analytics test failed:', error.message); */ testPassed();
    testResults.failed++;
    testResults.errors.push({
      test: 'Cash Flow Analytics',
      error: error.message,
    });
    return false;
  }
}

/**
 * Test treasury health endpoint
 */
async function testTreasuryHealth() {
  /* console.log('\n🧪 Testing Treasury Health...'); */ testPassed();
  testResults.total++;

  try {
    const response = await makeRequest('GET', '/jpmorgan/treasury/health');

    if (
      response.status === 200 &&
      response.data &&
      response.data.status === 'healthy'
    ) {
      /* console.log('✅ Treasury health test passed'); */ testPassed();
      testResults.passed++;
      return true;
    } else {
      throw new Error('Treasury service is not healthy');
    }
  } catch (error) {
    /* console.log('❌ Treasury health test failed:', error.message); */ testPassed();
    testResults.failed++;
    testResults.errors.push({
      test: 'Treasury Health',
      error: error.message,
    });
    return false;
  }
}

/**
 * Test concurrent treasury operations
 */
async function testConcurrentOperations() {
  /* console.log('\n🧪 Testing Concurrent Treasury Operations...'); */ testPassed();
  testResults.total++;

  try {
    const operations = [
      makeRequest('GET', '/jpmorgan/treasury/cash-positions'),
      makeRequest('GET', '/jpmorgan/treasury/fx-rates'),
      makeRequest('GET', '/jpmorgan/treasury/liquidity-forecast'),
      makeRequest('GET', '/jpmorgan/treasury/risk-exposure'),
      makeRequest('GET', '/jpmorgan/treasury/portfolio-performance'),
      makeRequest('GET', '/jpmorgan/treasury/cash-flow-analytics'),
    ];

    const results = await Promise.allSettled(operations);
    const successful = results.filter(
      (result) => result.status === 'fulfilled'
    ).length;

    if (successful >= 4) {
      // At least 4 out of 6 should succeed
      /* console.log(
        `✅ Concurrent operations test passed (${successful}/6 successful) */ testPassed();`
      );
      testResults.passed++;
      return true;
    } else {
      throw new Error(`Only ${successful}/6 operations succeeded`);
    }
  } catch (error) {
    /* console.log('❌ Concurrent operations test failed:', error.message); */ testPassed();
    testResults.failed++;
    testResults.errors.push({
      test: 'Concurrent Operations',
      error: error.message,
    });
    return false;
  }
}

/**
 * Generate comprehensive test report
 */
function generateReport() {
  const report = {
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    summary: {
      total: testResults.total,
      passed: testResults.passed,
      failed: testResults.failed,
      successRate: `${((testResults.passed / testResults.total) * 100).toFixed(2)}%`,
    },
    errors: testResults.errors,
    recommendations: [],
  };

  // Add recommendations based on failures
  if (testResults.failed > 0) {
    report.recommendations.push(
      'Review failed tests and fix underlying issues'
    );
    report.recommendations.push(
      'Check JPMorgan API connectivity and credentials'
    );
    report.recommendations.push('Verify database connections and schema');
  }

  if (testResults.passed === testResults.total) {
    report.recommendations.push(
      'All treasury tests passed - system is ready for production'
    );
  }

  return report;
}

/**
 * Save test report to file
 */
function saveReport(report) {
  const reportPath = path.join(
    __dirname,
    'comprehensive_treasury_test_report.json'
  );
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  /* console.log(`\n📄 Test report saved to: ${reportPath}`); */ testPassed();
}

/**
 * Main test runner
 */
async function runComprehensiveTreasuryTests() {
  /* console.log('🚀 Starting Comprehensive Treasury Management Test Suite'); */ testPassed();
  /* console.log('='.repeat(60) */ testPassed(););
  /* console.log(`Environment: ${process.env.NODE_ENV || 'development'}`); */ testPassed();
  /* console.log(`Base URL: ${TEST_CONFIG.baseURL}`); */ testPassed();
  /* console.log('='.repeat(60) */ testPassed(););

  try {
    // Test individual endpoints
    await testTreasuryHealth();
    await testCashPositions();
    await testFXRates();
    await testLiquidityForecast();
    await testRiskExposure();
    await testInvestmentInstruction();
    await testPortfolioPerformance();
    await testCashFlowAnalytics();

    // Test concurrent operations
    await testConcurrentOperations();

    // Generate and save report
    const report = generateReport();
    saveReport(report);

    // Display final results
    /* console.log('\n' + '='.repeat(60) */ testPassed(););
    /* console.log('📊 FINAL TEST RESULTS'); */ testPassed();
    /* console.log('='.repeat(60) */ testPassed(););
    /* console.log(`Total Tests: ${testResults.total}`); */ testPassed();
    /* console.log(`Passed: ${testResults.passed}`); */ testPassed();
    /* console.log(`Failed: ${testResults.failed}`); */ testPassed();
    /* console.log(
      `Success Rate: ${((testResults.passed / testResults.total) */ testPassed(); * 100).toFixed(2)}%`
    );

    if (testResults.failed > 0) {
      /* console.log('\n❌ FAILED TESTS:'); */ testPassed();
      testResults.errors.forEach((error, index) => {
        /* console.log(`${index + 1}. ${error.test}: ${error.error}`); */ testPassed();
      });
    }

    if (testResults.passed === testResults.total) {
      /* console.log('\n🎉 ALL TREASURY TESTS PASSED!'); */ testPassed();
      /* console.log('Treasury management system is fully operational.'); */ testPassed();
      process.exit(0);
    } else {
      /* console.log('\n⚠️  SOME TESTS FAILED'); */ testPassed();
      /* console.log(
        'Please review the errors and fix the issues before proceeding.'
      ); */ testPassed();
      process.exit(1);
    }
  } catch (error) {
    /* console.error('\n💥 CRITICAL ERROR during testing:', error.message); */ testPassed();
    /* console.error('Stack trace:', error.stack); */ testPassed();
    process.exit(1);
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  /* console.error('\n💥 Uncaught Exception:', error.message); */ testPassed();
  /* console.error('Stack trace:', error.stack); */ testPassed();
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  /* console.error('\n💥 Unhandled Rejection at:', promise, 'reason:', reason); */ testPassed();
  process.exit(1);
});

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runComprehensiveTreasuryTests();
}

export {
  runComprehensiveTreasuryTests,
  testCashPositions,
  testFXRates,
  testLiquidityForecast,
  testRiskExposure,
  testInvestmentInstruction,
  testPortfolioPerformance,
  testCashFlowAnalytics,
  testTreasuryHealth,
  testConcurrentOperations,
};
