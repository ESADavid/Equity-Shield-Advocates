// @ts-nocheck
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
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
}

/**
 * Test cash positions endpoint
 */
async function testCashPositions() {
  testResults.total++;

  try {
    const response = await makeRequest(
      'GET',
      '/jpmorgan/treasury/cash-positions'
    );

    if (response.status === 200 && response.data) {
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
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
  testResults.total++;

  try {
    const response = await makeRequest('GET', '/jpmorgan/treasury/fx-rates');

    if (response.status === 200 && response.data) {
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
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
  testResults.total++;

  try {
    const response = await makeRequest(
      'GET',
      '/jpmorgan/treasury/liquidity-forecast'
    );

    if (response.status === 200 && response.data) {
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
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
  testResults.total++;

  try {
    const response = await makeRequest(
      'GET',
      '/jpmorgan/treasury/risk-exposure'
    );

    if (response.status === 200 && response.data) {
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
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
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
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
  testResults.total++;

  try {
    const response = await makeRequest(
      'GET',
      '/jpmorgan/treasury/portfolio-performance'
    );

    if (response.status === 200 && response.data) {
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
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
  testResults.total++;

  try {
    const response = await makeRequest(
      'GET',
      '/jpmorgan/treasury/cash-flow-analytics'
    );

    if (response.status === 200 && response.data) {
      testResults.passed++;
      return true;
    } else {
      throw new Error('Invalid response format');
    }
  } catch (error) {
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
  testResults.total++;

  try {
    const response = await makeRequest('GET', '/jpmorgan/treasury/health');

    if (
      response.status === 200 &&
      response.data &&
      response.data.status === 'healthy'
    ) {
      testResults.passed++;
      return true;
    } else {
      throw new Error('Treasury service is not healthy');
    }
  } catch (error) {
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
      testResults.passed++;
      return true;
    } else {
      throw new Error(`Only ${successful}/6 operations succeeded`);
    }
  } catch (error) {
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
}

/**
 * Main test runner
 */
async function runComprehensiveTreasuryTests() {
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

    if (testResults.failed > 0) {
      process.exit(1);
    }

    if (testResults.passed === testResults.total) {
      process.exit(0);
    } else {
      process.exit(1);
    }
  } catch (error) {
    process.exit(1);
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
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
