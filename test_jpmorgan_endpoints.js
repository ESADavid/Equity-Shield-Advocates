const axios = require('axios');

const BASE_URL = process.env.JPMORGAN_TEST_BASE_URL || 'http://localhost:3000/jpmorgan';

class JPMorganTester {
  constructor() {
    this.baseURL = BASE_URL;
    this.testResults = {
      passed: 0,
      failed: 0,
      total: 0
    };
  }

  async runTest(testName, testFunction) {
    console.log(`\n🧪 Running test: ${testName}`);
    this.testResults.total++;

    try {
      await testFunction();
      console.log(`✅ ${testName} - PASSED`);
      this.testResults.passed++;
    } catch (error) {
      console.log(`❌ ${testName} - FAILED`);
      console.log(`   Error: ${error.message}`);
      if (error.response) {
        console.log(`   Status: ${error.response.status}`);
        console.log(`   Data: ${JSON.stringify(error.response.data, null, 2)}`);
      }
      this.testResults.failed++;
    }
  }

  async testHealthCheck() {
    const response = await axios.get(`${this.baseURL}/health`, { timeout: 10000 });
    if (response.data.status !== 'healthy') {
      throw new Error('Health check failed');
    }
  }

  async testTreasuryHealth() {
    const response = await axios.get(`${this.baseURL}/treasury/health`, { timeout: 10000 });
    if (response.data.status !== 'healthy') {
      throw new Error('Treasury health check failed');
    }
  }

  async testInvalidPaymentCreation() {
    try {
      await axios.post(`${this.baseURL}/create-payment`, {});
      throw new Error('Should have failed with invalid data');
    } catch (error) {
      if (error.response?.status !== 400) {
        throw new Error('Expected 400 status for invalid payment data');
      }
    }
  }

  async testCashPositions() {
    const response = await axios.get(`${this.baseURL}/treasury/cash-positions?currency=USD`);
    if (!response.data.success) {
      throw new Error('Cash positions request failed');
    }
  }

  async testFXRates() {
    const response = await axios.get(`${this.baseURL}/treasury/fx-rates?baseCurrency=USD&quoteCurrency=EUR`);
    if (!response.data.success) {
      throw new Error('FX rates request failed');
    }
  }

  async testLiquidityForecast() {
    const response = await axios.get(`${this.baseURL}/treasury/liquidity-forecast?days=30&currency=USD`);
    if (!response.data.success) {
      throw new Error('Liquidity forecast request failed');
    }
  }

  async testPortfolioPerformance() {
    const response = await axios.get(`${this.baseURL}/treasury/portfolio-performance?period=1M&currency=USD`);
    if (!response.data.success) {
      throw new Error('Portfolio performance request failed');
    }
  }

  async testCashFlowAnalytics() {
    const response = await axios.get(`${this.baseURL}/treasury/cash-flow-analytics?granularity=daily&currency=USD`);
    if (!response.data.success) {
      throw new Error('Cash flow analytics request failed');
    }
  }

  async testTransactionHistory() {
    const response = await axios.get(`${this.baseURL}/transactions?limit=5`);
    if (!response.data.success) {
      throw new Error('Transaction history request failed');
    }
  }

  async runAllTests() {
    console.log('🚀 Starting JPMorgan Payment Integration Tests');
    console.log('=' .repeat(50));

    // Basic health checks
    await this.runTest('Health Check', () => this.testHealthCheck());
    await this.runTest('Treasury Health Check', () => this.testTreasuryHealth());

    // Error handling tests
    await this.runTest('Invalid Payment Creation', () => this.testInvalidPaymentCreation());

    // Treasury endpoints
    await this.runTest('Cash Positions', () => this.testCashPositions());
    await this.runTest('FX Rates', () => this.testFXRates());
    await this.runTest('Liquidity Forecast', () => this.testLiquidityForecast());
    await this.runTest('Portfolio Performance', () => this.testPortfolioPerformance());
    await this.runTest('Cash Flow Analytics', () => this.testCashFlowAnalytics());

    // Transaction endpoints
    await this.runTest('Transaction History', () => this.testTransactionHistory());

    // Results summary
    console.log('\n' + '=' .repeat(50));
    console.log('📊 Test Results Summary:');
    console.log(`Total Tests: ${this.testResults.total}`);
    console.log(`Passed: ${this.testResults.passed}`);
    console.log(`Failed: ${this.testResults.failed}`);
    console.log(`Success Rate: ${((this.testResults.passed / this.testResults.total) * 100).toFixed(1)}%`);

    if (this.testResults.failed === 0) {
      console.log('🎉 All tests passed!');
    } else {
      console.log('⚠️  Some tests failed. Check the output above for details.');
    }
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  const tester = new JPMorganTester();
  tester.runAllTests().catch(console.error);
}

module.exports = JPMorganTester;
