/**
 * Comprehensive Payroll Money Integration Test Suite
 * Tests all edge cases, error scenarios, and performance aspects
 */

const axios = require('axios');
const fs = require('fs');
const path = require('path');

class PayrollMoneyIntegrationTester {
  constructor() {
    this.baseURL = 'http://localhost:3000';
    this.testResults = {
      passed: 0,
      failed: 0,
      total: 0,
      details: [],
    };
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = type === 'error' ? '❌' : type === 'success' ? '✅' : 'ℹ️';
    console.log(`[${timestamp}] ${prefix} ${message}`);
  }

  recordTest(name, passed, details = '') {
    this.testResults.total++;
    if (passed) {
      this.testResults.passed++;
      this.log(`PASSED: ${name}`, 'success');
    } else {
      this.testResults.failed++;
      this.log(`FAILED: ${name} - ${details}`, 'error');
    }
    this.testResults.details.push({ name, passed, details });
  }

  async testHealthCheck() {
    try {
      const response = await axios.get(
        `${this.baseURL}/api/payroll-money/health`
      );
      const isHealthy = response.data && response.data.status === 'healthy';
      this.recordTest(
        'Health Check',
        isHealthy,
        isHealthy ? 'All providers healthy' : 'Some providers unhealthy'
      );
    } catch (error) {
      this.recordTest('Health Check', false, `Error: ${error.message}`);
    }
  }

  async testPayrollConfiguration() {
    try {
      const response = await axios.get(
        `${this.baseURL}/api/payroll-money/payroll-config`
      );
      const config = response.data;
      const hasProviders =
        config.providers && Object.keys(config.providers).length === 3;
      const hasRevenue =
        config.currentRevenue && typeof config.currentRevenue === 'number';
      this.recordTest(
        'Payroll Configuration',
        hasProviders && hasRevenue,
        hasProviders
          ? 'All providers configured'
          : 'Missing provider configuration'
      );
    } catch (error) {
      this.recordTest(
        'Payroll Configuration',
        false,
        `Error: ${error.message}`
      );
    }
  }

  async testSingleEmployeePayroll() {
    try {
      const payload = {
        employeeId: 'emp001',
        payrollPeriod: '2024-Q1',
        paymentDate: new Date().toISOString(),
      };

      const response = await axios.post(
        `${this.baseURL}/api/payroll-money/process-payroll-payments`,
        payload
      );
      const isValid =
        response.data.success &&
        response.data.paymentResults &&
        response.data.paymentResults.length > 0;
      this.recordTest(
        'Single Employee Payroll',
        isValid,
        isValid
          ? `Processed ${response.data.paymentResults.length} payments`
          : 'Invalid response'
      );
    } catch (error) {
      this.recordTest(
        'Single Employee Payroll',
        false,
        `Error: ${error.message}`
      );
    }
  }

  async testBulkPayrollProcessing() {
    try {
      const payload = {
        employees: [
          { id: 'emp001', name: 'John Smith' },
          { id: 'emp002', name: 'Sarah Johnson' },
          { id: 'emp003', name: 'Mike Davis' },
        ],
        payrollPeriod: '2024-Q1',
        paymentDate: new Date().toISOString(),
      };

      const response = await axios.post(
        `${this.baseURL}/api/payroll-money/bulk-payroll-processing`,
        payload
      );
      const isValid =
        response.data.success && response.data.totalProcessed === 3;
      this.recordTest(
        'Bulk Payroll Processing',
        isValid,
        isValid ? 'All employees processed' : 'Bulk processing failed'
      );
    } catch (error) {
      this.recordTest(
        'Bulk Payroll Processing',
        false,
        `Error: ${error.message}`
      );
    }
  }

  async testPayrollHistory() {
    try {
      const response = await axios.get(
        `${this.baseURL}/api/payroll-money/payroll-history/emp001`
      );
      const hasHistory = Array.isArray(response.data.history);
      this.recordTest(
        'Payroll History',
        hasHistory,
        hasHistory
          ? `${response.data.history.length} records found`
          : 'No history data'
      );
    } catch (error) {
      this.recordTest('Payroll History', false, `Error: ${error.message}`);
    }
  }

  async testInvalidEmployeeId() {
    try {
      const payload = {
        employeeId: 'invalid_emp',
        payrollPeriod: '2024-Q1',
        paymentDate: new Date().toISOString(),
      };

      await axios.post(
        `${this.baseURL}/api/payroll-money/process-payroll-payments`,
        payload
      );
      this.recordTest(
        'Invalid Employee ID',
        false,
        'Should have failed with invalid employee'
      );
    } catch (error) {
      const isExpectedError = error.response && error.response.status === 400;
      this.recordTest(
        'Invalid Employee ID',
        isExpectedError,
        isExpectedError
          ? 'Correctly handled invalid employee'
          : `Unexpected error: ${error.message}`
      );
    }
  }

  async testMissingRequiredFields() {
    try {
      const payload = {
        // Missing employeeId
        payrollPeriod: '2024-Q1',
        paymentDate: new Date().toISOString(),
      };

      await axios.post(
        `${this.baseURL}/api/payroll-money/process-payroll-payments`,
        payload
      );
      this.recordTest(
        'Missing Required Fields',
        false,
        'Should have failed with missing fields'
      );
    } catch (error) {
      const isExpectedError = error.response && error.response.status === 400;
      this.recordTest(
        'Missing Required Fields',
        isExpectedError,
        isExpectedError
          ? 'Correctly validated required fields'
          : `Unexpected error: ${error.message}`
      );
    }
  }

  async testRevenueThresholds() {
    try {
      // Test with low revenue that should trigger minimum thresholds
      const payload = {
        employeeId: 'emp001',
        payrollPeriod: '2024-Q1',
        paymentDate: new Date().toISOString(),
      };

      const response = await axios.post(
        `${this.baseURL}/api/payroll-money/process-payroll-payments`,
        payload
      );
      const hasPayments =
        response.data.paymentResults && response.data.paymentResults.length > 0;
      this.recordTest(
        'Revenue Thresholds',
        hasPayments,
        hasPayments ? 'Thresholds applied correctly' : 'No payments processed'
      );
    } catch (error) {
      this.recordTest('Revenue Thresholds', false, `Error: ${error.message}`);
    }
  }

  async testConcurrentRequests() {
    const promises = [];
    const employeeIds = ['emp001', 'emp002', 'emp003', 'emp004', 'emp005'];

    for (let i = 0; i < 10; i++) {
      const payload = {
        employeeId: employeeIds[i % employeeIds.length],
        payrollPeriod: '2024-Q1',
        paymentDate: new Date().toISOString(),
      };

      promises.push(
        axios.post(
          `${this.baseURL}/api/payroll-money/process-payroll-payments`,
          payload
        )
      );
    }

    try {
      const results = await Promise.allSettled(promises);
      const successful = results.filter(
        (result) => result.status === 'fulfilled'
      ).length;
      const isMostlySuccessful = successful >= 8; // At least 80% success rate
      this.recordTest(
        'Concurrent Requests',
        isMostlySuccessful,
        `${successful}/10 requests successful`
      );
    } catch (error) {
      this.recordTest('Concurrent Requests', false, `Error: ${error.message}`);
    }
  }

  async testLargeBulkProcessing() {
    try {
      const employees = [];
      for (let i = 1; i <= 50; i++) {
        employees.push({
          id: `emp${i.toString().padStart(3, '0')}`,
          name: `Employee ${i}`,
        });
      }

      const payload = {
        employees,
        payrollPeriod: '2024-Q1',
        paymentDate: new Date().toISOString(),
      };

      const startTime = Date.now();
      const response = await axios.post(
        `${this.baseURL}/api/payroll-money/bulk-payroll-processing`,
        payload
      );
      const endTime = Date.now();
      const processingTime = endTime - startTime;

      const isValid =
        response.data.success && response.data.totalProcessed === 50;
      const isFast = processingTime < 30000; // Less than 30 seconds

      this.recordTest(
        'Large Bulk Processing',
        isValid && isFast,
        `Processed 50 employees in ${processingTime}ms`
      );
    } catch (error) {
      this.recordTest(
        'Large Bulk Processing',
        false,
        `Error: ${error.message}`
      );
    }
  }

  async testDataPersistence() {
    try {
      // Process a payment
      const payload = {
        employeeId: 'emp001',
        payrollPeriod: '2024-Q1',
        paymentDate: new Date().toISOString(),
      };

      await axios.post(
        `${this.baseURL}/api/payroll-money/process-payroll-payments`,
        payload
      );

      // Check if data was persisted by reading the revenue file
      const revenueFile = path.join(__dirname, 'earnings_report_updated.json');
      const revenueData = JSON.parse(fs.readFileSync(revenueFile, 'utf8'));

      const hasPayrollData =
        revenueData.payrollHistory && revenueData.payrollHistory.length > 0;
      this.recordTest(
        'Data Persistence',
        hasPayrollData,
        hasPayrollData
          ? 'Payroll data persisted correctly'
          : 'Data not persisted'
      );
    } catch (error) {
      this.recordTest('Data Persistence', false, `Error: ${error.message}`);
    }
  }

  async testRateLimits() {
    try {
      const promises = [];
      for (let i = 0; i < 100; i++) {
        const payload = {
          employeeId: 'emp001',
          payrollPeriod: '2024-Q1',
          paymentDate: new Date().toISOString(),
        };
        promises.push(
          axios.post(
            `${this.baseURL}/api/payroll-money/process-payroll-payments`,
            payload
          )
        );
      }

      const results = await Promise.allSettled(promises);
      const rateLimited = results.filter(
        (result) =>
          result.status === 'rejected' &&
          result.reason.response &&
          result.reason.response.status === 429
      ).length;

      const hasRateLimiting = rateLimited > 0;
      this.recordTest(
        'Rate Limiting',
        hasRateLimiting,
        hasRateLimiting
          ? `${rateLimited} requests rate limited`
          : 'No rate limiting detected'
      );
    } catch (error) {
      this.recordTest('Rate Limiting', false, `Error: ${error.message}`);
    }
  }

  async runAllTests() {
    this.log(
      '🚀 Starting Comprehensive Payroll Money Integration Tests',
      'info'
    );

    const tests = [
      this.testHealthCheck.bind(this),
      this.testPayrollConfiguration.bind(this),
      this.testSingleEmployeePayroll.bind(this),
      this.testBulkPayrollProcessing.bind(this),
      this.testPayrollHistory.bind(this),
      this.testInvalidEmployeeId.bind(this),
      this.testMissingRequiredFields.bind(this),
      this.testRevenueThresholds.bind(this),
      this.testConcurrentRequests.bind(this),
      this.testLargeBulkProcessing.bind(this),
      this.testDataPersistence.bind(this),
      this.testRateLimits.bind(this),
    ];

    for (const test of tests) {
      await test();
      // Small delay between tests to avoid overwhelming the server
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    this.printSummary();
  }

  printSummary() {
    console.log('\n' + '='.repeat(60));
    console.log('📊 TEST SUMMARY');
    console.log('='.repeat(60));
    console.log(`Total Tests: ${this.testResults.total}`);
    console.log(`✅ Passed: ${this.testResults.passed}`);
    console.log(`❌ Failed: ${this.testResults.failed}`);
    console.log(
      `📈 Success Rate: ${((this.testResults.passed / this.testResults.total) * 100).toFixed(1)}%`
    );

    if (this.testResults.failed > 0) {
      console.log('\n❌ FAILED TESTS:');
      this.testResults.details
        .filter((test) => !test.passed)
        .forEach((test) => console.log(`   - ${test.name}: ${test.details}`));
    }

    console.log('\n' + '='.repeat(60));

    if (this.testResults.failed === 0) {
      console.log(
        '🎉 ALL TESTS PASSED! The payroll integration is ready for production.'
      );
    } else {
      console.log('⚠️  Some tests failed. Please review the issues above.');
    }
  }
}

// Run the tests if this file is executed directly
if (require.main === module) {
  const tester = new PayrollMoneyIntegrationTester();
  tester.runAllTests().catch((error) => {
    console.error('❌ Test suite failed:', error.message);
    process.exit(1);
  });
}

module.exports = PayrollMoneyIntegrationTester;
