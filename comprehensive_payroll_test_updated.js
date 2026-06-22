// @ts-nocheck
// Mock testPassed for silent testing
const testPassed = () => {};

import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Test configuration
const TEST_CONFIG = {
  SERVER: {
    PORT: 4000,
    BASE_URL: 'http://localhost:4000',
  },
  PAYROLL: {
    BASE_URL: 'http://localhost:4000/api/payroll',
  },
};

// Test tracking
class TestSuite {
  constructor(name) {
    this.name = name;
    this.tests = [];
    this.startTime = Date.now();
  }

  addTest(name, result, message = '', duration = 0) {
    this.tests.push({
      name,
      result,
      message,
      duration,
      timestamp: new Date().toISOString(),
    });
  }

  getResults() {
    const endTime = Date.now();
    const total = this.tests.length;
    const passed = this.tests.filter((t) => t.result === 'passed').length;
    const failed = this.tests.filter((t) => t.result === 'failed').length;
    const skipped = this.tests.filter((t) => t.result === 'skipped').length;
    const successRate =
      total > 0 ? ((passed / total) * 100).toFixed(2) : '0.00';

    return {
      suite: this.name,
      summary: {
        total,
        passed,
        failed,
        skipped,
        successRate: `${successRate}%`,
        duration: endTime - this.startTime,
      },
      tests: this.tests,
      timestamp: new Date().toISOString(),
    };
  }

  saveResults() {
    const results = this.getResults();
    const filename = `comprehensive_payroll_test_report.json`;
    const filepath = path.join(__dirname, filename);

    fs.writeFileSync(filepath, JSON.stringify(results, null, 2), 'utf-8');
  }
}

// Payroll endpoint tests
class PayrollEndpointTests {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.testSuite = new TestSuite('Payroll Integration Tests');
  }

  async testEnvironmentConfiguration() {
    // Wait a moment for server to be fully ready
    await new Promise((resolve) => setTimeout(resolve, 2000));

    try {
      // Test server health
      const healthResponse = await axios.get(
        `${TEST_CONFIG.SERVER.BASE_URL}/health`
      );
      if (
        healthResponse.status === 200 &&
        (healthResponse.data.status === 'healthy' ||
          healthResponse.data.status === 'degraded')
      ) {
        this.testSuite.addTest(
          'Environment Config',
          'passed',
          `Server is ${healthResponse.data.status} and running`
        );
        return true;
      } else {
        this.testSuite.addTest(
          'Environment Config',
          'failed',
          `Server health check failed - status: ${healthResponse.data.status}`
        );
        return false;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Environment Config',
        'failed',
        `Health check error: ${error.message}`
      );
      return false;
    }
  }

  async testGetEmployees() {
    try {
      const response = await axios.get(`${this.baseUrl}/employees`);
      if (
        response.status === 200 &&
        response.data.success &&
        Array.isArray(response.data.data)
      ) {
        this.testSuite.addTest(
          'Get Employees',
          'passed',
          `Retrieved ${response.data.data.length} employees`
        );
        return true;
      } else {
        this.testSuite.addTest(
          'Get Employees',
          'failed',
          'Invalid response format'
        );
        return false;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Get Employees',
        'failed',
        `Request failed: ${error.message}`
      );
      return false;
    }
  }

  async testAddEmployee() {
    const testEmployee = {
      id: `test-emp-${Date.now()}`,
      name: 'Test Employee',
      position: 'Test Position',
      hourlyRate: 25.0,
      hoursWorked: 40,
      overtimeHours: 5,
      taxRate: 0.2,
      deductions: 50,
      bonuses: 100,
    };

    try {
      const response = await axios.post(
        `${this.baseUrl}/employees`,
        testEmployee
      );
      if (response.status === 200 && response.data.success) {
        this.testSuite.addTest(
          'Add Employee',
          'passed',
          'Employee added successfully'
        );
        return testEmployee.id;
      } else {
        this.testSuite.addTest(
          'Add Employee',
          'failed',
          'Failed to add employee'
        );
        return null;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Add Employee',
        'failed',
        `Request failed: ${error.message}`
      );
      return null;
    }
  }

  async testCalculatePayroll() {
    const payrollData = {
      employeeId: 'test-calc',
      hoursWorked: 40,
      hourlyRate: 25.0,
      overtimeHours: 5,
      taxRate: 0.2,
      deductions: 50,
      bonuses: 100,
    };

    try {
      const response = await axios.post(
        `${this.baseUrl}/calculate`,
        payrollData
      );
      if (
        response.status === 200 &&
        response.data.success &&
        response.data.data
      ) {
        const result = response.data.data;
        // Verify calculations
        const expectedRegularPay = 40 * 25;
        const expectedOvertimePay = 5 * 25 * 1.5;
        const expectedGrossPay = expectedRegularPay + expectedOvertimePay + 100;
        const expectedTaxAmount = expectedGrossPay * 0.2;
        const expectedNetPay = expectedGrossPay - expectedTaxAmount - 50;

        if (
          Math.abs(result.grossPay - expectedGrossPay) < 0.01 &&
          Math.abs(result.taxAmount - expectedTaxAmount) < 0.01 &&
          Math.abs(result.netPay - expectedNetPay) < 0.01
        ) {
          this.testSuite.addTest(
            'Calculate Payroll',
            'passed',
            'Payroll calculated correctly'
          );
          return true;
        } else {
          this.testSuite.addTest(
            'Calculate Payroll',
            'failed',
            'Incorrect calculations'
          );
          return false;
        }
      } else {
        this.testSuite.addTest(
          'Calculate Payroll',
          'failed',
          'Invalid response format'
        );
        return false;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Calculate Payroll',
        'failed',
        `Request failed: ${error.message}`
      );
      return false;
    }
  }

  async testProcessPayroll() {
    try {
      const response = await axios.post(`${this.baseUrl}/process`);
      if (
        response.status === 200 &&
        response.data.success &&
        Array.isArray(response.data.data)
      ) {
        this.testSuite.addTest(
          'Process Payroll',
          'passed',
          `Processed payroll for ${response.data.data.length} employees`
        );
        return true;
      } else {
        this.testSuite.addTest(
          'Process Payroll',
          'failed',
          'Failed to process payroll'
        );
        return false;
      }
    } catch (error) {
      this.testSuite.addTest(
        'Process Payroll',
        'failed',
        `Request failed: ${error.message}`
      );
      return false;
    }
  }

  async runAllTests() {
    // Run all tests
    await this.testEnvironmentConfiguration();
    await this.testGetEmployees();
    const employeeId = await this.testAddEmployee();
    await this.testCalculatePayroll();
    await this.testProcessPayroll();

    // Clean up test employee if it was created
    if (employeeId) {
      try {
        await axios.delete(`${this.baseUrl}/employees/${employeeId}`);
      } catch (error) {
        // Silent fail for cleanup
      }
    }

    return this.testSuite;
  }
}

// Main test runner
async function runComprehensivePayrollTests() {
  const tester = new PayrollEndpointTests(TEST_CONFIG.PAYROLL.BASE_URL);
  const testSuite = await tester.runAllTests();

  const results = testSuite.getResults();

  // Save detailed results
  testSuite.saveResults();

  return results;
}

export { runComprehensivePayrollTests, PayrollEndpointTests, TestSuite };
