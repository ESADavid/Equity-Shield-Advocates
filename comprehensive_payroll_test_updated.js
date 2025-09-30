import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Test configuration
const TEST_CONFIG = {
  SERVER: {
    PORT: 3000,
    BASE_URL: 'http://localhost:3000'
  },
  PAYROLL: {
    BASE_URL: 'http://localhost:3000/api/payroll'
  }
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
      timestamp: new Date().toISOString()
    });
  }

  getResults() {
    const endTime = Date.now();
    const total = this.tests.length;
    const passed = this.tests.filter(t => t.result === 'passed').length;
    const failed = this.tests.filter(t => t.result === 'failed').length;
    const skipped = this.tests.filter(t => t.result === 'skipped').length;
    const successRate = total > 0 ? ((passed / total) * 100).toFixed(2) : '0.00';

    return {
      suite: this.name,
      summary: {
        total,
        passed,
        failed,
        skipped,
        successRate: `${successRate}%`,
        duration: endTime - this.startTime
      },
      tests: this.tests,
      timestamp: new Date().toISOString()
    };
  }

  saveResults() {
    const results = this.getResults();
    const filename = `comprehensive_payroll_test_report.json`;
    const filepath = path.join(__dirname, filename);

    fs.writeFileSync(filepath, JSON.stringify(results, null, 2), 'utf-8');
    console.log(`📄 Detailed report saved to: ${filepath}`);
  }
}

// Payroll endpoint tests
class PayrollEndpointTests {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.testSuite = new TestSuite('Payroll Integration Tests');
  }

  async testEnvironmentConfiguration() {
    console.log('[2025-09-29T18:00:25.923Z] ℹ️ Testing environment configuration...');

    // Wait a moment for server to be fully ready
    await new Promise(resolve => setTimeout(resolve, 2000));

    try {
      // Test server health
      const healthResponse = await axios.get(`${TEST_CONFIG.SERVER.BASE_URL}/health`);
      console.log(`Health response status: ${healthResponse.status}, data status: ${healthResponse.data.status}`);
      if (healthResponse.status === 200 && (healthResponse.data.status === 'healthy' || healthResponse.data.status === 'degraded')) {
        this.testSuite.addTest('Environment Config', 'passed', `Server is ${healthResponse.data.status} and running`);
        console.log('[2025-09-29T18:00:25.923Z] ✅ Environment Config: PASSED');
        return true;
      } else {
        this.testSuite.addTest('Environment Config', 'failed', `Server health check failed - status: ${healthResponse.data.status}`);
        console.log('[2025-09-29T18:00:25.923Z] ❌ Environment Config: FAILED');
        return false;
      }
    } catch (error) {
      this.testSuite.addTest('Environment Config', 'failed', `Health check error: ${error.message}`);
      console.log('[2025-09-29T18:00:25.923Z] ❌ Environment Config: FAILED');
      return false;
    }
  }

  async testGetEmployees() {
    console.log('[2025-09-29T18:00:25.970Z] ℹ️ Testing get employees endpoint...');

    try {
      const response = await axios.get(`${this.baseUrl}/employees`);
      if (response.status === 200 && response.data.success && Array.isArray(response.data.data)) {
        this.testSuite.addTest('Get Employees', 'passed', `Retrieved ${response.data.data.length} employees`);
        console.log('[2025-09-29T18:00:25.970Z] ✅ Get Employees: PASSED');
        return true;
      } else {
        this.testSuite.addTest('Get Employees', 'failed', 'Invalid response format');
        console.log('[2025-09-29T18:00:25.970Z] ❌ Get Employees: FAILED');
        return false;
      }
    } catch (error) {
      this.testSuite.addTest('Get Employees', 'failed', `Request failed: ${error.message}`);
      console.log('[2025-09-29T18:00:25.970Z] ❌ Get Employees: FAILED');
      return false;
    }
  }

  async testAddEmployee() {
    console.log('[2025-09-29T18:00:26.033Z] ℹ️ Testing add employee endpoint...');

    const testEmployee = {
      id: `test-emp-${Date.now()}`,
      name: 'Test Employee',
      position: 'Test Position',
      hourlyRate: 25.00,
      hoursWorked: 40,
      overtimeHours: 5,
      taxRate: 0.2,
      deductions: 50,
      bonuses: 100
    };

    try {
      const response = await axios.post(`${this.baseUrl}/employees`, testEmployee);
      if (response.status === 200 && response.data.success) {
        this.testSuite.addTest('Add Employee', 'passed', 'Employee added successfully');
        console.log('[2025-09-29T18:00:26.033Z] ✅ Add Employee: PASSED');
        return testEmployee.id; // Return employee ID for cleanup
      } else {
        this.testSuite.addTest('Add Employee', 'failed', 'Failed to add employee');
        console.log('[2025-09-29T18:00:26.033Z] ❌ Add Employee: FAILED');
        return null;
      }
    } catch (error) {
      this.testSuite.addTest('Add Employee', 'failed', `Request failed: ${error.message}`);
      console.log('[2025-09-29T18:00:26.033Z] ❌ Add Employee: FAILED');
      return null;
    }
  }

  async testCalculatePayroll() {
    console.log('[2025-09-29T18:00:26.037Z] ℹ️ Testing calculate payroll endpoint...');

    const payrollData = {
      employeeId: 'test-calc',
      hoursWorked: 40,
      hourlyRate: 25.00,
      overtimeHours: 5,
      taxRate: 0.2,
      deductions: 50,
      bonuses: 100
    };

    try {
      const response = await axios.post(`${this.baseUrl}/calculate`, payrollData);
      if (response.status === 200 && response.data.success && response.data.data) {
        const result = response.data.data;
        // Verify calculations
        const expectedRegularPay = 40 * 25;
        const expectedOvertimePay = 5 * 25 * 1.5;
        const expectedGrossPay = expectedRegularPay + expectedOvertimePay + 100;
        const expectedTaxAmount = expectedGrossPay * 0.2;
        const expectedNetPay = expectedGrossPay - expectedTaxAmount - 50;

        if (Math.abs(result.grossPay - expectedGrossPay) < 0.01 &&
            Math.abs(result.taxAmount - expectedTaxAmount) < 0.01 &&
            Math.abs(result.netPay - expectedNetPay) < 0.01) {
          this.testSuite.addTest('Calculate Payroll', 'passed', 'Payroll calculated correctly');
          console.log('[2025-09-29T18:00:26.037Z] ✅ Calculate Payroll: PASSED');
          return true;
        } else {
          this.testSuite.addTest('Calculate Payroll', 'failed', 'Incorrect calculations');
          console.log('[2025-09-29T18:00:26.037Z] ❌ Calculate Payroll: FAILED');
          return false;
        }
      } else {
        this.testSuite.addTest('Calculate Payroll', 'failed', 'Invalid response format');
        console.log('[2025-09-29T18:00:26.037Z] ❌ Calculate Payroll: FAILED');
        return false;
      }
    } catch (error) {
      this.testSuite.addTest('Calculate Payroll', 'failed', `Request failed: ${error.message}`);
      console.log('[2025-09-29T18:00:26.037Z] ❌ Calculate Payroll: FAILED');
      return false;
    }
  }

  async testProcessPayroll() {
    console.log('[2025-09-29T18:00:26.040Z] ℹ️ Testing process payroll endpoint...');

    try {
      const response = await axios.post(`${this.baseUrl}/process`);
      if (response.status === 200 && response.data.success && Array.isArray(response.data.data)) {
        this.testSuite.addTest('Process Payroll', 'passed', `Processed payroll for ${response.data.data.length} employees`);
        console.log('[2025-09-29T18:00:26.040Z] ✅ Process Payroll: PASSED');
        return true;
      } else {
        this.testSuite.addTest('Process Payroll', 'failed', 'Failed to process payroll');
        console.log('[2025-09-29T18:00:26.040Z] ❌ Process Payroll: FAILED');
        return false;
      }
    } catch (error) {
      this.testSuite.addTest('Process Payroll', 'failed', `Request failed: ${error.message}`);
      console.log('[2025-09-29T18:00:26.040Z] ❌ Process Payroll: FAILED');
      return false;
    }
  }

  async runAllTests() {
    console.log('🧪 Starting Comprehensive Payroll Integration Tests');
    console.log('======================================================================');
    console.log(`Server URL: ${TEST_CONFIG.SERVER.BASE_URL}`);
    console.log('======================================================================');

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
        console.log(`🧹 Cleaned up test employee: ${employeeId}`);
      } catch (error) {
        console.log(`⚠️ Failed to clean up test employee: ${employeeId}`);
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

  console.log('\n============================================================');
  console.log('🧪 COMPREHENSIVE PAYROLL TEST REPORT');
  console.log('============================================================');
  console.log(`Total Tests: ${results.summary.total}`);
  console.log(`✅ Passed: ${results.summary.passed}`);
  console.log(`❌ Failed: ${results.summary.failed}`);
  console.log(`⚠️ Skipped: ${results.summary.skipped}`);
  console.log(`📈 Success Rate: ${results.summary.successRate}`);
  console.log('============================================================');

  // Save detailed results
  testSuite.saveResults();

  return results;
}

export { runComprehensivePayrollTests, PayrollEndpointTests, TestSuite };
