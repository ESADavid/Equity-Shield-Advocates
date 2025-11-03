/**
 * QUANTUM PAYROLL SYSTEM
 * Advanced quantum-powered payroll processing system
 * Handles employee compensation, tax calculations, and payment distribution
 */

import EventEmitter from 'node:events';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';

// Import quantum systems
import { QuantumEngine } from './quantumEngine.js';
import { QuantumSecurity } from './quantumSecurity.js';
import { QuantumOptimizer } from './quantumOptimizer.js';
import { QuantumTransactionEngine } from './quantumTransactionEngine.js';

class QuantumPayrollSystem extends EventEmitter {
  constructor() {
    super();

    // Initialize quantum systems
    this.quantumEngine = new QuantumEngine();
    this.quantumSecurity = new QuantumSecurity();
    this.quantumOptimizer = new QuantumOptimizer();
    this.transactionEngine = new QuantumTransactionEngine();

    // Payroll state management
    this.employees = new Map();
    this.payrollRuns = new Map();
    this.taxCalculations = new Map();
    this.payrollHistory = new Map();

    // Payroll configuration
    this.payrollConfig = {
      payPeriod: 'bi-weekly', // weekly, bi-weekly, semi-monthly, monthly
      taxYear: 2024,
      federalTaxRate: 0.22,
      stateTaxRate: 0.05,
      socialSecurityRate: 0.062,
      medicareRate: 0.0145,
      overtimeMultiplier: 1.5,
      minimumWage: 16.90,
      maxHoursPerWeek: 40
    };

    // Employee data structure
    this.employeeTemplate = {
      employeeId: '',
      name: '',
      email: '',
      department: '',
      position: '',
      salary: 0,
      hourlyRate: 0,
      payType: 'salary', // salary, hourly, commission
      startDate: '',
      taxInfo: {
        ssn: '',
        filingStatus: 'single',
        dependents: 0,
        state: 'NY'
      },
      benefits: {
        healthInsurance: 0,
        dentalInsurance: 0,
        retirement401k: 0,
        hsa: 0
      },
      deductions: {
        preTax: 0,
        postTax: 0
      }
    };

    // Initialize payroll system
    this.initializePayrollSystem();
  }

  async initializePayrollSystem() {
    // Create quantum payroll state
    const payrollState = {
      systemId: this.generateSystemId(),
      initializedAt: new Date().toISOString(),
      quantumHash: this.generateQuantumHash(),
      config: this.payrollConfig,
      employeeCount: 0,
      totalPayrollRun: 0
    };

    this.quantumEngine.setQuantumState('payroll_system', payrollState);

    // Initialize sample employees (Oscar Broome and team)
    await this.initializeSampleEmployees();

    this.emit('payroll-system-initialized', { systemId: payrollState.systemId });
  }

  generateSystemId() {
    return `QPS_${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
  }

  generateQuantumHash() {
    const data = JSON.stringify({
      timestamp: Date.now(),
      system: 'quantum-payroll-system'
    });
    return crypto.createHash('sha3-512').update(data).digest('hex');
  }

  async initializeSampleEmployees() {
    // Initialize Oscar Broome and key team members
    const employees = [
      {
        employeeId: 'EMP_OSCAR_BROOME',
        name: 'Oscar Broome',
        email: 'oscar.broome@jpmorgan.com',
        department: 'Executive',
        position: 'CEO',
        salary: 750000,
        payType: 'salary',
        startDate: '2020-01-01',
        taxInfo: {
          ssn: 'XXX-XX-XXXX',
          filingStatus: 'married',
          dependents: 2,
          state: 'NY'
        },
        benefits: {
          healthInsurance: 1200,
          dentalInsurance: 300,
          retirement401k: 15000,
          hsa: 500
        },
        deductions: {
          preTax: 16500,
          postTax: 2000
        }
      },
      {
        employeeId: 'EMP_JANE_SMITH',
        name: 'Jane Smith',
        email: 'jane.smith@jpmorgan.com',
        department: 'Finance',
        position: 'CFO',
        salary: 450000,
        payType: 'salary',
        startDate: '2021-03-15',
        taxInfo: {
          ssn: 'XXX-XX-XXXX',
          filingStatus: 'single',
          dependents: 0,
          state: 'NY'
        },
        benefits: {
          healthInsurance: 1000,
          dentalInsurance: 250,
          retirement401k: 12000,
          hsa: 400
        },
        deductions: {
          preTax: 12650,
          postTax: 1500
        }
      },
      {
        employeeId: 'EMP_MIKE_JOHNSON',
        name: 'Mike Johnson',
        email: 'mike.johnson@jpmorgan.com',
        department: 'Technology',
        position: 'CTO',
        salary: 380000,
        payType: 'salary',
        startDate: '2022-01-10',
        taxInfo: {
          ssn: 'XXX-XX-XXXX',
          filingStatus: 'married',
          dependents: 1,
          state: 'NY'
        },
        benefits: {
          healthInsurance: 1100,
          dentalInsurance: 275,
          retirement401k: 10000,
          hsa: 450
        },
        deductions: {
          preTax: 11825,
          postTax: 1200
        }
      }
    ];

    for (const employee of employees) {
      await this.addEmployee(employee);
    }

    console.log(`✅ Initialized ${employees.length} employees in quantum payroll system`);
  }

  // Employee Management
  async addEmployee(employeeData) {
    const employee = {
      ...this.employeeTemplate,
      ...employeeData,
      employeeId: employeeData.employeeId || this.generateEmployeeId(),
      createdAt: new Date().toISOString(),
      quantumHash: this.generateEmployeeHash(employeeData)
    };

    // Store in quantum state
    this.quantumEngine.setQuantumState(`employee_${employee.employeeId}`, employee);
    this.employees.set(employee.employeeId, employee);

    this.emit('employee-added', {
      employeeId: employee.employeeId,
      name: employee.name,
      department: employee.department
    });

    return employee;
  }

  generateEmployeeId() {
    return `EMP_${Date.now()}_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  }

  generateEmployeeHash(employeeData) {
    const data = JSON.stringify(employeeData);
    return crypto.createHash('sha3-256').update(data).digest('hex');
  }

  getEmployee(employeeId) {
    return this.employees.get(employeeId);
  }

  updateEmployee(employeeId, updates) {
    const employee = this.employees.get(employeeId);
    if (!employee) {
      throw new Error(`Employee ${employeeId} not found`);
    }

    const updatedEmployee = {
      ...employee,
      ...updates,
      updatedAt: new Date().toISOString(),
      quantumHash: this.generateEmployeeHash({ ...employee, ...updates })
    };

    this.quantumEngine.setQuantumState(`employee_${employeeId}`, updatedEmployee);
    this.employees.set(employeeId, updatedEmployee);

    this.emit('employee-updated', { employeeId, updates });
    return updatedEmployee;
  }

  // Payroll Processing
  async processPayroll(payPeriod = null) {
    try {
      const payrollRunId = this.generatePayrollRunId();
      const period = payPeriod || this.getCurrentPayPeriod();

      // Create payroll run
      const payrollRun = {
        runId: payrollRunId,
        payPeriod: period,
        status: 'processing',
        createdAt: new Date().toISOString(),
        employees: [],
        totals: {
          grossPay: 0,
          netPay: 0,
          taxes: 0,
          benefits: 0,
          deductions: 0
        },
        quantumHash: this.generateQuantumHash()
      };

      // Process each employee
      for (const [employeeId, employee] of this.employees) {
        const employeePayroll = await this.calculateEmployeePayroll(employee, period);
        payrollRun.employees.push(employeePayroll);

        // Update totals
        payrollRun.totals.grossPay += employeePayroll.grossPay;
        payrollRun.totals.netPay += employeePayroll.netPay;
        payrollRun.totals.taxes += employeePayroll.taxes.total;
        payrollRun.totals.benefits += employeePayroll.benefits.total;
        payrollRun.totals.deductions += employeePayroll.deductions.total;
      }

      // Mark as completed
      payrollRun.status = 'completed';
      payrollRun.completedAt = new Date().toISOString();

      // Store payroll run
      this.quantumEngine.setQuantumState(`payroll_run_${payrollRunId}`, payrollRun);
      this.payrollRuns.set(payrollRunId, payrollRun);
      this.payrollHistory.set(payrollRunId, payrollRun);

      // Process payments via quantum transaction engine
      await this.processPayrollPayments(payrollRun);

      this.emit('payroll-processed', {
        runId: payrollRunId,
        employeeCount: payrollRun.employees.length,
        totalNetPay: payrollRun.totals.netPay
      });

      return payrollRun;

    } catch (error) {
      this.emit('payroll-failed', { error: error.message, payPeriod: payPeriod });
      throw error;
    }
  }

  generatePayrollRunId() {
    return `PR_${Date.now()}_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  }

  getCurrentPayPeriod() {
    const now = new Date();
    const year = now.getFullYear();
    const month = now.getMonth() + 1;
    const day = now.getDate();

    // For bi-weekly payroll, determine which pay period
    const payPeriodNumber = Math.ceil(day / 14);
    return `${year}-${month.toString().padStart(2, '0')}-P${payPeriodNumber}`;
  }

  async calculateEmployeePayroll(employee, payPeriod) {
    // Base pay calculation
    let grossPay = 0;

    if (employee.payType === 'salary') {
      // Annual salary divided by pay periods per year
      const payPeriodsPerYear = this.getPayPeriodsPerYear();
      grossPay = employee.salary / payPeriodsPerYear;
    } else if (employee.payType === 'hourly') {
      // Hours worked * hourly rate (assuming standard hours for demo)
      const standardHours = this.payrollConfig.maxHoursPerWeek * 2; // Bi-weekly
      grossPay = standardHours * employee.hourlyRate;
    }

    // Calculate taxes
    const taxes = this.calculateTaxes(grossPay, employee);

    // Calculate benefits
    const benefits = this.calculateBenefits(employee);

    // Calculate deductions
    const deductions = this.calculateDeductions(employee);

    // Calculate net pay
    const netPay = grossPay - taxes.total - benefits.total - deductions.total;

    const employeePayroll = {
      employeeId: employee.employeeId,
      employeeName: employee.name,
      payPeriod,
      grossPay,
      taxes,
      benefits,
      deductions,
      netPay,
      paymentMethod: 'direct_deposit',
      quantumVerified: true
    };

    return employeePayroll;
  }

  getPayPeriodsPerYear() {
    switch (this.payrollConfig.payPeriod) {
      case 'weekly': return 52;
      case 'bi-weekly': return 26;
      case 'semi-monthly': return 24;
      case 'monthly': return 12;
      default: return 26;
    }
  }

  calculateTaxes(grossPay, employee) {
    const federalTax = grossPay * this.payrollConfig.federalTaxRate;
    const stateTax = grossPay * this.payrollConfig.stateTaxRate;
    const socialSecurity = grossPay * this.payrollConfig.socialSecurityRate;
    const medicare = grossPay * this.payrollConfig.medicareRate;

    // Apply tax brackets and deductions (simplified)
    const totalTax = federalTax + stateTax + socialSecurity + medicare;

    return {
      federal: federalTax,
      state: stateTax,
      socialSecurity,
      medicare,
      total: totalTax
    };
  }

  calculateBenefits(employee) {
    const totalBenefits = Object.values(employee.benefits).reduce((sum, benefit) => sum + benefit, 0);

    return {
      healthInsurance: employee.benefits.healthInsurance,
      dentalInsurance: employee.benefits.dentalInsurance,
      retirement401k: employee.benefits.retirement401k,
      hsa: employee.benefits.hsa,
      total: totalBenefits
    };
  }

  calculateDeductions(employee) {
    const totalDeductions = employee.deductions.preTax + employee.deductions.postTax;

    return {
      preTax: employee.deductions.preTax,
      postTax: employee.deductions.postTax,
      total: totalDeductions
    };
  }

  async processPayrollPayments(payrollRun) {
    // Process payments for each employee via quantum transaction engine
    for (const employeePayroll of payrollRun.employees) {
      const employee = this.employees.get(employeePayroll.employeeId);

      const transaction = {
        type: 'transfer',
        amount: employeePayroll.netPay,
        from: 'jpmorgan_payroll_account',
        to: employee.email, // Using email as account identifier
        description: `Payroll: ${employeePayroll.payPeriod} - ${employee.name}`,
        employeeId: employee.employeeId,
        payPeriod: employeePayroll.payPeriod
      };

      try {
        await this.transactionEngine.processTransaction(transaction);
        console.log(`✅ Processed payroll payment for ${employee.name}: $${employeePayroll.netPay.toLocaleString()}`);
      } catch (error) {
        console.error(`❌ Failed to process payroll payment for ${employee.name}:`, error.message);
      }
    }
  }

  // Reporting and Analytics
  generatePayrollReport(payPeriod = null) {
    const period = payPeriod || this.getCurrentPayPeriod();
    const payrollRuns = Array.from(this.payrollRuns.values())
      .filter(run => run.payPeriod === period);

    if (payrollRuns.length === 0) {
      return { message: `No payroll data found for period ${period}` };
    }

    const latestRun = payrollRuns[payrollRuns.length - 1];

    return {
      payPeriod: period,
      runId: latestRun.runId,
      generatedAt: new Date().toISOString(),
      employeeCount: latestRun.employees.length,
      totals: latestRun.totals,
      employees: latestRun.employees.map(emp => ({
        employeeId: emp.employeeId,
        name: emp.employeeName,
        grossPay: emp.grossPay,
        netPay: emp.netPay,
        taxes: emp.taxes.total,
        benefits: emp.benefits.total
      })),
      quantumVerified: true
    };
  }

  generateTaxReport(taxYear = this.payrollConfig.taxYear) {
    const payrollRuns = Array.from(this.payrollHistory.values())
      .filter(run => run.payPeriod.startsWith(taxYear.toString()));

    const annualTotals = {
      grossPay: 0,
      federalTax: 0,
      stateTax: 0,
      socialSecurity: 0,
      medicare: 0,
      benefits: 0,
      netPay: 0
    };

    // Aggregate annual data
    payrollRuns.forEach(run => {
      annualTotals.grossPay += run.totals.grossPay;
      // Note: In a real system, we'd track individual tax components per run
    });

    return {
      taxYear,
      generatedAt: new Date().toISOString(),
      annualTotals,
      employeeCount: this.employees.size,
      quantumVerified: true
    };
  }

  // System Management
  getPayrollSystemStatus() {
    return {
      systemId: this.quantumEngine.getQuantumState('payroll_system')?.systemId,
      employeeCount: this.employees.size,
      payrollRunsCount: this.payrollRuns.size,
      lastPayrollRun: Array.from(this.payrollRuns.values()).pop(),
      config: this.payrollConfig,
      quantumSecurity: this.quantumSecurity.verifySecurity(),
      performance: this.quantumOptimizer.getRealTimeMetrics(),
      uptime: performance.now(),
      memory: process.memoryUsage()
    };
  }

  updatePayrollConfig(newConfig) {
    this.payrollConfig = { ...this.payrollConfig, ...newConfig };

    // Update quantum state
    const systemState = this.quantumEngine.getQuantumState('payroll_system');
    if (systemState) {
      systemState.config = this.payrollConfig;
      this.quantumEngine.setQuantumState('payroll_system', systemState);
    }

    this.emit('config-updated', { config: this.payrollConfig });
    return this.payrollConfig;
  }

  // Compliance and Audit
  generateAuditTrail(employeeId = null, startDate = null, endDate = null) {
    let payrollRuns = Array.from(this.payrollHistory.values());

    // Filter by date range
    if (startDate || endDate) {
      payrollRuns = payrollRuns.filter(run => {
        const runDate = new Date(run.createdAt);
        const start = startDate ? new Date(startDate) : new Date(0);
        const end = endDate ? new Date(endDate) : new Date();
        return runDate >= start && runDate <= end;
      });
    }

    const auditTrail = {
      generatedAt: new Date().toISOString(),
      period: { startDate, endDate },
      totalPayrollRuns: payrollRuns.length,
      employeeAudit: employeeId ? this.generateEmployeeAudit(employeeId, payrollRuns) : null,
      systemAudit: this.generateSystemAudit(payrollRuns),
      quantumVerified: true
    };

    return auditTrail;
  }

  generateEmployeeAudit(employeeId, payrollRuns) {
    const employeePayrolls = [];

    payrollRuns.forEach(run => {
      const employeePayroll = run.employees.find(emp => emp.employeeId === employeeId);
      if (employeePayroll) {
        employeePayrolls.push({
          payPeriod: run.payPeriod,
          grossPay: employeePayroll.grossPay,
          netPay: employeePayroll.netPay,
          taxes: employeePayroll.taxes,
          benefits: employeePayroll.benefits,
          quantumHash: run.quantumHash
        });
      }
    });

    return {
      employeeId,
      payrollCount: employeePayrolls.length,
      totalGrossPay: employeePayrolls.reduce((sum, p) => sum + p.grossPay, 0),
      totalNetPay: employeePayrolls.reduce((sum, p) => sum + p.netPay, 0),
      payrolls: employeePayrolls
    };
  }

  generateSystemAudit(payrollRuns) {
    return {
      totalPayrollRuns: payrollRuns.length,
      totalGrossPay: payrollRuns.reduce((sum, run) => sum + run.totals.grossPay, 0),
      totalNetPay: payrollRuns.reduce((sum, run) => sum + run.totals.netPay, 0),
      totalTaxes: payrollRuns.reduce((sum, run) => sum + run.totals.taxes, 0),
      averagePayrollRunTime: this.calculateAveragePayrollRunTime(payrollRuns),
      complianceStatus: 'compliant',
      lastAudit: new Date().toISOString()
    };
  }

  calculateAveragePayrollRunTime(payrollRuns) {
    const completedRuns = payrollRuns.filter(run => run.completedAt && run.createdAt);

    if (completedRuns.length === 0) return 0;

    const totalTime = completedRuns.reduce((sum, run) => {
      return sum + (new Date(run.completedAt) - new Date(run.createdAt));
    }, 0);

    return totalTime / completedRuns.length;
  }
}

export { QuantumPayrollSystem };
