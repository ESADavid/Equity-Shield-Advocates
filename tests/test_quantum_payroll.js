const { expect } = require('chai');
const { QuantumPayrollSystem } = require('../owlban_revenue_repo/quantum/quantumPayrollSystem');

describe('Quantum Payroll System', () => {
  let payrollSystem;

  beforeEach(() => {
    payrollSystem = new QuantumPayrollSystem();
  });

  it('should add an employee correctly', async () => {
    const employeeData = {
      employeeId: 'emp001',
      name: 'John Doe',
      salary: 60000,
      hourlyRate: 30,
      benefits: { health: 500, dental: 200 },
      deductions: { preTax: 1000, postTax: 500 }
    };
    const result = await payrollSystem.addEmployee(employeeData);
    expect(result).to.have.property('employeeId', 'emp001');
    expect(payrollSystem.employees.has('emp001')).to.be.true;
  });

  it('should calculate payroll for an employee', async () => {
    const employeeData = {
      employeeId: 'emp002',
      name: 'Jane Smith',
      salary: 72000,
      hourlyRate: 35,
      benefits: { health: 600, dental: 250 },
      deductions: { preTax: 1200, postTax: 600 }
    };
    await payrollSystem.addEmployee(employeeData);
    const payroll = await payrollSystem.calculateEmployeePayroll(employeeData, null);
    expect(payroll).to.have.property('employeeId', 'emp002');
    expect(payroll).to.have.property('grossPay').that.is.a('number');
    expect(payroll).to.have.property('netPay').that.is.a('number');
  });

  it('should generate audit trail', async () => {
    const auditTrail = payrollSystem.generateAuditTrail();
    expect(auditTrail).to.have.property('generatedAt');
    expect(auditTrail).to.have.property('runs').that.is.an('array');
  });
});
