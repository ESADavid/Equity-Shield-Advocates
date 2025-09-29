import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const employeesFilePath = path.resolve(__dirname, 'data/employees.json');
const payrollRecordsFilePath = path.resolve(__dirname, 'data/payroll_records.json');

class PayrollSystem {
  constructor() {
    this.employees = [];
    this.payrollRecords = [];
    this.loadEmployees();
    this.loadPayrollRecords();
  }

  loadEmployees() {
    try {
      if (fs.existsSync(employeesFilePath)) {
        const data = fs.readFileSync(employeesFilePath, 'utf-8');
        this.employees = JSON.parse(data);
      } else {
        this.employees = [];
      }
    } catch (error) {
      console.error('Failed to load employees:', error);
      this.employees = [];
    }
  }

  saveEmployees() {
    try {
      fs.writeFileSync(employeesFilePath, JSON.stringify(this.employees, null, 2), 'utf-8');
    } catch (error) {
      console.error('Failed to save employees:', error);
    }
  }

  loadPayrollRecords() {
    try {
      if (fs.existsSync(payrollRecordsFilePath)) {
        const data = fs.readFileSync(payrollRecordsFilePath, 'utf-8');
        this.payrollRecords = JSON.parse(data);
      } else {
        this.payrollRecords = [];
      }
    } catch (error) {
      console.error('Failed to load payroll records:', error);
      this.payrollRecords = [];
    }
  }

  savePayrollRecords() {
    try {
      fs.writeFileSync(payrollRecordsFilePath, JSON.stringify(this.payrollRecords, null, 2), 'utf-8');
    } catch (error) {
      console.error('Failed to save payroll records:', error);
    }
  }

  addEmployee(employee) {
    if (this.employees.find(e => e.id === employee.id)) {
      throw new Error('Employee with this ID already exists');
    }
    this.employees.push(employee);
    this.saveEmployees();
  }

  updateEmployee(employee) {
    const index = this.employees.findIndex(e => e.id === employee.id);
    if (index === -1) {
      throw new Error('Employee not found');
    }
    this.employees[index] = employee;
    this.saveEmployees();
  }

  deleteEmployee(employeeId) {
    this.employees = this.employees.filter(e => e.id !== employeeId);
    this.saveEmployees();
  }

  calculatePayrollForEmployee(employee, payDate) {
    const grossPay = employee.salary;
    const taxAmount = grossPay * employee.taxRate;
    const netPay = grossPay - taxAmount - employee.deductions + employee.bonuses;

    return {
      employeeId: employee.id,
      grossPay,
      taxAmount,
      deductions: employee.deductions,
      bonuses: employee.bonuses,
      netPay,
      payDate,
    };
  }

  processPayroll(payDate) {
    const payrolls = this.employees.map(employee => this.calculatePayrollForEmployee(employee, payDate));
    this.payrollRecords.push(...payrolls);
    this.savePayrollRecords();
    return payrolls;
  }

  getPayrollRecords() {
    return this.payrollRecords;
  }

  getEmployees() {
    return this.employees;
  }
}

export default PayrollSystem;
