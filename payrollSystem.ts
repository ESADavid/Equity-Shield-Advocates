import { info, error as logError } from './utils/loggerWrapper.js';

export interface Employee {
  id: string;
  name: string;
  position: string;
  hourlyRate: number;
  hoursWorked?: number;
  overtimeHours?: number;
  taxRate?: number;
  deductions?: number;
  bonuses?: number;
  accountNumber?: string;
  routingNumber?: string;
}

export interface PayrollResult {
  employeeId: string;
  name: string;
  position: string;
  hoursWorked: number;
  hourlyRate: number;
  overtimeHours: number;
  taxRate: number;
  deductions: number;
  bonuses: number;
  grossPay: number;
  taxAmount: number;
  netPay: number;
  accountNumber?: string;
  routingNumber?: string;
  payDate: string;
}

export class PayrollSystem {
  private employees: Employee[] = [];

  constructor() {
    // Initialize with some sample employees
    this.initializeSampleEmployees();
  }

  private initializeSampleEmployees() {
    this.employees = [
      {
        id: 'emp001',
        name: 'John Smith',
        position: 'Software Engineer',
        hourlyRate: 45.0,
        hoursWorked: 40,
        overtimeHours: 5,
        taxRate: 0.25,
        deductions: 100,
        bonuses: 500,
        accountNumber: '123456789',
        routingNumber: '021000021',
      },
      {
        id: 'emp002',
        name: 'Sarah Johnson',
        position: 'Project Manager',
        hourlyRate: 55.0,
        hoursWorked: 40,
        overtimeHours: 0,
        taxRate: 0.28,
        deductions: 150,
        bonuses: 1000,
        accountNumber: '987654321',
        routingNumber: '021000021',
      },
      {
        id: 'emp003',
        name: 'Mike Davis',
        position: 'Senior Developer',
        hourlyRate: 65.0,
        hoursWorked: 40,
        overtimeHours: 10,
        taxRate: 0.30,
        deductions: 200,
        bonuses: 750,
        accountNumber: '456789123',
        routingNumber: '021000021',
      },
    ];
    info('Payroll system initialized with sample employees');
  }

  getEmployees(): Employee[] {
    return [...this.employees];
  }

  addEmployee(employee: Employee): void {
    // Validate employee data
    if (!employee.id || !employee.name || !employee.position) {
      throw new Error('Employee must have id, name, and position');
    }
    if (employee.hourlyRate <= 0) {
      throw new Error('Hourly rate must be positive');
    }

    // Check if employee already exists
    if (this.employees.find(e => e.id === employee.id)) {
      throw new Error('Employee with this ID already exists');
    }

    this.employees.push(employee);
    info(`Employee added: ${employee.name} (${employee.id})`);
  }

  updateEmployee(employee: Employee): void {
    const index = this.employees.findIndex(e => e.id === employee.id);
    if (index === -1) {
      throw new Error('Employee not found');
    }

    this.employees[index] = { ...employee };
    info(`Employee updated: ${employee.name} (${employee.id})`);
  }

  deleteEmployee(id: string): void {
    const index = this.employees.findIndex(e => e.id === id);
    if (index === -1) {
      throw new Error('Employee not found');
    }

    const employee = this.employees[index];
    this.employees.splice(index, 1);
    info(`Employee deleted: ${employee.name} (${employee.id})`);
  }

  processPayroll(payDate: string): PayrollResult[] {
    const results: PayrollResult[] = [];

    for (const employee of this.employees) {
      try {
        const payroll = this.calculatePayroll(employee, payDate);
        results.push(payroll);
      } catch (err) {
        logError(`Error processing payroll for ${employee.name}:`, err);
        // Continue with other employees
      }
    }

    info(`Payroll processed for ${results.length} employees on ${payDate}`);
    return results;
  }

  calculatePayroll(employee: Employee, payDate: string): PayrollResult {
    const hoursWorked = employee.hoursWorked || 0;
    const hourlyRate = employee.hourlyRate;
    const overtimeHours = employee.overtimeHours || 0;
    const taxRate = employee.taxRate || 0.25;
    const deductions = employee.deductions || 0;
    const bonuses = employee.bonuses || 0;

    // Calculate pay
    const regularPay = hoursWorked * hourlyRate;
    const overtimePay = overtimeHours * hourlyRate * 1.5;
    const grossPay = regularPay + overtimePay + bonuses;
    const taxAmount = grossPay * taxRate;
    const netPay = grossPay - taxAmount - deductions;

    return {
      employeeId: employee.id,
      name: employee.name,
      position: employee.position,
      hoursWorked,
      hourlyRate,
      overtimeHours,
      taxRate,
      deductions,
      bonuses,
      grossPay,
      taxAmount,
      netPay,
      accountNumber: employee.accountNumber,
      routingNumber: employee.routingNumber,
      payDate,
    };
  }

  getEmployeeById(id: string): Employee | undefined {
    return this.employees.find(e => e.id === id);
  }

  // Method to calculate payroll for a specific employee with custom parameters
  calculateCustomPayroll(params: {
    employeeId: string;
    hoursWorked: number;
    hourlyRate: number;
    overtimeHours?: number;
    taxRate?: number;
    deductions?: number;
    bonuses?: number;
  }): PayrollResult {
    const employee = this.getEmployeeById(params.employeeId);
    if (!employee) {
      throw new Error('Employee not found');
    }

    const customEmployee: Employee = {
      ...employee,
      hoursWorked: params.hoursWorked,
      hourlyRate: params.hourlyRate,
      overtimeHours: params.overtimeHours || 0,
      taxRate: params.taxRate || employee.taxRate || 0.25,
      deductions: params.deductions || employee.deductions || 0,
      bonuses: params.bonuses || employee.bonuses || 0,
    };

    return this.calculatePayroll(customEmployee, new Date().toISOString());
  }
}

// Export singleton instance
export const payrollSystem = new PayrollSystem();
