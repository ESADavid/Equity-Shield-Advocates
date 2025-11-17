/**
 * Payroll Calculator Utilities
 * Provides standardized payroll calculation logic
 */

import {
  Employee,
  PayrollCalculation,
  PayrollCalculationInput,
  PAYROLL_CONSTANTS
} from '../types/payroll.js';

/**
 * Calculates payroll for an employee based on hours worked and rates
 */
export function calculatePayrollForEmployee(
  employee: Employee,
  overrides?: Partial<PayrollCalculationInput>
): PayrollCalculation {
  // Use employee data as base, with optional overrides
  const hoursWorked = overrides?.hoursWorked ?? employee.hoursWorked ?? 0;
  const hourlyRate = overrides?.hourlyRate ?? employee.hourlyRate ?? 0;
  const overtimeHours = overrides?.overtimeHours ?? employee.overtimeHours ?? 0;
  const taxRate = overrides?.taxRate ?? employee.taxRate;
  const deductions = overrides?.deductions ?? employee.deductions;
  const bonuses = overrides?.bonuses ?? employee.bonuses;
  const payPeriod = overrides?.payPeriod ?? new Date().toISOString().split('T')[0];

  // Calculate regular pay
  const regularPay = hoursWorked * hourlyRate;

  // Calculate overtime pay (1.5x regular rate)
  const overtimePay = overtimeHours * hourlyRate * PAYROLL_CONSTANTS.OVERTIME_MULTIPLIER;

  // Calculate gross pay
  const grossPay = regularPay + overtimePay + bonuses;

  // Calculate tax amount
  const taxAmount = grossPay * taxRate;

  // Calculate net pay
  const netPay = grossPay - taxAmount - deductions;

  return {
    employeeId: employee.id,
    regularPay: Math.round(regularPay * 100) / 100, // Round to 2 decimal places
    overtimePay: Math.round(overtimePay * 100) / 100,
    grossPay: Math.round(grossPay * 100) / 100,
    taxAmount: Math.round(taxAmount * 100) / 100,
    deductions,
    bonuses,
    netPay: Math.round(netPay * 100) / 100,
    payPeriod,
    calculatedAt: new Date().toISOString()
  };
}

/**
 * Calculates payroll for a salaried employee
 */
export function calculateSalariedPayroll(
  employee: Employee,
  payPeriod: string = new Date().toISOString().split('T')[0]
): PayrollCalculation {
  if (!employee.salary) {
    throw new Error('Employee does not have a salary defined');
  }

  const grossPay = employee.salary + employee.bonuses;
  const taxAmount = grossPay * employee.taxRate;
  const netPay = grossPay - taxAmount - employee.deductions;

  return {
    employeeId: employee.id,
    regularPay: Math.round(employee.salary * 100) / 100,
    overtimePay: 0, // Salaried employees don't get overtime
    grossPay: Math.round(grossPay * 100) / 100,
    taxAmount: Math.round(taxAmount * 100) / 100,
    deductions: employee.deductions,
    bonuses: employee.bonuses,
    netPay: Math.round(netPay * 100) / 100,
    payPeriod,
    calculatedAt: new Date().toISOString()
  };
}

/**
 * Determines if an employee should be paid as salaried or hourly
 */
export function isSalariedEmployee(employee: Employee): boolean {
  return employee.salary !== undefined && employee.salary > 0;
}

/**
 * Calculates payroll summary for multiple employees
 */
export function calculatePayrollSummary(
  employees: Employee[],
  payPeriod: string = new Date().toISOString().split('T')[0]
) {
  const calculations = employees.map(employee => {
    if (isSalariedEmployee(employee)) {
      return calculateSalariedPayroll(employee, payPeriod);
    } else {
      return calculatePayrollForEmployee(employee);
    }
  });

  const summary = calculations.reduce(
    (acc, calc) => ({
      totalEmployees: acc.totalEmployees + 1,
      totalGrossPay: acc.totalGrossPay + calc.grossPay,
      totalNetPay: acc.totalNetPay + calc.netPay,
      totalTaxes: acc.totalTaxes + calc.taxAmount,
      totalDeductions: acc.totalDeductions + calc.deductions,
      totalBonuses: acc.totalBonuses + calc.bonuses
    }),
    {
      totalEmployees: 0,
      totalGrossPay: 0,
      totalNetPay: 0,
      totalTaxes: 0,
      totalDeductions: 0,
      totalBonuses: 0
    }
  );

  return {
    ...summary,
    payPeriod,
    generatedAt: new Date().toISOString(),
    calculations
  };
}

/**
 * Validates that calculated payroll makes mathematical sense
 */
export function validatePayrollCalculation(calculation: PayrollCalculation): boolean {
  const expectedGrossPay = calculation.regularPay + calculation.overtimePay + calculation.bonuses;
  const expectedNetPay = calculation.grossPay - calculation.taxAmount - calculation.deductions;

  const grossPayMatch = Math.abs(calculation.grossPay - expectedGrossPay) < 0.01;
  const netPayMatch = Math.abs(calculation.netPay - expectedNetPay) < 0.01;

  return grossPayMatch && netPayMatch;
}
