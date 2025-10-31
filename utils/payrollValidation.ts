/**
 * Payroll Validation Utilities
 * Provides comprehensive validation for payroll data and calculations
 */

import {
  Employee,
  EmployeeInput,
  PayrollCalculationInput,
  PayrollValidationError,
  PAYROLL_CONSTANTS
} from '../types/payroll.js';

export class PayrollValidationError extends Error {
  constructor(
    public field: string,
    message: string,
    public value?: any
  ) {
    super(message);
    this.name = 'PayrollValidationError';
  }
}

/**
 * Validates employee input data
 */
export function validateEmployeeInput(input: EmployeeInput): PayrollValidationError[] {
  const errors: PayrollValidationError[] = [];

  // Required fields
  if (!input.name || typeof input.name !== 'string' || input.name.trim().length === 0) {
    errors.push(new PayrollValidationError('name', 'Employee name is required and must be a non-empty string'));
  }

  if (typeof input.taxRate !== 'number' || input.taxRate < PAYROLL_CONSTANTS.MIN_TAX_RATE || input.taxRate > PAYROLL_CONSTANTS.MAX_TAX_RATE) {
    errors.push(new PayrollValidationError('taxRate', `Tax rate must be between ${PAYROLL_CONSTANTS.MIN_TAX_RATE} and ${PAYROLL_CONSTANTS.MAX_TAX_RATE}`, input.taxRate));
  }

  if (typeof input.deductions !== 'number' || input.deductions < 0 || input.deductions > PAYROLL_CONSTANTS.MAX_DEDUCTIONS) {
    errors.push(new PayrollValidationError('deductions', `Deductions must be between 0 and ${PAYROLL_CONSTANTS.MAX_DEDUCTIONS}`, input.deductions));
  }

  if (typeof input.bonuses !== 'number' || input.bonuses < 0 || input.bonuses > PAYROLL_CONSTANTS.MAX_BONUSES) {
    errors.push(new PayrollValidationError('bonuses', `Bonuses must be between 0 and ${PAYROLL_CONSTANTS.MAX_BONUSES}`, input.bonuses));
  }

  // Optional numeric fields
  if (input.hourlyRate !== undefined) {
    if (typeof input.hourlyRate !== 'number' || input.hourlyRate < 0 || input.hourlyRate > PAYROLL_CONSTANTS.MAX_HOURLY_RATE) {
      errors.push(new PayrollValidationError('hourlyRate', `Hourly rate must be between 0 and ${PAYROLL_CONSTANTS.MAX_HOURLY_RATE}`, input.hourlyRate));
    }
  }

  if (input.hoursWorked !== undefined) {
    if (typeof input.hoursWorked !== 'number' || input.hoursWorked < 0 || input.hoursWorked > PAYROLL_CONSTANTS.MAX_HOURS_WORKED) {
      errors.push(new PayrollValidationError('hoursWorked', `Hours worked must be between 0 and ${PAYROLL_CONSTANTS.MAX_HOURS_WORKED}`, input.hoursWorked));
    }
  }

  if (input.overtimeHours !== undefined) {
    if (typeof input.overtimeHours !== 'number' || input.overtimeHours < 0 || input.overtimeHours > PAYROLL_CONSTANTS.MAX_OVERTIME_HOURS) {
      errors.push(new PayrollValidationError('overtimeHours', `Overtime hours must be between 0 and ${PAYROLL_CONSTANTS.MAX_OVERTIME_HOURS}`, input.overtimeHours));
    }
  }

  if (input.salary !== undefined) {
    if (typeof input.salary !== 'number' || input.salary < 0) {
      errors.push(new PayrollValidationError('salary', 'Salary must be a positive number', input.salary));
    }
  }

  // Banking information validation
  if (input.accountNumber !== undefined) {
    if (typeof input.accountNumber !== 'string' || !/^\d{8,17}$/.test(input.accountNumber)) {
      errors.push(new PayrollValidationError('accountNumber', 'Account number must be 8-17 digits', input.accountNumber));
    }
  }

  if (input.routingNumber !== undefined) {
    if (typeof input.routingNumber !== 'string' || !/^\d{9}$/.test(input.routingNumber)) {
      errors.push(new PayrollValidationError('routingNumber', 'Routing number must be 9 digits', input.routingNumber));
    }
  }

  return errors;
}

/**
 * Validates payroll calculation input
 */
export function validatePayrollCalculationInput(input: PayrollCalculationInput): PayrollValidationError[] {
  const errors: PayrollValidationError[] = [];

  if (!input.employeeId || typeof input.employeeId !== 'string' || input.employeeId.trim().length === 0) {
    errors.push(new PayrollValidationError('employeeId', 'Employee ID is required'));
  }

  // Optional fields with validation
  if (input.hoursWorked !== undefined) {
    if (typeof input.hoursWorked !== 'number' || input.hoursWorked < 0 || input.hoursWorked > PAYROLL_CONSTANTS.MAX_HOURS_WORKED) {
      errors.push(new PayrollValidationError('hoursWorked', `Hours worked must be between 0 and ${PAYROLL_CONSTANTS.MAX_HOURS_WORKED}`, input.hoursWorked));
    }
  }

  if (input.hourlyRate !== undefined) {
    if (typeof input.hourlyRate !== 'number' || input.hourlyRate < 0 || input.hourlyRate > PAYROLL_CONSTANTS.MAX_HOURLY_RATE) {
      errors.push(new PayrollValidationError('hourlyRate', `Hourly rate must be between 0 and ${PAYROLL_CONSTANTS.MAX_HOURLY_RATE}`, input.hourlyRate));
    }
  }

  if (input.overtimeHours !== undefined) {
    if (typeof input.overtimeHours !== 'number' || input.overtimeHours < 0 || input.overtimeHours > PAYROLL_CONSTANTS.MAX_OVERTIME_HOURS) {
      errors.push(new PayrollValidationError('overtimeHours', `Overtime hours must be between 0 and ${PAYROLL_CONSTANTS.MAX_OVERTIME_HOURS}`, input.overtimeHours));
    }
  }

  if (input.taxRate !== undefined) {
    if (typeof input.taxRate !== 'number' || input.taxRate < PAYROLL_CONSTANTS.MIN_TAX_RATE || input.taxRate > PAYROLL_CONSTANTS.MAX_TAX_RATE) {
      errors.push(new PayrollValidationError('taxRate', `Tax rate must be between ${PAYROLL_CONSTANTS.MIN_TAX_RATE} and ${PAYROLL_CONSTANTS.MAX_TAX_RATE}`, input.taxRate));
    }
  }

  if (input.deductions !== undefined) {
    if (typeof input.deductions !== 'number' || input.deductions < 0 || input.deductions > PAYROLL_CONSTANTS.MAX_DEDUCTIONS) {
      errors.push(new PayrollValidationError('deductions', `Deductions must be between 0 and ${PAYROLL_CONSTANTS.MAX_DEDUCTIONS}`, input.deductions));
    }
  }

  if (input.bonuses !== undefined) {
    if (typeof input.bonuses !== 'number' || input.bonuses < 0 || input.bonuses > PAYROLL_CONSTANTS.MAX_BONUSES) {
      errors.push(new PayrollValidationError('bonuses', `Bonuses must be between 0 and ${PAYROLL_CONSTANTS.MAX_BONUSES}`, input.bonuses));
    }
  }

  return errors;
}

/**
 * Validates a complete employee object
 */
export function validateEmployee(employee: Employee): PayrollValidationError[] {
  return validateEmployeeInput(employee);
}

/**
 * Sanitizes and normalizes employee input data
 */
export function sanitizeEmployeeInput(input: EmployeeInput): EmployeeInput {
  return {
    ...input,
    name: input.name?.trim(),
    position: input.position?.trim(),
    department: input.department?.trim(),
    accountNumber: input.accountNumber?.replace(/\D/g, ''), // Remove non-digits
    routingNumber: input.routingNumber?.replace(/\D/g, '') // Remove non-digits
  };
}

/**
 * Checks if an employee ID is valid format
 */
export function isValidEmployeeId(employeeId: string): boolean {
  return typeof employeeId === 'string' &&
         employeeId.length > 0 &&
         employeeId.length <= 50 &&
         /^[a-zA-Z0-9_-]+$/.test(employeeId);
}

/**
 * Validates pay period date string
 */
export function isValidPayPeriod(payPeriod: string): boolean {
  const date = new Date(payPeriod);
  return !isNaN(date.getTime()) && payPeriod === date.toISOString().split('T')[0];
}
