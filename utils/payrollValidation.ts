/**
 * Payroll Validation Utilities
 * Provides comprehensive validation for payroll data and calculations
 */

import {
  Employee,
  EmployeeInput,
  PayrollCalculationInput,
  PAYROLL_CONSTANTS
} from '../types/payroll.js';

export class PayrollValidationError extends Error {
  public field: string;
  public value?: any;

  constructor(field: string, message: string, value?: any) {
    super(message);
    this.name = 'PayrollValidationError';
    this.field = field;
    this.value = value;
  }
}

/**
 * Validates a required string field
 */
function validateRequiredString(value: any, fieldName: string, errors: PayrollValidationError[]): void {
  if (!value || typeof value !== 'string' || value.trim().length === 0) {
    errors.push(new PayrollValidationError(fieldName, `${fieldName} is required and must be a non-empty string`));
  }
}

/**
 * Validates a numeric field within bounds
 */
function validateNumericField(value: any, fieldName: string, min: number, max: number, errors: PayrollValidationError[]): void {
  if (typeof value !== 'number' || value < min || value > max) {
    errors.push(new PayrollValidationError(fieldName, `${fieldName} must be between ${min} and ${max}`, value));
  }
}

/**
 * Validates an optional numeric field
 */
function validateOptionalNumericField(value: any, fieldName: string, min: number, max: number, errors: PayrollValidationError[]): void {
  if (value !== undefined) {
    validateNumericField(value, fieldName, min, max, errors);
  }
}

/**
 * Validates banking information
 */
function validateBankingInfo(input: EmployeeInput, errors: PayrollValidationError[]): void {
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
}

/**
 * Validates salary field
 */
function validateSalaryField(input: EmployeeInput, errors: PayrollValidationError[]): void {
  if (input.salary !== undefined) {
    if (typeof input.salary !== 'number' || input.salary < 0) {
      errors.push(new PayrollValidationError('salary', 'Salary must be a positive number', input.salary));
    }
  }
}

/**
 * Validates optional payroll calculation fields
 */
function validateOptionalPayrollFields(input: PayrollCalculationInput, errors: PayrollValidationError[]): void {
  validateOptionalNumericField(input.hoursWorked, 'hoursWorked', 0, PAYROLL_CONSTANTS.MAX_HOURS_WORKED, errors);
  validateOptionalNumericField(input.hourlyRate, 'hourlyRate', 0, PAYROLL_CONSTANTS.MAX_HOURLY_RATE, errors);
  validateOptionalNumericField(input.overtimeHours, 'overtimeHours', 0, PAYROLL_CONSTANTS.MAX_OVERTIME_HOURS, errors);
  validateOptionalNumericField(input.taxRate, 'taxRate', PAYROLL_CONSTANTS.MIN_TAX_RATE, PAYROLL_CONSTANTS.MAX_TAX_RATE, errors);
  validateOptionalNumericField(input.deductions, 'deductions', 0, PAYROLL_CONSTANTS.MAX_DEDUCTIONS, errors);
  validateOptionalNumericField(input.bonuses, 'bonuses', 0, PAYROLL_CONSTANTS.MAX_BONUSES, errors);
}

/**
 * Validates employee input data
 */
export function validateEmployeeInput(input: EmployeeInput): PayrollValidationError[] {
  const errors: PayrollValidationError[] = [];

  // Required fields
  validateRequiredString(input.name, 'name', errors);
  validateNumericField(input.taxRate, 'taxRate', PAYROLL_CONSTANTS.MIN_TAX_RATE, PAYROLL_CONSTANTS.MAX_TAX_RATE, errors);
  validateNumericField(input.deductions, 'deductions', 0, PAYROLL_CONSTANTS.MAX_DEDUCTIONS, errors);
  validateNumericField(input.bonuses, 'bonuses', 0, PAYROLL_CONSTANTS.MAX_BONUSES, errors);

  // Optional numeric fields
  validateOptionalNumericField(input.hourlyRate, 'hourlyRate', 0, PAYROLL_CONSTANTS.MAX_HOURLY_RATE, errors);
  validateOptionalNumericField(input.hoursWorked, 'hoursWorked', 0, PAYROLL_CONSTANTS.MAX_HOURS_WORKED, errors);
  validateOptionalNumericField(input.overtimeHours, 'overtimeHours', 0, PAYROLL_CONSTANTS.MAX_OVERTIME_HOURS, errors);

  // Salary validation
  validateSalaryField(input, errors);

  // Banking information validation
  validateBankingInfo(input, errors);

  return errors;
}

/**
 * Validates payroll calculation input
 */
export function validatePayrollCalculationInput(input: PayrollCalculationInput): PayrollValidationError[] {
  const errors: PayrollValidationError[] = [];

  // Required field
  validateRequiredString(input.employeeId, 'employeeId', errors);

  // Optional fields with validation
  validateOptionalPayrollFields(input, errors);

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
  const sanitized: EmployeeInput = {
    name: input.name?.trim(),
    taxRate: input.taxRate,
    deductions: input.deductions,
    bonuses: input.bonuses
  };

  if (input.hourlyRate !== undefined) {
    sanitized.hourlyRate = input.hourlyRate;
  }

  if (input.hoursWorked !== undefined) {
    sanitized.hoursWorked = input.hoursWorked;
  }

  if (input.overtimeHours !== undefined) {
    sanitized.overtimeHours = input.overtimeHours;
  }

  if (input.salary !== undefined) {
    sanitized.salary = input.salary;
  }

  const accountNumber = input.accountNumber?.replace(/\D/g, '');
  if (accountNumber) {
    sanitized.accountNumber = accountNumber;
  }

  const routingNumber = input.routingNumber?.replace(/\D/g, '');
  if (routingNumber) {
    sanitized.routingNumber = routingNumber;
  }

  if (input.position !== undefined) {
    sanitized.position = input.position.trim();
  }

  if (input.department !== undefined) {
    sanitized.department = input.department.trim();
  }

  return sanitized;
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
  return !Number.isNaN(date.getTime()) && payPeriod === date.toISOString().split('T')[0];
}
