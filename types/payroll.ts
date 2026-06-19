/**
 * Unified TypeScript interfaces for the Payroll System
 * Provides type safety and consistency across all payroll operations
 */

export interface Employee {
  id: string;
  name: string;
  position?: string;
  department?: string;
  hourlyRate?: number;
  hoursWorked?: number;
  overtimeHours?: number;
  salary?: number; // For salaried employees
  taxRate: number; // 0.0 to 1.0
  deductions: number;
  bonuses: number;
  accountNumber?: string;
  routingNumber?: string;
  hireDate?: string;
  isActive?: boolean;
}

export interface PayrollCalculation {
  employeeId: string;
  regularPay: number;
  overtimePay: number;
  grossPay: number;
  taxAmount: number;
  deductions: number;
  bonuses: number;
  netPay: number;
  payPeriod: string; // ISO date string
  calculatedAt: string; // ISO date string
}

export interface PayrollRecord extends PayrollCalculation {
  id: string; // Unique record ID
  payDate: string; // ISO date string
  status: 'pending' | 'processed' | 'paid';
  paymentMethod?: 'direct_deposit' | 'check' | 'wire';
  notes?: string;
}

export interface PayrollSummary {
  totalEmployees: number;
  totalGrossPay: number;
  totalNetPay: number;
  totalTaxes: number;
  totalDeductions: number;
  totalBonuses: number;
  payPeriod: string;
  generatedAt: string;
}

export interface PayrollValidationError {
  field: string;
  message: string;
  value?: any;
}

export interface PayrollApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  errors?: PayrollValidationError[];
  timestamp: string;
}

export interface PayrollSyncResult {
  success: boolean;
  syncedEmployees: number;
  newRecords: number;
  errors: string[];
  duration: number; // milliseconds
}

// Input validation interfaces
export interface EmployeeInput {
  id?: string; // Optional for new employees
  name: string;
  position?: string;
  department?: string;
  hourlyRate?: number;
  hoursWorked?: number;
  overtimeHours?: number;
  salary?: number;
  taxRate: number;
  deductions: number;
  bonuses: number;
  accountNumber?: string;
  routingNumber?: string;
}

export interface PayrollCalculationInput {
  employeeId: string;
  hoursWorked?: number;
  hourlyRate?: number;
  overtimeHours?: number;
  taxRate?: number;
  deductions?: number;
  bonuses?: number;
  payPeriod?: string;
}

// Constants for validation
export const PAYROLL_CONSTANTS = {
  MAX_HOURLY_RATE: 1000,
  MAX_HOURS_WORKED: 168, // Hours in a week
  MAX_OVERTIME_HOURS: 80,
  MAX_TAX_RATE: 1.0,
  MIN_TAX_RATE: 0.0,
  MAX_DEDUCTIONS: 10000,
  MAX_BONUSES: 50000,
  OVERTIME_MULTIPLIER: 1.5,
} as const;
