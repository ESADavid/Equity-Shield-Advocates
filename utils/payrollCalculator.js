'use strict';
/**
 * Payroll Calculator Utilities
 * Provides standardized payroll calculation logic
 */
var __assign =
  (this && this.__assign) ||
  function () {
    __assign =
      Object.assign ||
      function (t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
          s = arguments[i];
          for (var p in s)
            if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
      };
    return __assign.apply(this, arguments);
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.calculatePayrollForEmployee = calculatePayrollForEmployee;
exports.calculateSalariedPayroll = calculateSalariedPayroll;
exports.isSalariedEmployee = isSalariedEmployee;
exports.calculatePayrollSummary = calculatePayrollSummary;
exports.validatePayrollCalculation = validatePayrollCalculation;
var payroll_js_1 = require('../types/payroll.js');
/**
 * Calculates payroll for an employee based on hours worked and rates
 */
function calculatePayrollForEmployee(employee, overrides) {
  var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k;
  // Use employee data as base, with optional overrides
  var hoursWorked =
    (_b =
      (_a =
        overrides === null || overrides === void 0
          ? void 0
          : overrides.hoursWorked) !== null && _a !== void 0
        ? _a
        : employee.hoursWorked) !== null && _b !== void 0
      ? _b
      : 0;
  var hourlyRate =
    (_d =
      (_c =
        overrides === null || overrides === void 0
          ? void 0
          : overrides.hourlyRate) !== null && _c !== void 0
        ? _c
        : employee.hourlyRate) !== null && _d !== void 0
      ? _d
      : 0;
  var overtimeHours =
    (_f =
      (_e =
        overrides === null || overrides === void 0
          ? void 0
          : overrides.overtimeHours) !== null && _e !== void 0
        ? _e
        : employee.overtimeHours) !== null && _f !== void 0
      ? _f
      : 0;
  var taxRate =
    (_g =
      overrides === null || overrides === void 0
        ? void 0
        : overrides.taxRate) !== null && _g !== void 0
      ? _g
      : employee.taxRate;
  var deductions =
    (_h =
      overrides === null || overrides === void 0
        ? void 0
        : overrides.deductions) !== null && _h !== void 0
      ? _h
      : employee.deductions;
  var bonuses =
    (_j =
      overrides === null || overrides === void 0
        ? void 0
        : overrides.bonuses) !== null && _j !== void 0
      ? _j
      : employee.bonuses;
  var payPeriod =
    (_k =
      overrides === null || overrides === void 0
        ? void 0
        : overrides.payPeriod) !== null && _k !== void 0
      ? _k
      : new Date().toISOString().split('T')[0];
  // Calculate regular pay
  var regularPay = hoursWorked * hourlyRate;
  // Calculate overtime pay (1.5x regular rate)
  var overtimePay =
    overtimeHours *
    hourlyRate *
    payroll_js_1.PAYROLL_CONSTANTS.OVERTIME_MULTIPLIER;
  // Calculate gross pay
  var grossPay = regularPay + overtimePay + bonuses;
  // Calculate tax amount
  var taxAmount = grossPay * taxRate;
  // Calculate net pay
  var netPay = grossPay - taxAmount - deductions;
  return {
    employeeId: employee.id,
    regularPay: Math.round(regularPay * 100) / 100, // Round to 2 decimal places
    overtimePay: Math.round(overtimePay * 100) / 100,
    grossPay: Math.round(grossPay * 100) / 100,
    taxAmount: Math.round(taxAmount * 100) / 100,
    deductions: deductions,
    bonuses: bonuses,
    netPay: Math.round(netPay * 100) / 100,
    payPeriod: payPeriod,
    calculatedAt: new Date().toISOString(),
  };
}
/**
 * Calculates payroll for a salaried employee
 */
function calculateSalariedPayroll(employee, payPeriod) {
  if (payPeriod === void 0) {
    payPeriod = new Date().toISOString().split('T')[0];
  }
  if (!employee.salary) {
    throw new Error('Employee does not have a salary defined');
  }
  var grossPay = employee.salary + employee.bonuses;
  var taxAmount = grossPay * employee.taxRate;
  var netPay = grossPay - taxAmount - employee.deductions;
  return {
    employeeId: employee.id,
    regularPay: Math.round(employee.salary * 100) / 100,
    overtimePay: 0, // Salaried employees don't get overtime
    grossPay: Math.round(grossPay * 100) / 100,
    taxAmount: Math.round(taxAmount * 100) / 100,
    deductions: employee.deductions,
    bonuses: employee.bonuses,
    netPay: Math.round(netPay * 100) / 100,
    payPeriod: payPeriod,
    calculatedAt: new Date().toISOString(),
  };
}
/**
 * Determines if an employee should be paid as salaried or hourly
 */
function isSalariedEmployee(employee) {
  return employee.salary !== undefined && employee.salary > 0;
}
/**
 * Calculates payroll summary for multiple employees
 */
function calculatePayrollSummary(employees, payPeriod) {
  if (payPeriod === void 0) {
    payPeriod = new Date().toISOString().split('T')[0];
  }
  var calculations = employees.map(function (employee) {
    if (isSalariedEmployee(employee)) {
      return calculateSalariedPayroll(employee, payPeriod);
    } else {
      return calculatePayrollForEmployee(employee);
    }
  });
  var summary = calculations.reduce(
    function (acc, calc) {
      return {
        totalEmployees: acc.totalEmployees + 1,
        totalGrossPay: acc.totalGrossPay + calc.grossPay,
        totalNetPay: acc.totalNetPay + calc.netPay,
        totalTaxes: acc.totalTaxes + calc.taxAmount,
        totalDeductions: acc.totalDeductions + calc.deductions,
        totalBonuses: acc.totalBonuses + calc.bonuses,
      };
    },
    {
      totalEmployees: 0,
      totalGrossPay: 0,
      totalNetPay: 0,
      totalTaxes: 0,
      totalDeductions: 0,
      totalBonuses: 0,
    }
  );
  return __assign(__assign({}, summary), {
    payPeriod: payPeriod,
    generatedAt: new Date().toISOString(),
    calculations: calculations,
  });
}
/**
 * Validates that calculated payroll makes mathematical sense
 */
function validatePayrollCalculation(calculation) {
  var expectedGrossPay =
    calculation.regularPay + calculation.overtimePay + calculation.bonuses;
  var expectedNetPay =
    calculation.grossPay - calculation.taxAmount - calculation.deductions;
  var grossPayMatch = Math.abs(calculation.grossPay - expectedGrossPay) < 0.01;
  var netPayMatch = Math.abs(calculation.netPay - expectedNetPay) < 0.01;
  return grossPayMatch && netPayMatch;
}
