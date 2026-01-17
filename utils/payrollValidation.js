"use strict";
/**
 * Payroll Validation Utilities
 * Provides comprehensive validation for payroll data and calculations
 */
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.PayrollValidationError = void 0;
exports.validateEmployeeInput = validateEmployeeInput;
exports.validatePayrollCalculationInput = validatePayrollCalculationInput;
exports.validateEmployee = validateEmployee;
exports.sanitizeEmployeeInput = sanitizeEmployeeInput;
exports.isValidEmployeeId = isValidEmployeeId;
exports.isValidPayPeriod = isValidPayPeriod;
var payroll_js_1 = require("../types/payroll.js");
var PayrollValidationError = /** @class */ (function (_super) {
    __extends(PayrollValidationError, _super);
    function PayrollValidationError(field, message, value) {
        var _this = _super.call(this, message) || this;
        _this.name = 'PayrollValidationError';
        _this.field = field;
        _this.value = value;
        return _this;
    }
    return PayrollValidationError;
}(Error));
exports.PayrollValidationError = PayrollValidationError;
/**
 * Validates a required string field
 */
function validateRequiredString(value, fieldName, errors) {
    if (!value || typeof value !== 'string' || value.trim().length === 0) {
        errors.push(new PayrollValidationError(fieldName, "".concat(fieldName, " is required and must be a non-empty string")));
    }
}
/**
 * Validates a numeric field within bounds
 */
function validateNumericField(value, fieldName, min, max, errors) {
    if (typeof value !== 'number' || value < min || value > max) {
        errors.push(new PayrollValidationError(fieldName, "".concat(fieldName, " must be between ").concat(min, " and ").concat(max), value));
    }
}
/**
 * Validates an optional numeric field
 */
function validateOptionalNumericField(value, fieldName, min, max, errors) {
    if (value !== undefined) {
        validateNumericField(value, fieldName, min, max, errors);
    }
}
/**
 * Validates banking information
 */
function validateBankingInfo(input, errors) {
    if (input.accountNumber !== undefined) {
        if (typeof input.accountNumber !== 'string' ||
            !/^\d{8,17}$/.test(input.accountNumber)) {
            errors.push(new PayrollValidationError('accountNumber', 'Account number must be 8-17 digits', input.accountNumber));
        }
    }
    if (input.routingNumber !== undefined) {
        if (typeof input.routingNumber !== 'string' ||
            !/^\d{9}$/.test(input.routingNumber)) {
            errors.push(new PayrollValidationError('routingNumber', 'Routing number must be 9 digits', input.routingNumber));
        }
    }
}
/**
 * Validates salary field
 */
function validateSalaryField(input, errors) {
    if (input.salary !== undefined) {
        if (typeof input.salary !== 'number' || input.salary < 0) {
            errors.push(new PayrollValidationError('salary', 'Salary must be a positive number', input.salary));
        }
    }
}
/**
 * Validates optional payroll calculation fields
 */
function validateOptionalPayrollFields(input, errors) {
    validateOptionalNumericField(input.hoursWorked, 'hoursWorked', 0, payroll_js_1.PAYROLL_CONSTANTS.MAX_HOURS_WORKED, errors);
    validateOptionalNumericField(input.hourlyRate, 'hourlyRate', 0, payroll_js_1.PAYROLL_CONSTANTS.MAX_HOURLY_RATE, errors);
    validateOptionalNumericField(input.overtimeHours, 'overtimeHours', 0, payroll_js_1.PAYROLL_CONSTANTS.MAX_OVERTIME_HOURS, errors);
    validateOptionalNumericField(input.taxRate, 'taxRate', payroll_js_1.PAYROLL_CONSTANTS.MIN_TAX_RATE, payroll_js_1.PAYROLL_CONSTANTS.MAX_TAX_RATE, errors);
    validateOptionalNumericField(input.deductions, 'deductions', 0, payroll_js_1.PAYROLL_CONSTANTS.MAX_DEDUCTIONS, errors);
    validateOptionalNumericField(input.bonuses, 'bonuses', 0, payroll_js_1.PAYROLL_CONSTANTS.MAX_BONUSES, errors);
}
/**
 * Validates employee input data
 */
function validateEmployeeInput(input) {
    var errors = [];
    // Required fields
    validateRequiredString(input.name, 'name', errors);
    validateNumericField(input.taxRate, 'taxRate', payroll_js_1.PAYROLL_CONSTANTS.MIN_TAX_RATE, payroll_js_1.PAYROLL_CONSTANTS.MAX_TAX_RATE, errors);
    validateNumericField(input.deductions, 'deductions', 0, payroll_js_1.PAYROLL_CONSTANTS.MAX_DEDUCTIONS, errors);
    validateNumericField(input.bonuses, 'bonuses', 0, payroll_js_1.PAYROLL_CONSTANTS.MAX_BONUSES, errors);
    // Optional numeric fields
    validateOptionalNumericField(input.hourlyRate, 'hourlyRate', 0, payroll_js_1.PAYROLL_CONSTANTS.MAX_HOURLY_RATE, errors);
    validateOptionalNumericField(input.hoursWorked, 'hoursWorked', 0, payroll_js_1.PAYROLL_CONSTANTS.MAX_HOURS_WORKED, errors);
    validateOptionalNumericField(input.overtimeHours, 'overtimeHours', 0, payroll_js_1.PAYROLL_CONSTANTS.MAX_OVERTIME_HOURS, errors);
    // Salary validation
    validateSalaryField(input, errors);
    // Banking information validation
    validateBankingInfo(input, errors);
    return errors;
}
/**
 * Validates payroll calculation input
 */
function validatePayrollCalculationInput(input) {
    var errors = [];
    // Required field
    validateRequiredString(input.employeeId, 'employeeId', errors);
    // Optional fields with validation
    validateOptionalPayrollFields(input, errors);
    return errors;
}
/**
 * Validates a complete employee object
 */
function validateEmployee(employee) {
    return validateEmployeeInput(employee);
}
/**
 * Sanitizes and normalizes employee input data
 */
function sanitizeEmployeeInput(input) {
    var _a, _b, _c;
    var sanitized = {
        name: (_a = input.name) === null || _a === void 0 ? void 0 : _a.trim(),
        taxRate: input.taxRate,
        deductions: input.deductions,
        bonuses: input.bonuses,
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
    var accountNumber = (_b = input.accountNumber) === null || _b === void 0 ? void 0 : _b.replace(/\D/g, '');
    if (accountNumber) {
        sanitized.accountNumber = accountNumber;
    }
    var routingNumber = (_c = input.routingNumber) === null || _c === void 0 ? void 0 : _c.replace(/\D/g, '');
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
function isValidEmployeeId(employeeId) {
    return (typeof employeeId === 'string' &&
        employeeId.length > 0 &&
        employeeId.length <= 50 &&
        /^[a-zA-Z0-9_-]+$/.test(employeeId));
}
/**
 * Validates pay period date string
 */
function isValidPayPeriod(payPeriod) {
    var date = new Date(payPeriod);
    return (!Number.isNaN(date.getTime()) &&
        payPeriod === date.toISOString().split('T')[0]);
}
