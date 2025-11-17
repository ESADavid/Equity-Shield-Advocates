"use strict";
/**
 * Unified TypeScript interfaces for the Payroll System
 * Provides type safety and consistency across all payroll operations
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PAYROLL_CONSTANTS = void 0;
// Constants for validation
exports.PAYROLL_CONSTANTS = {
    MAX_HOURLY_RATE: 1000,
    MAX_HOURS_WORKED: 168, // Hours in a week
    MAX_OVERTIME_HOURS: 80,
    MAX_TAX_RATE: 1.0,
    MIN_TAX_RATE: 0.0,
    MAX_DEDUCTIONS: 10000,
    MAX_BONUSES: 50000,
    OVERTIME_MULTIPLIER: 1.5
};
//# sourceMappingURL=payroll.js.map