"use strict";
/**
 * Unified Payroll System
 * Consolidated TypeScript implementation with proper validation and error handling
 */
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.payrollSystem = exports.PayrollSystem = void 0;
var fs = require("node:fs");
var path = require("node:path");
var payrollValidation_js_1 = require("./utils/payrollValidation.js");
var payrollCalculator_js_1 = require("./utils/payrollCalculator.js");
// Use module directory for data directory - works in both Node.js and Jest
var DATA_DIR = path.join(__dirname, 'data');
var EMPLOYEES_FILE = path.join(DATA_DIR, 'employees.json');
var PAYROLL_RECORDS_FILE = path.join(DATA_DIR, 'payroll_records.json');
var PayrollSystem = /** @class */ (function () {
    function PayrollSystem() {
        this.employees = new Map();
        this.payrollRecords = [];
        this.ensureDataDirectory();
        this.loadEmployees();
        this.loadPayrollRecords();
    }
    PayrollSystem.prototype.ensureDataDirectory = function () {
        var dataDir = path.dirname(EMPLOYEES_FILE);
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
    };
    PayrollSystem.prototype.loadEmployees = function () {
        try {
            if (fs.existsSync(EMPLOYEES_FILE)) {
                var data = fs.readFileSync(EMPLOYEES_FILE, 'utf-8');
                var employeesArray = JSON.parse(data);
                this.employees = new Map(employeesArray.map(function (emp) { return [emp.id, emp]; }));
            }
        }
        catch (error) {
            console.error('Failed to load employees:', error);
            this.employees = new Map();
        }
    };
    PayrollSystem.prototype.saveEmployees = function () {
        try {
            var employeesArray = Array.from(this.employees.values());
            fs.writeFileSync(EMPLOYEES_FILE, JSON.stringify(employeesArray, null, 2), 'utf-8');
        }
        catch (error) {
            console.error('Failed to save employees:', error);
            throw new Error('Failed to save employee data');
        }
    };
    PayrollSystem.prototype.loadPayrollRecords = function () {
        try {
            if (fs.existsSync(PAYROLL_RECORDS_FILE)) {
                var data = fs.readFileSync(PAYROLL_RECORDS_FILE, 'utf-8');
                this.payrollRecords = JSON.parse(data);
            }
        }
        catch (error) {
            console.error('Failed to load payroll records:', error);
            this.payrollRecords = [];
        }
    };
    PayrollSystem.prototype.savePayrollRecords = function () {
        try {
            fs.writeFileSync(PAYROLL_RECORDS_FILE, JSON.stringify(this.payrollRecords, null, 2), 'utf-8');
        }
        catch (error) {
            console.error('Failed to save payroll records:', error);
            throw new Error('Failed to save payroll records');
        }
    };
    /**
     * Adds a new employee to the system
     */
    PayrollSystem.prototype.addEmployee = function (input) {
        try {
            // Validate input
            var validationErrors = (0, payrollValidation_js_1.validateEmployeeInput)(input);
            if (validationErrors.length > 0) {
                return {
                    success: false,
                    errors: validationErrors,
                    timestamp: new Date().toISOString(),
                };
            }
            // Sanitize input
            var sanitizedInput = (0, payrollValidation_js_1.sanitizeEmployeeInput)(input);
            // Generate ID if not provided
            var employeeId = sanitizedInput.id || this.generateEmployeeId();
            // Check if employee already exists
            if (this.employees.has(employeeId)) {
                return {
                    success: false,
                    error: "Employee with ID ".concat(employeeId, " already exists"),
                    timestamp: new Date().toISOString(),
                };
            }
            // Create employee object
            var employee = __assign(__assign(__assign(__assign(__assign(__assign(__assign(__assign({ id: employeeId, name: sanitizedInput.name, taxRate: sanitizedInput.taxRate, deductions: sanitizedInput.deductions, bonuses: sanitizedInput.bonuses, hireDate: new Date().toISOString(), isActive: true }, (sanitizedInput.position !== undefined && {
                position: sanitizedInput.position,
            })), (sanitizedInput.department !== undefined && {
                department: sanitizedInput.department,
            })), (sanitizedInput.hourlyRate !== undefined && {
                hourlyRate: sanitizedInput.hourlyRate,
            })), (sanitizedInput.hoursWorked !== undefined && {
                hoursWorked: sanitizedInput.hoursWorked,
            })), (sanitizedInput.overtimeHours !== undefined && {
                overtimeHours: sanitizedInput.overtimeHours,
            })), (sanitizedInput.salary !== undefined && {
                salary: sanitizedInput.salary,
            })), (sanitizedInput.accountNumber !== undefined && {
                accountNumber: sanitizedInput.accountNumber,
            })), (sanitizedInput.routingNumber !== undefined && {
                routingNumber: sanitizedInput.routingNumber,
            }));
            // Add to collection
            this.employees.set(employeeId, employee);
            this.saveEmployees();
            return {
                success: true,
                data: employee,
                timestamp: new Date().toISOString(),
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString(),
            };
        }
    };
    /**
     * Updates an existing employee
     */
    PayrollSystem.prototype.updateEmployee = function (employeeId, updates) {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m;
        try {
            var existingEmployee = this.employees.get(employeeId);
            if (!existingEmployee) {
                return {
                    success: false,
                    error: "Employee with ID ".concat(employeeId, " not found"),
                    timestamp: new Date().toISOString(),
                };
            }
            // Create update input with existing values as defaults
            var updateInput = __assign(__assign(__assign(__assign(__assign(__assign(__assign(__assign({ id: employeeId, name: (_a = updates.name) !== null && _a !== void 0 ? _a : existingEmployee.name, taxRate: (_b = updates.taxRate) !== null && _b !== void 0 ? _b : existingEmployee.taxRate, deductions: (_c = updates.deductions) !== null && _c !== void 0 ? _c : existingEmployee.deductions, bonuses: (_d = updates.bonuses) !== null && _d !== void 0 ? _d : existingEmployee.bonuses }, (updates.position !== undefined ||
                existingEmployee.position !== undefined
                ? { position: (_e = updates.position) !== null && _e !== void 0 ? _e : existingEmployee.position }
                : {})), (updates.department !== undefined ||
                existingEmployee.department !== undefined
                ? { department: (_f = updates.department) !== null && _f !== void 0 ? _f : existingEmployee.department }
                : {})), (updates.hourlyRate !== undefined ||
                existingEmployee.hourlyRate !== undefined
                ? { hourlyRate: (_g = updates.hourlyRate) !== null && _g !== void 0 ? _g : existingEmployee.hourlyRate }
                : {})), (updates.hoursWorked !== undefined ||
                existingEmployee.hoursWorked !== undefined
                ? { hoursWorked: (_h = updates.hoursWorked) !== null && _h !== void 0 ? _h : existingEmployee.hoursWorked }
                : {})), (updates.overtimeHours !== undefined ||
                existingEmployee.overtimeHours !== undefined
                ? {
                    overtimeHours: (_j = updates.overtimeHours) !== null && _j !== void 0 ? _j : existingEmployee.overtimeHours,
                }
                : {})), (updates.salary !== undefined ||
                existingEmployee.salary !== undefined
                ? { salary: (_k = updates.salary) !== null && _k !== void 0 ? _k : existingEmployee.salary }
                : {})), (updates.accountNumber !== undefined ||
                existingEmployee.accountNumber !== undefined
                ? {
                    accountNumber: (_l = updates.accountNumber) !== null && _l !== void 0 ? _l : existingEmployee.accountNumber,
                }
                : {})), (updates.routingNumber !== undefined ||
                existingEmployee.routingNumber !== undefined
                ? {
                    routingNumber: (_m = updates.routingNumber) !== null && _m !== void 0 ? _m : existingEmployee.routingNumber,
                }
                : {}));
            // Validate updates
            var validationErrors = (0, payrollValidation_js_1.validateEmployeeInput)(updateInput);
            if (validationErrors.length > 0) {
                return {
                    success: false,
                    errors: validationErrors,
                    timestamp: new Date().toISOString(),
                };
            }
            // Sanitize and update
            var sanitizedUpdates = (0, payrollValidation_js_1.sanitizeEmployeeInput)(updateInput);
            var updatedEmployee = __assign(__assign(__assign({}, existingEmployee), sanitizedUpdates), { id: employeeId });
            this.employees.set(employeeId, updatedEmployee);
            this.saveEmployees();
            return {
                success: true,
                data: updatedEmployee,
                timestamp: new Date().toISOString(),
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString(),
            };
        }
    };
    /**
     * Deletes an employee from the system
     */
    PayrollSystem.prototype.deleteEmployee = function (employeeId) {
        try {
            if (!this.employees.has(employeeId)) {
                return {
                    success: false,
                    error: "Employee with ID ".concat(employeeId, " not found"),
                    timestamp: new Date().toISOString(),
                };
            }
            this.employees.delete(employeeId);
            this.saveEmployees();
            return {
                success: true,
                data: true,
                timestamp: new Date().toISOString(),
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString(),
            };
        }
    };
    /**
     * Gets all employees
     */
    PayrollSystem.prototype.getEmployees = function () {
        try {
            var employees = Array.from(this.employees.values());
            return {
                success: true,
                data: employees,
                timestamp: new Date().toISOString(),
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString(),
            };
        }
    };
    /**
     * Gets a specific employee by ID
     */
    PayrollSystem.prototype.getEmployee = function (employeeId) {
        try {
            var employee = this.employees.get(employeeId);
            if (!employee) {
                return {
                    success: false,
                    error: "Employee with ID ".concat(employeeId, " not found"),
                    timestamp: new Date().toISOString(),
                };
            }
            return {
                success: true,
                data: employee,
                timestamp: new Date().toISOString(),
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString(),
            };
        }
    };
    /**
     * Processes payroll for all employees
     */
    PayrollSystem.prototype.processPayroll = function (payDate) {
        var _a;
        try {
            var payPeriod = payDate || new Date().toISOString().split('T')[0];
            var records = [];
            for (var _i = 0, _b = this.employees.values(); _i < _b.length; _i++) {
                var employee = _b[_i];
                if (!employee.isActive)
                    continue;
                var calculation = void 0;
                if ((0, payrollCalculator_js_1.isSalariedEmployee)(employee)) {
                    calculation = (0, payrollCalculator_js_1.calculateSalariedPayroll)(employee, payPeriod);
                }
                else {
                    calculation = (0, payrollCalculator_js_1.calculatePayrollForEmployee)(employee);
                }
                var record = __assign(__assign({}, calculation), { id: this.generatePayrollRecordId(), payDate: payPeriod, status: 'processed', paymentMethod: employee.accountNumber ? 'direct_deposit' : 'check' });
                records.push(record);
            }
            // Add to records and save
            (_a = this.payrollRecords).push.apply(_a, records);
            this.savePayrollRecords();
            return {
                success: true,
                data: records,
                timestamp: new Date().toISOString(),
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString(),
            };
        }
    };
    /**
     * Gets payroll records with optional filtering
     */
    PayrollSystem.prototype.getPayrollRecords = function (employeeId, payPeriod) {
        try {
            var records = this.payrollRecords;
            if (employeeId) {
                records = records.filter(function (r) { return r.employeeId === employeeId; });
            }
            if (payPeriod) {
                records = records.filter(function (r) { return r.payPeriod === payPeriod; });
            }
            return {
                success: true,
                data: records,
                timestamp: new Date().toISOString(),
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString(),
            };
        }
    };
    /**
     * Gets payroll summary for a specific period
     */
    PayrollSystem.prototype.getPayrollSummary = function (payPeriod) {
        try {
            var targetPeriod = payPeriod || new Date().toISOString().split('T')[0];
            var employees = Array.from(this.employees.values()).filter(function (e) { return e.isActive; });
            var summary = (0, payrollCalculator_js_1.calculatePayrollSummary)(employees, targetPeriod);
            return {
                success: true,
                data: summary,
                timestamp: new Date().toISOString(),
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString(),
            };
        }
    };
    /**
     * Syncs payroll data (placeholder for future integration)
     */
    PayrollSystem.prototype.syncPayrollData = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                // Placeholder implementation
                return [2 /*return*/, {
                        success: true,
                        data: {
                            success: true,
                            syncedEmployees: this.employees.size,
                            newRecords: 0,
                            errors: [],
                            duration: 0,
                        },
                        timestamp: new Date().toISOString(),
                    }];
            });
        });
    };
    PayrollSystem.prototype.generateEmployeeId = function () {
        var id;
        do {
            id = "EMP".concat(Date.now().toString(36).toUpperCase());
        } while (this.employees.has(id));
        return id;
    };
    PayrollSystem.prototype.generatePayrollRecordId = function () {
        return "PR".concat(Date.now()).concat(Math.random().toString(36).substring(2, 7).toUpperCase());
    };
    return PayrollSystem;
}());
exports.PayrollSystem = PayrollSystem;
// Export singleton instance
exports.payrollSystem = new PayrollSystem();
