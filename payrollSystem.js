"use strict";
/**
 * Unified Payroll System
 * Consolidated TypeScript implementation with proper validation and error handling
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.payrollSystem = exports.PayrollSystem = void 0;
const fs = __importStar(require("node:fs"));
const path = __importStar(require("node:path"));
const payrollValidation_js_1 = require("./utils/payrollValidation.js");
const payrollCalculator_js_1 = require("./utils/payrollCalculator.js");
// Use module directory for data directory - works in both Node.js and Jest
const DATA_DIR = path.join(__dirname, 'data');
const EMPLOYEES_FILE = path.join(DATA_DIR, 'employees.json');
const PAYROLL_RECORDS_FILE = path.join(DATA_DIR, 'payroll_records.json');
class PayrollSystem {
    constructor() {
        this.employees = new Map();
        this.payrollRecords = [];
        this.ensureDataDirectory();
        this.loadEmployees();
        this.loadPayrollRecords();
    }
    ensureDataDirectory() {
        const dataDir = path.dirname(EMPLOYEES_FILE);
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }
    }
    loadEmployees() {
        try {
            if (fs.existsSync(EMPLOYEES_FILE)) {
                const data = fs.readFileSync(EMPLOYEES_FILE, 'utf-8');
                const employeesArray = JSON.parse(data);
                this.employees = new Map(employeesArray.map(emp => [emp.id, emp]));
            }
        }
        catch (error) {
            console.error('Failed to load employees:', error);
            this.employees = new Map();
        }
    }
    saveEmployees() {
        try {
            const employeesArray = Array.from(this.employees.values());
            fs.writeFileSync(EMPLOYEES_FILE, JSON.stringify(employeesArray, null, 2), 'utf-8');
        }
        catch (error) {
            console.error('Failed to save employees:', error);
            throw new Error('Failed to save employee data');
        }
    }
    loadPayrollRecords() {
        try {
            if (fs.existsSync(PAYROLL_RECORDS_FILE)) {
                const data = fs.readFileSync(PAYROLL_RECORDS_FILE, 'utf-8');
                this.payrollRecords = JSON.parse(data);
            }
        }
        catch (error) {
            console.error('Failed to load payroll records:', error);
            this.payrollRecords = [];
        }
    }
    savePayrollRecords() {
        try {
            fs.writeFileSync(PAYROLL_RECORDS_FILE, JSON.stringify(this.payrollRecords, null, 2), 'utf-8');
        }
        catch (error) {
            console.error('Failed to save payroll records:', error);
            throw new Error('Failed to save payroll records');
        }
    }
    /**
     * Adds a new employee to the system
     */
    addEmployee(input) {
        try {
            // Validate input
            const validationErrors = (0, payrollValidation_js_1.validateEmployeeInput)(input);
            if (validationErrors.length > 0) {
                return {
                    success: false,
                    errors: validationErrors,
                    timestamp: new Date().toISOString()
                };
            }
            // Sanitize input
            const sanitizedInput = (0, payrollValidation_js_1.sanitizeEmployeeInput)(input);
            // Generate ID if not provided
            const employeeId = sanitizedInput.id || this.generateEmployeeId();
            // Check if employee already exists
            if (this.employees.has(employeeId)) {
                return {
                    success: false,
                    error: `Employee with ID ${employeeId} already exists`,
                    timestamp: new Date().toISOString()
                };
            }
            // Create employee object
            const employee = {
                id: employeeId,
                name: sanitizedInput.name,
                taxRate: sanitizedInput.taxRate,
                deductions: sanitizedInput.deductions,
                bonuses: sanitizedInput.bonuses,
                hireDate: new Date().toISOString(),
                isActive: true,
                ...(sanitizedInput.position !== undefined && { position: sanitizedInput.position }),
                ...(sanitizedInput.department !== undefined && { department: sanitizedInput.department }),
                ...(sanitizedInput.hourlyRate !== undefined && { hourlyRate: sanitizedInput.hourlyRate }),
                ...(sanitizedInput.hoursWorked !== undefined && { hoursWorked: sanitizedInput.hoursWorked }),
                ...(sanitizedInput.overtimeHours !== undefined && { overtimeHours: sanitizedInput.overtimeHours }),
                ...(sanitizedInput.salary !== undefined && { salary: sanitizedInput.salary }),
                ...(sanitizedInput.accountNumber !== undefined && { accountNumber: sanitizedInput.accountNumber }),
                ...(sanitizedInput.routingNumber !== undefined && { routingNumber: sanitizedInput.routingNumber })
            };
            // Add to collection
            this.employees.set(employeeId, employee);
            this.saveEmployees();
            return {
                success: true,
                data: employee,
                timestamp: new Date().toISOString()
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString()
            };
        }
    }
    /**
     * Updates an existing employee
     */
    updateEmployee(employeeId, updates) {
        try {
            const existingEmployee = this.employees.get(employeeId);
            if (!existingEmployee) {
                return {
                    success: false,
                    error: `Employee with ID ${employeeId} not found`,
                    timestamp: new Date().toISOString()
                };
            }
            // Create update input with existing values as defaults
            const updateInput = {
                id: employeeId,
                name: updates.name ?? existingEmployee.name,
                taxRate: updates.taxRate ?? existingEmployee.taxRate,
                deductions: updates.deductions ?? existingEmployee.deductions,
                bonuses: updates.bonuses ?? existingEmployee.bonuses,
                ...(updates.position !== undefined || existingEmployee.position !== undefined ? { position: updates.position ?? existingEmployee.position } : {}),
                ...(updates.department !== undefined || existingEmployee.department !== undefined ? { department: updates.department ?? existingEmployee.department } : {}),
                ...(updates.hourlyRate !== undefined || existingEmployee.hourlyRate !== undefined ? { hourlyRate: updates.hourlyRate ?? existingEmployee.hourlyRate } : {}),
                ...(updates.hoursWorked !== undefined || existingEmployee.hoursWorked !== undefined ? { hoursWorked: updates.hoursWorked ?? existingEmployee.hoursWorked } : {}),
                ...(updates.overtimeHours !== undefined || existingEmployee.overtimeHours !== undefined ? { overtimeHours: updates.overtimeHours ?? existingEmployee.overtimeHours } : {}),
                ...(updates.salary !== undefined || existingEmployee.salary !== undefined ? { salary: updates.salary ?? existingEmployee.salary } : {}),
                ...(updates.accountNumber !== undefined || existingEmployee.accountNumber !== undefined ? { accountNumber: updates.accountNumber ?? existingEmployee.accountNumber } : {}),
                ...(updates.routingNumber !== undefined || existingEmployee.routingNumber !== undefined ? { routingNumber: updates.routingNumber ?? existingEmployee.routingNumber } : {})
            };
            // Validate updates
            const validationErrors = (0, payrollValidation_js_1.validateEmployeeInput)(updateInput);
            if (validationErrors.length > 0) {
                return {
                    success: false,
                    errors: validationErrors,
                    timestamp: new Date().toISOString()
                };
            }
            // Sanitize and update
            const sanitizedUpdates = (0, payrollValidation_js_1.sanitizeEmployeeInput)(updateInput);
            const updatedEmployee = {
                ...existingEmployee,
                ...sanitizedUpdates,
                id: employeeId // Ensure ID doesn't change
            };
            this.employees.set(employeeId, updatedEmployee);
            this.saveEmployees();
            return {
                success: true,
                data: updatedEmployee,
                timestamp: new Date().toISOString()
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString()
            };
        }
    }
    /**
     * Deletes an employee from the system
     */
    deleteEmployee(employeeId) {
        try {
            if (!this.employees.has(employeeId)) {
                return {
                    success: false,
                    error: `Employee with ID ${employeeId} not found`,
                    timestamp: new Date().toISOString()
                };
            }
            this.employees.delete(employeeId);
            this.saveEmployees();
            return {
                success: true,
                data: true,
                timestamp: new Date().toISOString()
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString()
            };
        }
    }
    /**
     * Gets all employees
     */
    getEmployees() {
        try {
            const employees = Array.from(this.employees.values());
            return {
                success: true,
                data: employees,
                timestamp: new Date().toISOString()
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString()
            };
        }
    }
    /**
     * Gets a specific employee by ID
     */
    getEmployee(employeeId) {
        try {
            const employee = this.employees.get(employeeId);
            if (!employee) {
                return {
                    success: false,
                    error: `Employee with ID ${employeeId} not found`,
                    timestamp: new Date().toISOString()
                };
            }
            return {
                success: true,
                data: employee,
                timestamp: new Date().toISOString()
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString()
            };
        }
    }
    /**
     * Processes payroll for all employees
     */
    processPayroll(payDate) {
        try {
            const payPeriod = payDate || new Date().toISOString().split('T')[0];
            const records = [];
            for (const employee of this.employees.values()) {
                if (!employee.isActive)
                    continue;
                let calculation;
                if ((0, payrollCalculator_js_1.isSalariedEmployee)(employee)) {
                    calculation = (0, payrollCalculator_js_1.calculateSalariedPayroll)(employee, payPeriod);
                }
                else {
                    calculation = (0, payrollCalculator_js_1.calculatePayrollForEmployee)(employee);
                }
                const record = {
                    ...calculation,
                    id: this.generatePayrollRecordId(),
                    payDate: payPeriod,
                    status: 'processed',
                    paymentMethod: employee.accountNumber ? 'direct_deposit' : 'check'
                };
                records.push(record);
            }
            // Add to records and save
            this.payrollRecords.push(...records);
            this.savePayrollRecords();
            return {
                success: true,
                data: records,
                timestamp: new Date().toISOString()
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString()
            };
        }
    }
    /**
     * Gets payroll records with optional filtering
     */
    getPayrollRecords(employeeId, payPeriod) {
        try {
            let records = this.payrollRecords;
            if (employeeId) {
                records = records.filter(r => r.employeeId === employeeId);
            }
            if (payPeriod) {
                records = records.filter(r => r.payPeriod === payPeriod);
            }
            return {
                success: true,
                data: records,
                timestamp: new Date().toISOString()
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString()
            };
        }
    }
    /**
     * Gets payroll summary for a specific period
     */
    getPayrollSummary(payPeriod) {
        try {
            const targetPeriod = payPeriod || new Date().toISOString().split('T')[0];
            const employees = Array.from(this.employees.values()).filter(e => e.isActive);
            const summary = (0, payrollCalculator_js_1.calculatePayrollSummary)(employees, targetPeriod);
            return {
                success: true,
                data: summary,
                timestamp: new Date().toISOString()
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error occurred',
                timestamp: new Date().toISOString()
            };
        }
    }
    /**
     * Syncs payroll data (placeholder for future integration)
     */
    async syncPayrollData() {
        // Placeholder implementation
        return {
            success: true,
            data: {
                success: true,
                syncedEmployees: this.employees.size,
                newRecords: 0,
                errors: [],
                duration: 0
            },
            timestamp: new Date().toISOString()
        };
    }
    generateEmployeeId() {
        let id;
        do {
            id = `EMP${Date.now().toString(36).toUpperCase()}`;
        } while (this.employees.has(id));
        return id;
    }
    generatePayrollRecordId() {
        return `PR${Date.now()}${Math.random().toString(36).substring(2, 7).toUpperCase()}`;
    }
}
exports.PayrollSystem = PayrollSystem;
// Export singleton instance
exports.payrollSystem = new PayrollSystem();
//# sourceMappingURL=payrollSystem.js.map