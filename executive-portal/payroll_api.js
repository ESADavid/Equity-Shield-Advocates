import { info, error, warn, debug } from '../utils/loggerWrapper.js';

// Payroll API for Executive Dashboard
// Simple mock API to provide employee data for payroll calculations

const express = require('express');
const router = express.Router();

// Mock employee data
const employees = [
    {
        id: 'emp001',
        name: 'John Smith',
        position: 'Software Engineer',
        hourlyRate: 45.00,
        department: 'Engineering'
    },
    {
        id: 'emp002',
        name: 'Sarah Johnson',
        position: 'Project Manager',
        hourlyRate: 55.00,
        department: 'Management'
    },
    {
        id: 'emp003',
        name: 'Mike Davis',
        position: 'Financial Analyst',
        hourlyRate: 40.00,
        department: 'Finance'
    },
    {
        id: 'emp004',
        name: 'Emily Chen',
        position: 'Marketing Specialist',
        hourlyRate: 35.00,
        department: 'Marketing'
    },
    {
        id: 'emp005',
        name: 'David Wilson',
        position: 'Operations Manager',
        hourlyRate: 50.00,
        department: 'Operations'
    }
];

// GET /api/payroll/employees - Get all employees
router.get('/employees', (req, res) => {
    try {
        res.json(employees);
    } catch (error) {
        logger.error('Error fetching employees:', error);
        res.status(500).json({ error: 'Failed to fetch employee data' });
    }
});

// GET /api/payroll/employees/:id - Get specific employee
router.get('/employees/:id', (req, res) => {
    try {
        const employee = employees.find(emp => emp.id === req.params.id);
        if (!employee) {
            return res.status(404).json({ error: 'Employee not found' });
        }
        res.json(employee);
    } catch (error) {
        logger.error('Error fetching employee:', error);
        res.status(500).json({ error: 'Failed to fetch employee data' });
    }
});

// POST /api/payroll/calculate - Calculate payroll (for future use)
router.post('/calculate', (req, res) => {
    try {
        const { employeeId, hoursWorked, overtimeHours, taxRate, deductions, bonuses } = req.body;

        const employee = employees.find(emp => emp.id === employeeId);
        if (!employee) {
            return res.status(404).json({ error: 'Employee not found' });
        }

        // Calculate payroll
        const regularPay = hoursWorked * employee.hourlyRate;
        const overtimePay = overtimeHours * employee.hourlyRate * 1.5;
        const grossPay = regularPay + overtimePay + bonuses;
        const taxAmount = grossPay * (taxRate / 100);
        const netPay = grossPay - taxAmount - deductions;

        const calculation = {
            employeeId,
            employeeName: employee.name,
            hoursWorked: parseFloat(hoursWorked),
            overtimeHours: parseFloat(overtimeHours),
            hourlyRate: employee.hourlyRate,
            regularPay,
            overtimePay,
            bonuses: parseFloat(bonuses),
            grossPay,
            taxRate: parseFloat(taxRate),
            taxAmount,
            deductions: parseFloat(deductions),
            netPay,
            calculatedAt: new Date().toISOString()
        };

        res.json(calculation);
    } catch (error) {
        logger.error('Error calculating payroll:', error);
        res.status(500).json({ error: 'Failed to calculate payroll' });
    }
});

module.exports = router;
