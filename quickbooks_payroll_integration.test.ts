import QuickBooksPayrollIntegration from './quickbooks_payroll_integration';

describe('QuickBooksPayrollIntegration', () => {
  let integration: QuickBooksPayrollIntegration;

  beforeEach(() => {
    integration = new QuickBooksPayrollIntegration(
      'https://quickbooks.api.intuit.com',
      'test-access-token',
      'test-company-id',
      'test-client-id',
      'test-client-secret',
      'test-refresh-token'
    );
  });

  describe('constructor', () => {
    it('should initialize with provided parameters', () => {
      expect(integration).toBeDefined();
    });
  });

  describe('getAuthHeaders', () => {
    it('should return correct authorization headers', () => {
      const headers = (integration as any).getAuthHeaders();
      expect(headers.Authorization).toBe('Bearer test-access-token');
      expect(headers['Content-Type']).toBe('application/json');
      expect(headers.Accept).toBe('application/json');
    });
  });

  describe('addOrUpdateEmployeePayroll', () => {
    it('should validate bank account info', async () => {
      const employee = {
        id: '1',
        name: 'John Doe',
        salary: 50000,
        taxRate: 0.2,
        // Missing accountNumber and routingNumber
      };

      const result = await integration.addOrUpdateEmployeePayroll(employee);
      expect(result.success).toBe(false);
      expect(result.message).toContain('Missing bank account');
    });

    it('should handle API errors gracefully', async () => {
      const employee = {
        id: '1',
        name: 'John Doe',
        salary: 50000,
        taxRate: 0.2,
        accountNumber: '123456789',
        routingNumber: '123456789',
      };

      // Mock axios to throw error
      const mockAxios = require('axios');
      mockAxios.post = jest.fn().mockRejectedValue(new Error('API Error'));

      const result = await integration.addOrUpdateEmployeePayroll(employee);
      expect(result.success).toBe(false);
      expect(result.message).toContain('Failed to update payroll data');
    });
  });

  describe('getEmployeePayroll', () => {
    it('should fetch employee payroll data', async () => {
      // Mock successful API response
      const mockAxios = require('axios');
      mockAxios.get = jest.fn().mockResolvedValue({
        data: {
          Employee: {
            Id: '1',
            Name: 'John Doe',
            Compensation: {
              HourlyRate: 25,
            },
          },
        },
      });

      const result = await integration.getEmployeePayroll('1');
      expect(result.success).toBe(true);
      expect(result.data.employeeId).toBe('1');
      expect(result.data.name).toBe('John Doe');
    });

    it('should handle API errors', async () => {
      const mockAxios = require('axios');
      mockAxios.get = jest.fn().mockRejectedValue(new Error('API Error'));

      const result = await integration.getEmployeePayroll('1');
      expect(result.success).toBe(false);
      expect(result.message).toContain('Failed to fetch payroll data');
    });
  });

  describe('getAllEmployees', () => {
    it('should fetch all employees', async () => {
      const mockAxios = require('axios');
      mockAxios.get = jest.fn().mockResolvedValue({
        data: {
          QueryResponse: {
            Employee: [
              { Id: '1', Name: 'John Doe' },
              { Id: '2', Name: 'Jane Smith' },
            ],
          },
        },
      });

      const result = await integration.getAllEmployees();
      expect(result.success).toBe(true);
      expect(result.data).toHaveLength(2);
    });
  });

  describe('createPayrollRun', () => {
    it('should create a payroll run', async () => {
      const mockAxios = require('axios');
      mockAxios.post = jest.fn().mockResolvedValue({
        data: { Id: 'run-1', Status: 'Created' },
      });

      const result = await integration.createPayrollRun(['1', '2']);
      expect(result.success).toBe(true);
      expect(result.message).toContain('Payroll run created');
    });
  });
});
