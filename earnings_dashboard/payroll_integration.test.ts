const PayrollIntegration = require('../payroll_integration').default;

describe('PayrollIntegration', () => {
  const baseUrl = 'https://fakeapi.example.com';
  const accessToken = 'fake-token';
  const payroll = new PayrollIntegration(baseUrl, accessToken);

  it('should create a PayrollEmployee object with accountNumber and routingNumber', () => {
    const employee = {
      id: '123',
      name: 'John Doe',
      salary: 50000,
      taxRate: 0.2,
      accountNumber: '111222333',
      routingNumber: '444555666',
      benefits: {}
    };
    expect(employee.accountNumber).toBe('111222333');
    expect(employee.routingNumber).toBe('444555666');
  });

  it('should call addOrUpdateEmployeePayroll and return success', async () => {
    // Mock axios.put to simulate API call
    const mockResponse = { data: { updated: true } };
    payroll['axios'] = { put: jest.fn().mockResolvedValue(mockResponse) };

    const employee = {
      id: '123',
      name: 'John Doe',
      salary: 50000,
      taxRate: 0.2,
      accountNumber: '111222333',
      routingNumber: '444555666',
      benefits: {}
    };

    // Override axios.put temporarily
    const originalPut = payroll['axios']?.put;
    payroll['axios'] = { put: jest.fn().mockResolvedValue(mockResponse) };

    const response = await payroll.addOrUpdateEmployeePayroll(employee);
    expect(response.success).toBe(true);
    expect(response.message).toBe('Payroll data updated');

    // Restore original axios.put
    if (originalPut) {
      payroll['axios'].put = originalPut;
    }
  });

  it('should call getEmployeePayroll and return success', async () => {
    // Mock axios.get to simulate API call
    const mockResponse = { data: { id: '123', name: 'John Doe' } };
    payroll['axios'] = { get: jest.fn().mockResolvedValue(mockResponse) };

    // Override axios.get temporarily
    const originalGet = payroll['axios']?.get;
    payroll['axios'] = { get: jest.fn().mockResolvedValue(mockResponse) };

    const response = await payroll.getEmployeePayroll('123');
    expect(response.success).toBe(true);
    expect(response.message).toBe('Payroll data fetched');

    // Restore original axios.get
    if (originalGet) {
      payroll['axios'].get = originalGet;
    }
  });
});
