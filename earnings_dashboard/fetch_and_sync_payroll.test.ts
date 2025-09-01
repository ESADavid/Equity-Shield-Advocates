import fs from 'fs';
import path from 'path';
import fetchAndSyncPayroll from './fetch_and_sync_payroll';
import QuickBooksPayrollIntegration from '../quickbooks_payroll_integration';
import PayrollIntegration from '../payroll_integration';

jest.mock('fs');
jest.mock('../quickbooks_payroll_integration');
jest.mock('../payroll_integration');
jest.mock('./fetch_employee_ids', () => ({
  fetchEmployeeIds: jest.fn().mockResolvedValue(['emp1', 'emp2']),
}));

describe('fetchAndSyncPayroll', () => {
  const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should fetch payroll data from Dynamics 365 and QuickBooks and update revenue data', async () => {
    // Mock reading existing revenue data
    (fs.readFileSync as jest.Mock).mockReturnValue(JSON.stringify({ payroll: [] }));

    // Mock Dynamics 365 integration
    const mockDynamicsGetEmployeePayroll = jest.fn()
      .mockResolvedValueOnce({ success: true, data: { salary: 1000, taxRate: 0.2, deductions: 50, bonuses: 100 } })
      .mockResolvedValueOnce({ success: true, data: { salary: 2000, taxRate: 0.25, deductions: 100, bonuses: 200 } });
    (PayrollIntegration as jest.Mock).mockImplementation(() => ({
      getEmployeePayroll: mockDynamicsGetEmployeePayroll,
    }));

    // Mock QuickBooks integration
    const mockQuickBooksGetEmployeePayroll = jest.fn()
      .mockResolvedValueOnce({ success: true, data: { amount: 1100, taxRate: 0.2, deductions: 55, bonuses: 110 } })
      .mockResolvedValueOnce({ success: true, data: { amount: 2100, taxRate: 0.25, deductions: 105, bonuses: 210 } });
    (QuickBooksPayrollIntegration as jest.Mock).mockImplementation(() => ({
      getEmployeePayroll: mockQuickBooksGetEmployeePayroll,
    }));

    // Mock writing to file
    (fs.writeFileSync as jest.Mock).mockImplementation(() => {});

    await fetchAndSyncPayroll();

    expect(fs.readFileSync).toHaveBeenCalledWith(revenueDataPath, 'utf-8');
    expect(mockDynamicsGetEmployeePayroll).toHaveBeenCalledTimes(2);
    expect(mockQuickBooksGetEmployeePayroll).toHaveBeenCalledTimes(2);
    expect(fs.writeFileSync).toHaveBeenCalled();

    const writtenData = JSON.parse((fs.writeFileSync as jest.Mock).mock.calls[0][1]);
    expect(writtenData.payroll.length).toBeGreaterThanOrEqual(2);
  });

  it('should handle missing revenue data file gracefully', async () => {
    (fs.readFileSync as jest.Mock).mockImplementation(() => { throw new Error('File not found'); });

    (PayrollIntegration as jest.Mock).mockImplementation(() => ({
      getEmployeePayroll: jest.fn().mockResolvedValue({ success: true, data: { salary: 1000, taxRate: 0.2 } }),
    }));

    (QuickBooksPayrollIntegration as jest.Mock).mockImplementation(() => ({
      getEmployeePayroll: jest.fn().mockResolvedValue({ success: true, data: { amount: 1100, taxRate: 0.2 } }),
    }));

    (fs.writeFileSync as jest.Mock).mockImplementation(() => {});

    await fetchAndSyncPayroll();

    expect(fs.writeFileSync).toHaveBeenCalled();
  });

  it('should skip updating revenue data if no new payroll data fetched', async () => {
    (fs.readFileSync as jest.Mock).mockReturnValue(JSON.stringify({ payroll: [{ employeeId: 'emp1', date: new Date().toISOString(), source: 'dynamics365' }] }));

    (PayrollIntegration as jest.Mock).mockImplementation(() => ({
      getEmployeePayroll: jest.fn().mockResolvedValue({ success: true, data: { salary: 1000, taxRate: 0.2 } }),
    }));

    (QuickBooksPayrollIntegration as jest.Mock).mockImplementation(() => ({
      getEmployeePayroll: jest.fn().mockResolvedValue({ success: true, data: { amount: 1100, taxRate: 0.2 } }),
    }));

    (fs.writeFileSync as jest.Mock).mockImplementation(() => {});

    const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    await fetchAndSyncPayroll();

    expect(consoleWarnSpy).toHaveBeenCalledWith('No new payroll data was fetched. Revenue data will not be updated.');
    expect(fs.writeFileSync).not.toHaveBeenCalled();

    consoleWarnSpy.mockRestore();
  });

  it('should handle errors during payroll fetch gracefully', async () => {
    (fs.readFileSync as jest.Mock).mockReturnValue(JSON.stringify({ payroll: [] }));

    (PayrollIntegration as jest.Mock).mockImplementation(() => ({
      getEmployeePayroll: jest.fn().mockRejectedValue(new Error('Dynamics API error')),
    }));

    (QuickBooksPayrollIntegration as jest.Mock).mockImplementation(() => ({
      getEmployeePayroll: jest.fn().mockRejectedValue(new Error('QuickBooks API error')),
    }));

    (fs.writeFileSync as jest.Mock).mockImplementation(() => {});

    const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    await fetchAndSyncPayroll();

    expect(consoleWarnSpy).toHaveBeenCalledTimes(2);
    expect(fs.writeFileSync).not.toHaveBeenCalled();

    consoleWarnSpy.mockRestore();
  });
});
