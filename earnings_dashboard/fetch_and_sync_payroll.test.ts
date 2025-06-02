import fs from 'fs';
import path from 'path';
import { jest } from '@jest/globals';
import PayrollIntegration from '../payroll_integration';

jest.mock('../payroll_integration');
jest.mock('fs');

const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');

describe('fetch_and_sync_payroll', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('should exit if environment variables are missing', async () => {
    process.env.DYNAMICS365_BASE_URL = '';
    process.env.DYNAMICS365_ACCESS_TOKEN = '';
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const processExitSpy = jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('process.exit'); });

    try {
      const fetchAndSyncPayroll = require('./fetch_and_sync_payroll').default;
      await fetchAndSyncPayroll();
    } catch (error: any) {
      expect(error.message).toBe('process.exit');
    }

    expect(consoleErrorSpy).toHaveBeenCalledWith('Dynamics365 base URL or access token is not set in environment variables.');
    expect(processExitSpy).toHaveBeenCalledWith(1);

    consoleErrorSpy.mockRestore();
    processExitSpy.mockRestore();
  });

  it('should update revenue data with payroll information', async () => {
    process.env.DYNAMICS365_BASE_URL = 'https://fakeurl.com';
    process.env.DYNAMICS365_ACCESS_TOKEN = 'fake-token';

    const mockRevenueData = {
      totalRevenue: 1000000,
      purchases: {
        corporateHomes: 0,
        autoFleet: 0
      }
    };

    (fs.existsSync as jest.Mock).mockReturnValue(true);
    (fs.readFileSync as jest.Mock).mockReturnValue(JSON.stringify(mockRevenueData));
    const writeFileSyncMock = jest.spyOn(fs, 'writeFileSync').mockImplementation(() => {});

    const mockGetEmployeePayroll = jest.fn().mockResolvedValue({
      success: true,
      data: { salary: 50000 }
    } as any);
    (PayrollIntegration as jest.Mock).mockImplementation(() => ({
      getEmployeePayroll: mockGetEmployeePayroll
    }));

    const fetchAndSyncPayroll = require('./fetch_and_sync_payroll').default;
    await fetchAndSyncPayroll();

    expect(mockGetEmployeePayroll).toHaveBeenCalled();
    expect(writeFileSyncMock).toHaveBeenCalled();

    writeFileSyncMock.mockRestore();
  });
});
