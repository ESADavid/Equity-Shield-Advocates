const request = require('supertest');
const express = require('express');
const payrollApiRouter = require('./payroll_api.js');
const fetchAndSyncPayroll = require('./fetch_and_sync_payroll').default;
const fs = require('fs');
const path = require('path');

jest.mock('./fetch_and_sync_payroll');
jest.mock('fs');

const app = express();
app.use(express.json());
app.use('/api/payroll', payrollApiRouter);

const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');

describe('Payroll API', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  describe('GET /api/payroll/employees', () => {
    it('should return payroll data from revenue file', async () => {
      const mockPayrollData = [
        { employeeId: '1', amount: 1000, date: '2024-01-01', source: 'quickbooks' },
        { employeeId: '2', amount: 2000, date: '2024-01-01', source: 'dynamics365' },
      ];
      const mockRevenueData = { payroll: mockPayrollData };
      jest.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify(mockRevenueData));

      const res = await request(app).get('/api/payroll/employees');

      expect(res).toHaveProperty('status', 200);
      expect(res.body).toEqual(mockPayrollData);
      expect(fs.readFileSync).toHaveBeenCalledWith(revenueDataPath, 'utf-8');
    });

    it('should return 500 if reading payroll data fails', async () => {
      jest.spyOn(fs, 'readFileSync').mockImplementation(() => {
        throw new Error('File read error');
      });

      const res = await request(app).get('/api/payroll/employees');

      expect(res).toHaveProperty('status', 500);
      expect(res.body).toHaveProperty('error');
    });
  });

  describe('POST /api/payroll/sync', () => {
    it('should trigger payroll sync and return success', async () => {
      fetchAndSyncPayroll.mockResolvedValue(undefined);

      const res = await request(app).post('/api/payroll/sync');

      expect(res).toHaveProperty('status', 200);
      expect(res.body).toEqual({ success: true, message: 'Payroll data sync completed' });
      expect(fetchAndSyncPayroll).toHaveBeenCalled();
    });

    it('should return 500 if payroll sync fails', async () => {
      fetchAndSyncPayroll.mockRejectedValue(new Error('Sync error'));

      const res = await request(app).post('/api/payroll/sync');

      expect(res).toHaveProperty('status', 500);
      expect(res.body).toEqual({ success: false, message: 'Payroll data sync failed' });
      expect(fetchAndSyncPayroll).toHaveBeenCalled();
    });
  });
});
