import fs from 'fs';
import path from 'path';

const revenueDataPath = path.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');

describe('update_revenue_data', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  it('should update revenue.json with detailed purchase data', () => {
    const originalData = {
      totalRevenue: 1000000,
      purchases: {
        corporateHomes: 100000,
        autoFleet: 0
      }
    };

    jest.spyOn(fs, 'existsSync').mockReturnValue(true);
    jest.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify(originalData));
    const writeFileSyncMock = jest.spyOn(fs, 'writeFileSync').mockImplementation(() => {});

    // Import and run the update script
    const updateRevenueData = require('./update_revenue_data').default || require('./update_revenue_data');
    updateRevenueData();

    expect(writeFileSyncMock).toHaveBeenCalled();

    const updatedData = JSON.parse(writeFileSyncMock.mock.calls[0][1].toString());
    expect(updatedData.purchases.autoFleetDetails).toBeDefined();
    expect(Array.isArray(updatedData.purchases.autoFleetDetails)).toBe(true);
    expect(updatedData.purchases.autoFleetDetails.length).toBeGreaterThan(0);

    writeFileSyncMock.mockRestore();
  });
});
