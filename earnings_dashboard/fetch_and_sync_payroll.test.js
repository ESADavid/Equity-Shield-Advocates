"use strict";
const __importDefault = function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const globals_1 = require("@jest/globals");
const fetch_and_sync_payroll_1 = __importDefault(require("./fetch_and_sync_payroll"));
globals_1.jest.mock('fs');
const revenueDataPath = path_1.default.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');
describe('fetch_and_sync_payroll', () => {
    beforeEach(() => {
        globals_1.jest.resetAllMocks();
    });
    it('should exit if environment variables are missing', async () => {
        process.env.DYNAMICS365_BASE_URL = '';
        process.env.DYNAMICS365_ACCESS_TOKEN = '';
        const consoleErrorSpy = globals_1.jest.spyOn(console, 'error').mockImplementation(() => { });
        const processExitSpy = globals_1.jest.spyOn(process, 'exit').mockImplementation(() => { throw new Error('process.exit'); });
        try {
            await (0, fetch_and_sync_payroll_1.default)();
        }
        catch (error) {
            // Fix for "Object is of type 'unknown'" error by type guard
            if (error instanceof Error) {
                expect(error.message).toBe('process.exit');
            }
            else {
                throw new Error(String(error));
            }
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
        const mockEmployeeIds = ['emp001', 'emp002'];
        const consoleErrorSpy = globals_1.jest.spyOn(console, 'error').mockImplementation(() => { });
        const consoleLogSpy = globals_1.jest.spyOn(console, 'log').mockImplementation(() => { });
        globals_1.jest.spyOn(fs_1.default, 'existsSync').mockReturnValue(true);
        globals_1.jest.spyOn(fs_1.default, 'readFileSync').mockImplementation((filePath) => {
            if (filePath.includes('employee_ids.json')) {
                return JSON.stringify(mockEmployeeIds);
            }
            else if (filePath.includes('revenue.json')) {
                return JSON.stringify(mockRevenueData);
            }
            return '{}';
        });
        const writeFileSyncMock = globals_1.jest.spyOn(fs_1.default, 'writeFileSync').mockImplementation(() => { });
        // Import the actual PayrollIntegration class
        const ActualPayrollIntegration = globals_1.jest.requireActual('../payroll_integration').default;
        // Create a mocked instance of PayrollIntegration
        const mockGetEmployeePayroll = globals_1.jest.fn(async (employeeId) => {
            return {
                success: true,
                message: 'Payroll data fetched',
                data: { salary: 50000 }
            };
        });
        // Fix for "Argument of type 'PayrollResponse' is not assignable to parameter of type 'never'" error
        globals_1.jest.spyOn(ActualPayrollIntegration.prototype, 'getEmployeePayroll').mockImplementation(mockGetEmployeePayroll);
        await (0, fetch_and_sync_payroll_1.default)();
        expect(mockGetEmployeePayroll).toHaveBeenCalledTimes(mockEmployeeIds.length);
        expect(writeFileSyncMock).toHaveBeenCalled();
        writeFileSyncMock.mockRestore();
        consoleErrorSpy.mockRestore();
        consoleLogSpy.mockRestore();
    });
});
