"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const supertest_1 = __importDefault(require("supertest"));
const express_1 = __importDefault(require("express"));
const payroll_api_1 = __importDefault(require("./payroll_api"));
const fetch_and_sync_payroll_1 = __importDefault(require("./fetch_and_sync_payroll"));
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
jest.mock('./fetch_and_sync_payroll');
jest.mock('fs');
const app = (0, express_1.default)();
app.use(express_1.default.json());
app.use('/api/payroll', payroll_api_1.default);
const revenueDataPath = node_path_1.default.resolve(__dirname, '../owlban_repos/sample_repo/revenue.json');
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
            jest.spyOn(node_fs_1.default, 'readFileSync').mockReturnValue(JSON.stringify(mockRevenueData));
            const res = await (0, supertest_1.default)(app).get('/api/payroll/employees');
            expect(res).toHaveProperty('status', 200);
            expect(res.body).toEqual(mockPayrollData);
            expect(node_fs_1.default.readFileSync).toHaveBeenCalledWith(revenueDataPath, 'utf-8');
        });
        it('should return 500 if reading payroll data fails', async () => {
            jest.spyOn(node_fs_1.default, 'readFileSync').mockImplementation(() => {
                throw new Error('File read error');
            });
            const res = await (0, supertest_1.default)(app).get('/api/payroll/employees');
            expect(res).toHaveProperty('status', 500);
            expect(res.body).toHaveProperty('error');
        });
    });
    describe('POST /api/payroll/sync', () => {
        it('should trigger payroll sync and return success', async () => {
            fetch_and_sync_payroll_1.default.mockResolvedValue(undefined);
            const res = await (0, supertest_1.default)(app).post('/api/payroll/sync');
            expect(res).toHaveProperty('status', 200);
            expect(res.body).toEqual({ success: true, message: 'Payroll data sync completed' });
            expect(fetch_and_sync_payroll_1.default).toHaveBeenCalled();
        });
        it('should return 500 if payroll sync fails', async () => {
            fetch_and_sync_payroll_1.default.mockRejectedValue(new Error('Sync error'));
            const res = await (0, supertest_1.default)(app).post('/api/payroll/sync');
            expect(res).toHaveProperty('status', 500);
            expect(res.body).toEqual({ success: false, message: 'Payroll data sync failed' });
            expect(fetch_and_sync_payroll_1.default).toHaveBeenCalled();
        });
    });
});
//# sourceMappingURL=fetch_and_sync_payroll.test.js.map