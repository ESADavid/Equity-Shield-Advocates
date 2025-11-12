"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const quickbooks_payroll_integration_1 = __importDefault(require("./quickbooks_payroll_integration"));
const dummyConfig = {
    baseUrl: 'https://quickbooks.api.intuit.com',
    accessToken: 'dummy-access-token',
    companyId: 'dummy-company-id',
    clientId: 'dummy-client-id',
    clientSecret: 'dummy-client-secret',
    refreshToken: 'dummy-refresh-token',
};
describe('QuickBooksPayrollIntegration', () => {
    let integration;
    beforeEach(() => {
        integration = new quickbooks_payroll_integration_1.default(dummyConfig.baseUrl, dummyConfig.accessToken, dummyConfig.companyId, dummyConfig.clientId, dummyConfig.clientSecret, dummyConfig.refreshToken);
    });
    test('should refresh access token on 401 error and retry request', async () => {
        // Mock axios post for token refresh and get for employee payroll
        const axios = require('axios');
        jest.spyOn(axios, 'post').mockImplementationOnce(() => Promise.resolve({
            data: {
                access_token: 'new-access-token',
                refresh_token: 'new-refresh-token',
            },
        }));
        jest.spyOn(axios, 'get').mockImplementationOnce(() => Promise.reject(new Error('401 Unauthorized')));
        jest.spyOn(axios, 'get').mockImplementationOnce(() => Promise.resolve({
            data: {
                Employee: {
                    Id: '123',
                    Name: 'John Doe',
                    Compensation: { HourlyRate: 50 },
                },
            },
        }));
        const response = await integration.getEmployeePayroll('123');
        expect(response.success).toBe(true);
        expect(response.data.employeeId).toBe('123');
    });
    test('should add or update employee payroll', async () => {
        const axios = require('axios');
        jest.spyOn(axios, 'post').mockResolvedValue({
            data: { success: true },
        });
        const employee = {
            id: '123',
            name: 'John Doe',
            salary: 50000,
            taxRate: 0.2,
            accountNumber: '123456789',
            routingNumber: '987654321',
        };
        const response = await integration.addOrUpdateEmployeePayroll(employee);
        expect(response.success).toBe(true);
    });
    test('should fail to add or update employee payroll if bank info missing', async () => {
        const employee = {
            id: '123',
            name: 'John Doe',
            salary: 50000,
            taxRate: 0.2,
        };
        const response = await integration.addOrUpdateEmployeePayroll(employee);
        expect(response.success).toBe(false);
        expect(response.message).toMatch(/Missing bank account/);
    });
    test('should get all employees', async () => {
        const axios = require('axios');
        jest.spyOn(axios, 'get').mockResolvedValue({
            data: {
                QueryResponse: {
                    Employee: [{ Id: '123', Name: 'John Doe' }],
                },
            },
        });
        const response = await integration.getAllEmployees();
        expect(response.success).toBe(true);
        expect(response.data.length).toBeGreaterThan(0);
    });
    test('should create payroll run', async () => {
        const axios = require('axios');
        jest.spyOn(axios, 'post').mockResolvedValue({
            data: { success: true },
        });
        const response = await integration.createPayrollRun(['123', '456']);
        expect(response.success).toBe(true);
    });
});
//# sourceMappingURL=quickbooks_payroll_integration.test.js.map