import axios from 'axios';
class QuickBooksPayrollIntegration {
    constructor(baseUrl, accessToken, companyId, clientId, clientSecret, refreshToken) {
        this.baseUrl = baseUrl;
        this.accessToken = accessToken;
        this.companyId = companyId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.refreshToken = refreshToken;
    }
    getAuthHeaders() {
        return {
            Authorization: `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json',
            Accept: 'application/json',
        };
    }
    async refreshAccessToken() {
        try {
            const response = await axios.post('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', null, {
                params: {
                    grant_type: 'refresh_token',
                    refresh_token: this.refreshToken,
                },
                auth: {
                    username: this.clientId,
                    password: this.clientSecret,
                },
            });
            this.accessToken = response.data.access_token;
            this.refreshToken = response.data.refresh_token || this.refreshToken;
            console.log('QuickBooks access token refreshed');
        }
        catch (error) {
            console.error('Failed to refresh QuickBooks access token:', error);
            throw error;
        }
    }
    async retryRequest(fn, retries = 3, delayMs = 1000) {
        let lastError;
        for (let attempt = 1; attempt <= retries; attempt++) {
            try {
                return await fn();
            }
            catch (error) {
                lastError = error;
                if (error.response?.status === 401) {
                    try {
                        await this.refreshAccessToken();
                        continue;
                    }
                    catch (refreshError) {
                        console.error('Failed to refresh token:', refreshError);
                    }
                }
                console.warn(`Attempt ${attempt} failed: ${error}. Retrying in ${delayMs}ms...`);
                await new Promise((resolve) => setTimeout(resolve, delayMs));
            }
        }
        throw lastError;
    }
    async addOrUpdateEmployeePayroll(employee) {
        try {
            if (!employee.accountNumber || !employee.routingNumber) {
                const message = 'Missing bank account or routing number for direct deposit';
                console.error(message);
                return { success: false, message };
            }
            const url = `${this.baseUrl}/company/${this.companyId}/employee`;
            const employeeData = {
                Id: employee.id,
                Name: employee.name,
                PrimaryAddr: {
                    Line1: 'Employee Address',
                },
                PrimaryEmailAddr: {
                    Address: 'employee@example.com',
                },
                EmployeeNumber: employee.id,
                HiredDate: new Date().toISOString().split('T')[0],
            };
            const response = await this.retryRequest(() => axios.post(url, employeeData, {
                headers: this.getAuthHeaders(),
            }));
            return {
                success: true,
                message: 'Employee payroll data updated',
                data: response.data,
            };
        }
        catch (error) {
            console.error('Error updating QuickBooks payroll data:', error);
            return {
                success: false,
                message: 'Failed to update payroll data',
                data: error,
            };
        }
    }
    async getEmployeePayroll(employeeId) {
        try {
            const url = `${this.baseUrl}/company/${this.companyId}/employee/${employeeId}`;
            const response = await this.retryRequest(() => axios.get(url, {
                headers: this.getAuthHeaders(),
            }));
            const employee = response.data.Employee;
            const payrollData = {
                employeeId: employee.Id,
                name: employee.Name,
                salary: employee.Compensation?.HourlyRate || 0,
                taxRate: 0.2,
                date: new Date().toISOString().split('T')[0],
                amount: (employee.Compensation?.HourlyRate || 0) * 40,
            };
            return {
                success: true,
                message: 'Payroll data fetched',
                data: payrollData,
            };
        }
        catch (error) {
            console.error('Error fetching QuickBooks payroll data:', error);
            return {
                success: false,
                message: 'Failed to fetch payroll data',
                data: error,
            };
        }
    }
    async getAllEmployees() {
        try {
            const url = `${this.baseUrl}/company/${this.companyId}/employees`;
            const response = await this.retryRequest(() => axios.get(url, {
                headers: this.getAuthHeaders(),
            }));
            return {
                success: true,
                message: 'Employees fetched',
                data: response.data.QueryResponse.Employee,
            };
        }
        catch (error) {
            console.error('Error fetching QuickBooks employees:', error);
            return {
                success: false,
                message: 'Failed to fetch employees',
                data: error,
            };
        }
    }
    async createPayrollRun(employeeIds) {
        try {
            const url = `${this.baseUrl}/company/${this.companyId}/payrollrun`;
            const payrollRunData = {
                StartDate: new Date().toISOString().split('T')[0],
                EndDate: new Date().toISOString().split('T')[0],
                EmployeeIds: employeeIds,
            };
            const response = await this.retryRequest(() => axios.post(url, payrollRunData, {
                headers: this.getAuthHeaders(),
            }));
            return {
                success: true,
                message: 'Payroll run created',
                data: response.data,
            };
        }
        catch (error) {
            console.error('Error creating QuickBooks payroll run:', error);
            return {
                success: false,
                message: 'Failed to create payroll run',
                data: error,
            };
        }
    }
}
export default QuickBooksPayrollIntegration;
