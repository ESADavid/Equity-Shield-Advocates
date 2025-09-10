export interface PayrollResponse {
  success: boolean;
  message: string;
  data?: any;
}

export interface Employee {
  id: string;
  name?: string;
  department?: string;
  accountNumber?: string;
  routingNumber?: string;
  [key: string]: any;
}

export declare class QuickBooksPayrollIntegration {
  constructor(
    baseUrl: string,
    accessToken: string,
    companyId: string,
    clientId: string,
    clientSecret: string,
    refreshToken: string
  );
  getAuthHeaders(): { Authorization: string; 'Content-Type': string; Accept: string };
  retryRequest<T>(fn: () => Promise<T>, retries?: number, delayMs?: number): Promise<T>;
  refreshAccessToken(): Promise<void>;
  addOrUpdateEmployeePayroll(employee: Employee): Promise<PayrollResponse>;
  getEmployeePayroll(employeeId: string): Promise<PayrollResponse>;
  getAllEmployees(): Promise<PayrollResponse>;
  createPayrollRun(employeeIds: string[]): Promise<PayrollResponse>;
}

export default QuickBooksPayrollIntegration;
