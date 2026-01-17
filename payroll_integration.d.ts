export interface PayrollData {
  employeeId: string;
  salary: number;
  taxRate: number;
  deductions: number;
  bonuses: number;
  date: string;
  amount?: number;
}

export interface Employee {
  id: string;
  accountNumber?: string;
  routingNumber?: string;
  name?: string;
  department?: string;
  [key: string]: any;
}

export interface PayrollResponse {
  success: boolean;
  message: string;
  data?: PayrollData | any;
}

export interface TransactionStatus {
  success: boolean;
  status: string;
  message?: string;
}

export interface ReconciliationResult {
  success: boolean;
  reconciledCount: number;
  message?: string;
}

export declare class PayrollIntegration {
  constructor(baseUrl: string, accessToken: string);
  getAuthHeaders(): { Authorization: string; 'Content-Type': string };
  retryRequest<T>(
    fn: () => Promise<T>,
    retries?: number,
    delayMs?: number
  ): Promise<T>;
  addOrUpdateEmployeePayroll(employee: Employee): Promise<PayrollResponse>;
  getEmployeePayroll(employeeId: string): Promise<PayrollResponse>;
  validateDirectDeposit(employee: Employee): Promise<PayrollResponse>;
  getTransactionStatus(transactionId: string): Promise<TransactionStatus>;
  reconcileTransactions(): Promise<ReconciliationResult>;
  simulateBankValidation(
    accountNumber: string,
    routingNumber: string
  ): Promise<boolean>;
}

export default PayrollIntegration;
