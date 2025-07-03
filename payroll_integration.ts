

import axios from 'axios';

interface PayrollEmployee {
  id: string;
  name: string;
  salary: number;
  taxRate: number;
  accountNumber?: string;
  routingNumber?: string;
  benefits?: any;
  deductions?: any;
  bonuses?: number;
}

export interface PayrollResponse {
  success: boolean;
  message: string;
  data?: any;
}

class PayrollIntegration {
  private dynamicsBaseUrl: string;
  private accessToken: string;

  constructor(baseUrl: string, accessToken: string) {
    this.dynamicsBaseUrl = baseUrl;
    this.accessToken = accessToken;
  }

  private getAuthHeaders() {
    return {
      Authorization: `Bearer ${this.accessToken}`,
      'Content-Type': 'application/json',
    };
  }

  private async retryRequest<T>(fn: () => Promise<T>, retries = 3, delayMs = 1000): Promise<T> {
    let lastError: any;
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error;
        console.warn(`Attempt ${attempt} failed: ${error}. Retrying in ${delayMs}ms...`);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
    throw lastError;
  }

  async addOrUpdateEmployeePayroll(employee: PayrollEmployee): Promise<PayrollResponse> {
    try {
      // Validate bank account info for direct deposit
      if (!employee.accountNumber || !employee.routingNumber) {
        const message = 'Missing bank account or routing number for direct deposit';
        console.error(message);
        return { success: false, message };
      }

      // Validate direct deposit details before update
      const validationResponse = await this.validateDirectDeposit(employee);
      if (!validationResponse.success) {
        return validationResponse;
      }

      // API call to Microsoft Dynamics 365 Payroll endpoint with retry
      const url = `${this.dynamicsBaseUrl}/payroll/employees/${employee.id}`;
      const response = await this.retryRequest(() =>
        axios.put(url, employee, {
          headers: this.getAuthHeaders(),
        })
      );
      return { success: true, message: 'Payroll data updated', data: response.data };
    } catch (error) {
      // Improved error handling with detailed logging
      console.error('Error updating payroll data:', error);
      return { success: false, message: 'Failed to update payroll data', data: error };
    }
  }

  async getEmployeePayroll(employeeId: string): Promise<PayrollResponse> {
    try {
      const url = `${this.dynamicsBaseUrl}/payroll/employees/${employeeId}`;
      const response = await this.retryRequest(() =>
        axios.get(url, {
          headers: this.getAuthHeaders(),
        })
      );
      return { success: true, message: 'Payroll data fetched', data: response.data };
    } catch (error) {
      console.error('Error fetching payroll data:', error);
      return { success: false, message: 'Failed to fetch payroll data', data: error };
    }
  }

  // New method: Validate direct deposit details with banking API
  async validateDirectDeposit(employee: PayrollEmployee): Promise<PayrollResponse> {
    try {
      if (!employee.accountNumber || !employee.routingNumber) {
        const message = 'Missing bank account or routing number for validation';
        console.error(message);
        return { success: false, message };
      }
      // Simulate banking API validation call
      const isValid = await this.simulateBankValidation(employee.accountNumber, employee.routingNumber);
      if (!isValid) {
        return { success: false, message: 'Invalid bank account or routing number' };
      }
      return { success: true, message: 'Direct deposit details validated' };
    } catch (error) {
      console.error('Error validating direct deposit:', error);
      return { success: false, message: 'Failed to validate direct deposit', data: error };
    }
  }

  // New method: Check transaction status from banking API (simulated)
  async getTransactionStatus(transactionId: string): Promise<{ success: boolean; status: string; message?: string }> {
    try {
      // Simulate async call to banking API for transaction status
      await new Promise((resolve) => setTimeout(resolve, 500));
      // For demo, randomly assign status
      const statuses = ['pending', 'completed', 'failed'];
      const status = statuses[Math.floor(Math.random() * statuses.length)];
      return { success: true, status };
    } catch (error) {
      console.error('Error fetching transaction status:', error);
      return { success: false, status: 'unknown', message: 'Failed to fetch transaction status' };
    }
  }

  // New method: Reconcile transactions (simulated)
  async reconcileTransactions(): Promise<{ success: boolean; reconciledCount: number; message?: string }> {
    try {
      // Simulate reconciliation process
      await new Promise((resolve) => setTimeout(resolve, 1000));
      // For demo, assume 10 transactions reconciled
      return { success: true, reconciledCount: 10 };
    } catch (error) {
      console.error('Error during reconciliation:', error);
      return { success: false, reconciledCount: 0, message: 'Failed to reconcile transactions' };
    }
  }

  private async simulateBankValidation(accountNumber: string, routingNumber: string): Promise<boolean> {
    // Simulate async validation logic, e.g., call to external banking API
    await new Promise((resolve) => setTimeout(resolve, 500));
    // For demo, assume all account numbers starting with '0' are invalid
    if (accountNumber.startsWith('0')) {
      return false;
    }
    return true;
  }
}

export default PayrollIntegration;

