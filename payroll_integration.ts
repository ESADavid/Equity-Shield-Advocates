
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
}

export default PayrollIntegration;

