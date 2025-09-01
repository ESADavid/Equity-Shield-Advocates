# QuickBooks Payroll Integration

This document describes the QuickBooks payroll integration for the OSCAR-BROOME-REVENUE system.

## Overview

The QuickBooks payroll integration allows the system to fetch and sync payroll data from QuickBooks Online, providing an alternative or complementary payroll source to Microsoft Dynamics 365.

## Features

- OAuth 2.0 authentication with automatic token refresh
- Fetch employee payroll data
- Update employee payroll information
- Get all employees from QuickBooks
- Create payroll runs
- Retry logic for API calls
- Error handling and logging

## Setup

### Prerequisites

1. QuickBooks Online account with payroll enabled
2. QuickBooks Developer account
3. OAuth 2.0 application registered in QuickBooks Developer Console

### Environment Variables

Set the following environment variables:

```bash
QUICKBOOKS_BASE_URL=https://quickbooks.api.intuit.com
QUICKBOOKS_ACCESS_TOKEN=your_access_token
QUICKBOOKS_COMPANY_ID=your_company_id
QUICKBOOKS_CLIENT_ID=your_client_id
QUICKBOOKS_CLIENT_SECRET=your_client_secret
QUICKBOOKS_REFRESH_TOKEN=your_refresh_token
```

### Obtaining OAuth Credentials

1. Go to [QuickBooks Developer Console](https://developer.intuit.com/app/developer/qbo/docs/get-started)
2. Create a new app
3. Configure OAuth 2.0 settings
4. Get your Client ID and Client Secret
5. Implement OAuth flow to get access token and refresh token

## Usage

### Basic Usage

```typescript
import QuickBooksPayrollIntegration from './quickbooks_payroll_integration';

const integration = new QuickBooksPayrollIntegration(
  process.env.QUICKBOOKS_BASE_URL!,
  process.env.QUICKBOOKS_ACCESS_TOKEN!,
  process.env.QUICKBOOKS_COMPANY_ID!,
  process.env.QUICKBOOKS_CLIENT_ID!,
  process.env.QUICKBOOKS_CLIENT_SECRET!,
  process.env.QUICKBOOKS_REFRESH_TOKEN!
);

// Get employee payroll
const payroll = await integration.getEmployeePayroll('employee-id');

// Update employee payroll
const employee = {
  id: 'employee-id',
  name: 'John Doe',
  salary: 50000,
  taxRate: 0.2,
  accountNumber: '123456789',
  routingNumber: '123456789'
};
const result = await integration.addOrUpdateEmployeePayroll(employee);
```

### Integration with Sync Process

The QuickBooks integration is automatically included in the payroll sync process when environment variables are configured. The system will attempt to fetch payroll data from both Dynamics 365 and QuickBooks if both are configured.

## API Reference

### QuickBooksPayrollIntegration

#### Constructor

```typescript
new QuickBooksPayrollIntegration(
  baseUrl: string,
  accessToken: string,
  companyId: string,
  clientId: string,
  clientSecret: string,
  refreshToken: string
)
```

#### Methods

- `getEmployeePayroll(employeeId: string): Promise<QuickBooksPayrollResponse>`
- `addOrUpdateEmployeePayroll(employee: QuickBooksEmployee): Promise<QuickBooksPayrollResponse>`
- `getAllEmployees(): Promise<QuickBooksPayrollResponse>`
- `createPayrollRun(employeeIds: string[]): Promise<QuickBooksPayrollResponse>`

## Data Structures

### QuickBooksEmployee

```typescript
interface QuickBooksEmployee {
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
```

### QuickBooksPayrollResponse

```typescript
interface QuickBooksPayrollResponse {
  success: boolean;
  message: string;
  data?: any;
}
```

## Error Handling

The integration includes comprehensive error handling:

- Automatic token refresh on 401 errors
- Retry logic for transient failures
- Detailed error logging
- Graceful degradation when services are unavailable

## Testing

Run the tests using:

```bash
npm test quickbooks_payroll_integration.test.ts
```

## Security Considerations

- Store OAuth tokens securely
- Use HTTPS for all API communications
- Regularly rotate refresh tokens
- Implement proper access controls

## Troubleshooting

### Common Issues

1. **Invalid Token**: Ensure access token is valid and refresh token is working
2. **Company ID Mismatch**: Verify the company ID matches your QuickBooks company
3. **Rate Limiting**: QuickBooks has API rate limits; the integration includes retry logic
4. **Permissions**: Ensure your OAuth app has necessary permissions for payroll operations

### Logs

Check application logs for detailed error information and API call status.

## Support

For issues with QuickBooks integration:

1. Check QuickBooks Developer documentation
2. Verify OAuth setup
3. Review application logs
4. Test with QuickBooks sandbox environment first
