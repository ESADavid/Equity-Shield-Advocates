# Oscar Broome Transaction Override Capabilities

## Overview
This enhanced Oscar Broome Revenue System includes comprehensive transaction override capabilities, allowing authorized users to modify, approve, or reject transaction changes with full audit logging.

## Features

### Transaction Override System
- **Override Request Creation**: Submit override requests for any transaction
- **Approval Workflow**: Multi-level approval process with role-based access
- **Audit Trail**: Complete audit logging for all override operations
- **Real-time Monitoring**: Dashboard for managing override requests
- **Security**: Enhanced authentication and authorization

### User Roles
- **Admin**: Full override capabilities and system management
- **Override Manager**: Create and manage override requests
- **Super Admin**: Complete system access and override approval

### API Endpoints

#### Transaction Override Endpoints
- `GET /api/transactions/overrides` - List all override requests
- `POST /api/transactions/override` - Create new override request
- `PUT /api/transactions/:id/override` - Update transaction with override
- `DELETE /api/transactions/:id/override` - Reject override request
- `GET /api/transactions/:id/audit` - Get transaction audit trail

#### System Endpoints
- `GET /api/earnings` - Get earnings data
- `GET /health` - System health check
- `GET /override-dashboard` - Override management dashboard

## Installation

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Environment Configuration**
   Create `.env` file:
   ```
   PORT=4000
   ADMIN_USER=admin
   ADMIN_PASS=securepassword
   OVERRIDE_MANAGER_USER=override_manager
   OVERRIDE_MANAGER_PASS=override123
   CORS_ORIGIN=http://localhost:3000
   REVENUE_DATA_PATH=./owlban_repos/aggregated_revenue.json
   ```

3. **Start the Server**
   ```bash
   npm start
   # or for development
   npm run dev
   ```

## Usage

### Accessing the Override Dashboard
1. Navigate to `http://localhost:4000/override-dashboard`
2. Login with credentials:
   - Username: `admin`
   - Password: `securepassword`

### Creating Override Requests
1. Fill in the override form with:
   - Transaction ID
   - Transaction type
   - Override type (amount, status, date, delete)
   - New value
   - Reason for override

### Managing Override Requests
1. View all override requests in the dashboard
2. Approve or reject requests based on role permissions
3. View complete audit trail for any transaction

## Security Features
- **Role-based Access Control**: Different permissions for different roles
- **Comprehensive Audit Logging**: All actions logged with user, timestamp, and details
- **Authentication**: Basic auth with configurable credentials
- **Input Validation**: All inputs validated before processing
- **Error Handling**: Comprehensive error handling and logging

## File Structure
```
OSCAR-BROOME-REVENUE/
├── models/
│   └── TransactionOverride.js    # Transaction override model
├── middleware/
│   └── authOverride.js          # Authentication middleware
├── routes/
│   └── transactionOverrideRoutes.js  # API routes
├── public/
│   └── override-dashboard.html  # Override management dashboard
├── server-enhanced.js           # Enhanced server with override capabilities
├── package-enhanced.json        # Updated package configuration
└── README-OVERRIDE.md          # This documentation
```

## Testing
Run the test suite:
```bash
npm test
```

## Logging
All override operations are logged to:
- Console output
- `override.log` - Override-specific logs
- `error.log` - Error logs

## Future Enhancements
- Database integration for persistent override storage
- Email notifications for override requests
- Advanced reporting and analytics
- Integration with external audit systems
- Multi-signature approval workflows
