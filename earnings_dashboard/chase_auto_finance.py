import os
import json
import requests
from flask import Blueprint, Response, request, jsonify, session
from datetime import datetime, timedelta
import jwt
import hashlib
import hmac
import base64
from functools import wraps

# Create a Blueprint for Chase Auto Finance integration
router = Blueprint('chase_auto_finance', __name__)

# Configuration
CHASE_CONFIG = {
    'client_id': os.getenv('CHASE_CLIENT_ID', 'your_chase_client_id'),
    'client_secret': os.getenv('CHASE_CLIENT_SECRET', 'your_chase_client_secret'),
    'api_base_url': 'https://api.chase.com',
    'auth_url': 'https://auth.chase.com/oauth2/token',
    'auto_finance_api_url': 'https://api.chase.com/auto-finance/v1',
    'jwt_secret': os.getenv('JWT_SECRET', 'your_jwt_secret_key'),
    'session_timeout': int(os.getenv('SESSION_TIMEOUT', '3600'))  # 1 hour
}

class ChaseAutoFinanceAPI:
    def __init__(self):
        self.client_id = CHASE_CONFIG['client_id']
        self.client_secret = CHASE_CONFIG['client_secret']
        self.api_base_url = CHASE_CONFIG['api_base_url']
        self.auth_url = CHASE_CONFIG['auth_url']
        self.auto_finance_api_url = CHASE_CONFIG['auto_finance_api_url']
        self.access_token = None
        self.token_expires = None

    def authenticate(self, username, password):
        """Authenticate with Chase API"""
        try:
            auth_string = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()

            headers = {
                'Authorization': f'Basic {auth_string}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            data = {
                'grant_type': 'password',
                'username': username,
                'password': password,
                'scope': 'auto-finance:read auto-finance:write'
            }

            response = requests.post(self.auth_url, headers=headers, data=data)
            response.raise_for_status()

            token_data = response.json()
            self.access_token = token_data['access_token']
            self.token_expires = datetime.now() + timedelta(seconds=token_data['expires_in'])

            return {
                'success': True,
                'access_token': self.access_token,
                'expires_in': token_data['expires_in']
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Authentication failed: {str(e)}'
            }

    def get_auto_finance_accounts(self, account_id=None):
        """Get auto finance account information"""
        if not self._is_token_valid():
            return {'success': False, 'error': 'Authentication required'}

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        try:
            if account_id:
                url = f"{self.auto_finance_api_url}/accounts/{account_id}"
            else:
                url = f"{self.auto_finance_api_url}/accounts"

            response = requests.get(url, headers=headers)
            response.raise_for_status()

            return {
                'success': True,
                'data': response.json()
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Failed to retrieve auto finance data: {str(e)}'
            }

    def get_loan_details(self, account_id, start_date=None, end_date=None):
        """Get auto loan details and payment history"""
        if not self._is_token_valid():
            return {'success': False, 'error': 'Authentication required'}

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        params = {}
        if start_date:
            params['start_date'] = start_date
        if end_date:
            params['end_date'] = end_date

        try:
            url = f"{self.auto_finance_api_url}/accounts/{account_id}/details"
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()

            return {
                'success': True,
                'data': response.json()
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Failed to retrieve loan details: {str(e)}'
            }

    def make_payment(self, account_id, amount, payment_date=None):
        """Make an auto finance payment"""
        if not self._is_token_valid():
            return {'success': False, 'error': 'Authentication required'}

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        payment_data = {
            'account_id': account_id,
            'amount': amount,
            'payment_date': payment_date or datetime.now().strftime('%Y-%m-%d')
        }

        try:
            url = f"{self.auto_finance_api_url}/payments"
            response = requests.post(url, headers=headers, json=payment_data)
            response.raise_for_status()

            return {
                'success': True,
                'data': response.json()
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Payment failed: {str(e)}'
            }

    def _is_token_valid(self):
        """Check if current access token is valid"""
        return self.access_token and self.token_expires and datetime.now() < self.token_expires

# Initialize Chase API client
chase_api = ChaseAutoFinanceAPI()

def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

@router.route('/login', methods=['GET', 'POST'])
def chase_login():
    """Handle Chase login"""
    if request.method == 'GET':
        # Return error for GET requests without proper data
        return jsonify({'success': False, 'error': 'Username and password required'}), 400

    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400

    username = data['username']
    password = data['password']

    # Hash password for security (in production, use proper password hashing)
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Authenticate with Chase API
    auth_result = chase_api.authenticate(username, password_hash)

    if auth_result['success']:
        # Create JWT token
        token_payload = {
            'user': username,
            'exp': datetime.utcnow() + timedelta(seconds=CHASE_CONFIG['session_timeout'])
        }
        token = jwt.encode(token_payload, CHASE_CONFIG['jwt_secret'], algorithm='HS256')

        session['user'] = username
        session['token'] = token

        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': token
        })
    else:
        return jsonify(auth_result), 401

@router.route('/accounts', methods=['GET'])
@login_required
def get_accounts():
    """Get auto finance accounts"""
    account_id = request.args.get('account_id')

    result = chase_api.get_auto_finance_accounts(account_id)

    if result['success']:
        return jsonify(result)
    else:
        return jsonify(result), 400

@router.route('/details/<account_id>', methods=['GET'])
@login_required
def get_details(account_id):
    """Get auto loan details"""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    result = chase_api.get_loan_details(account_id, start_date, end_date)

    if result['success']:
        return jsonify(result)
    else:
        return jsonify(result), 400

@router.route('/payment', methods=['POST'])
@login_required
def make_payment():
    """Make an auto finance payment"""
    data = request.get_json()

    if not data or 'account_id' not in data or 'amount' not in data:
        return jsonify({'success': False, 'error': 'Account ID and amount required'}), 400

    account_id = data['account_id']
    amount = data['amount']
    payment_date = data.get('payment_date')

    result = chase_api.make_payment(account_id, amount, payment_date)

    if result['success']:
        return jsonify(result)
    else:
        return jsonify(result), 400

@router.route('/sync', methods=['POST'])
@login_required
def sync_auto_finance_data():
    """Sync auto finance data with local system"""
    try:
        # Get all accounts
        accounts_result = chase_api.get_auto_finance_accounts()

        if not accounts_result['success']:
            return jsonify(accounts_result), 400

        accounts = accounts_result['data'].get('accounts', [])

        synced_data = {
            'sync_timestamp': datetime.now().isoformat(),
            'accounts': []
        }

        for account in accounts:
            account_id = account['id']

            # Get loan details
            details_result = chase_api.get_loan_details(
                account_id,
                start_date=(datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            )

            account_data = {
                'account_id': account_id,
                'account_info': account,
                'loan_details': details_result['data'] if details_result['success'] else []
            }

            synced_data['accounts'].append(account_data)

        # Save to local file (in production, use database)
        sync_file = os.path.join(os.path.dirname(__file__), 'auto_finance_sync_data.json')
        with open(sync_file, 'w') as f:
            json.dump(synced_data, f, indent=2)

        return jsonify({
            'success': True,
            'message': 'Auto finance data synced successfully',
            'data': synced_data
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Sync failed: {str(e)}'
        }), 500

@router.route('/')
def chase_auto_finance_page():
    """
    Serve enhanced Chase Auto Finance page with API integration.
    """
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Chase Auto Finance Integration</title>
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }

          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
          }

          .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
          }

          .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            text-align: center;
          }

          .header h1 {
            color: #00457c;
            font-size: 2.5rem;
            margin-bottom: 10px;
          }

          .login-section, .dashboard-section {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
          }

          .form-group {
            margin-bottom: 20px;
          }

          .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #555;
          }

          .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
          }

          .form-group input:focus {
            outline: none;
            border-color: #00457c;
          }

          .btn {
            background: linear-gradient(135deg, #00457c 0%, #0066cc 100%);
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            margin-right: 10px;
          }

          .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0, 69, 124, 0.3);
          }

          .btn-secondary {
            background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
          }

          .accounts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
          }

          .account-card {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            border-left: 4px solid #00457c;
          }

          .account-card h3 {
            color: #00457c;
            margin-bottom: 10px;
          }

          .account-info {
            margin-bottom: 15px;
          }

          .account-info p {
            margin-bottom: 5px;
            font-size: 14px;
          }

          .status {
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
          }

          .status.active {
            background: #d4edda;
            color: #155724;
          }

          .hidden {
            display: none;
          }

          .loading {
            text-align: center;
            padding: 20px;
          }

          .error {
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #dc3545;
          }

          .success {
            background: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #28a745;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🚗 Chase Auto Finance Integration</h1>
            <p>Secure access to your auto finance accounts and loan management</p>
          </div>

          <div id="loginSection" class="login-section">
            <h2>🔐 Login to Chase</h2>
            <div id="loginMessage"></div>
            <form id="loginForm">
              <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" required>
              </div>
              <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" required>
              </div>
              <button type="submit" class="btn">Login</button>
            </form>
          </div>

          <div id="dashboardSection" class="dashboard-section hidden">
            <h2>📊 Auto Finance Dashboard</h2>
            <div id="dashboardMessage"></div>
            <div class="accounts-grid" id="accountsGrid">
              <div class="loading">Loading accounts...</div>
            </div>
            <div style="margin-top: 20px;">
              <button id="syncBtn" class="btn">🔄 Sync Data</button>
              <button id="logoutBtn" class="btn btn-secondary">🚪 Logout</button>
            </div>
          </div>
        </div>

        <script>
          const API_BASE = '/chase-auto-finance';
          let authToken = localStorage.getItem('chase_token');

          // DOM elements
          const loginSection = document.getElementById('loginSection');
          const dashboardSection = document.getElementById('dashboardSection');
          const loginForm = document.getElementById('loginForm');
          const accountsGrid = document.getElementById('accountsGrid');
          const syncBtn = document.getElementById('syncBtn');
          const logoutBtn = document.getElementById('logoutBtn');

          // Initialize app
          function init() {
            if (authToken) {
              showDashboard();
              loadAccounts();
            } else {
              showLogin();
            }
          }

          // Show login form
          function showLogin() {
            loginSection.classList.remove('hidden');
            dashboardSection.classList.add('hidden');
          }

          // Show dashboard
          function showDashboard() {
            loginSection.classList.add('hidden');
            dashboardSection.classList.remove('hidden');
          }

          // Display message
          function showMessage(elementId, message, type = 'info') {
            const element = document.getElementById(elementId);
            element.className = type;
            element.innerHTML = message;
            setTimeout(() => element.innerHTML = '', 5000);
          }

          // Login handler
          loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            try {
              const response = await fetch(`${API_BASE}/login`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password }),
              });

              const data = await response.json();

              if (data.success) {
                authToken = data.token;
                localStorage.setItem('chase_token', authToken);
                showMessage('loginMessage', 'Login successful!', 'success');
                showDashboard();
                loadAccounts();
              } else {
                showMessage('loginMessage', data.error || 'Login failed', 'error');
              }
            } catch (error) {
              showMessage('loginMessage', 'Network error occurred', 'error');
            }
          });

          // Load accounts
          async function loadAccounts() {
            try {
              const response = await fetch(`${API_BASE}/accounts`, {
                headers: {
                  'Authorization': `Bearer ${authToken}`,
                },
              });

              const data = await response.json();

              if (data.success) {
                displayAccounts(data.data.accounts || []);
              } else {
                accountsGrid.innerHTML = '<div class="error">Failed to load accounts</div>';
              }
            } catch (error) {
              accountsGrid.innerHTML = '<div class="error">Network error occurred</div>';
            }
          }

          // Display accounts
          function displayAccounts(accounts) {
            if (accounts.length === 0) {
              accountsGrid.innerHTML = '<div class="account-card">No accounts found</div>';
              return;
            }

            accountsGrid.innerHTML = accounts.map(account => `
              <div class="account-card">
                <h3>${account.name || 'Auto Finance Account'}</h3>
                <div class="account-info">
                  <p><strong>Account ID:</strong> ${account.id}</p>
                  <p><strong>Balance:</strong> $${account.balance || 'N/A'}</p>
                  <p><strong>Interest Rate:</strong> ${account.interestRate || 'N/A'}%</p>
                  <p><strong>Status:</strong> <span class="status active">${account.status || 'Active'}</span></p>
                </div>
                <button class="btn" onclick="viewDetails('${account.id}')">View Details</button>
              </div>
            `).join('');
          }

          // View loan details
          async function viewDetails(accountId) {
            try {
              const response = await fetch(`${API_BASE}/details/${accountId}`, {
                headers: {
                  'Authorization': `Bearer ${authToken}`,
                },
              });

              const data = await response.json();

              if (data.success) {
                alert('Loan details loaded successfully! (Check console for details)');
                console.log('Loan Details:', data.data);
              } else {
                alert('Failed to load loan details');
              }
            } catch (error) {
              alert('Network error occurred');
            }
          }

          // Sync data
          syncBtn.addEventListener('click', async () => {
            try {
              const response = await fetch(`${API_BASE}/sync`, {
                method: 'POST',
                headers: {
                  'Authorization': `Bearer ${authToken}`,
                },
              });

              const data = await response.json();

              if (data.success) {
                showMessage('dashboardMessage', 'Data synced successfully!', 'success');
              } else {
                showMessage('dashboardMessage', data.error || 'Sync failed', 'error');
              }
            } catch (error) {
              showMessage('dashboardMessage', 'Network error occurred', 'error');
            }
          });

          // Logout
          logoutBtn.addEventListener('click', () => {
            authToken = null;
            localStorage.removeItem('chase_token');
            showLogin();
            showMessage('loginMessage', 'Logged out successfully', 'success');
          });

          // Initialize on page load
          init();
        </script>
      </body>
    </html>
    """

    return Response(html_content, mimetype='text/html')
