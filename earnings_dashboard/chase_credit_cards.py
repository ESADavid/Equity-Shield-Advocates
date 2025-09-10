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

# Create a Blueprint for Chase Credit Cards integration
router = Blueprint('chase_credit_cards', __name__)

# Configuration
CHASE_CONFIG = {
    'client_id': os.getenv('CHASE_CLIENT_ID', 'your_chase_client_id'),
    'client_secret': os.getenv('CHASE_CLIENT_SECRET', 'your_chase_client_secret'),
    'api_base_url': 'https://api.chase.com',
    'auth_url': 'https://auth.chase.com/oauth2/token',
    'credit_card_api_url': 'https://api.chase.com/credit-cards/v1',
    'jwt_secret': os.getenv('JWT_SECRET', 'your_jwt_secret_key'),
    'session_timeout': int(os.getenv('SESSION_TIMEOUT', '3600'))  # 1 hour
}

class ChaseCreditCardAPI:
    def __init__(self):
        self.client_id = CHASE_CONFIG['client_id']
        self.client_secret = CHASE_CONFIG['client_secret']
        self.api_base_url = CHASE_CONFIG['api_base_url']
        self.auth_url = CHASE_CONFIG['auth_url']
        self.credit_card_api_url = CHASE_CONFIG['credit_card_api_url']
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
                'scope': 'credit-cards:read credit-cards:write'
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

    def get_credit_card_accounts(self, account_id=None):
        """Get credit card account information"""
        if not self._is_token_valid():
            return {'success': False, 'error': 'Authentication required'}

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        try:
            if account_id:
                url = f"{self.credit_card_api_url}/accounts/{account_id}"
            else:
                url = f"{self.credit_card_api_url}/accounts"

            response = requests.get(url, headers=headers)
            response.raise_for_status()

            return {
                'success': True,
                'data': response.json()
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Failed to retrieve credit card data: {str(e)}'
            }

    def get_transaction_history(self, account_id, start_date=None, end_date=None):
        """Get credit card transaction history"""
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
            url = f"{self.credit_card_api_url}/accounts/{account_id}/transactions"
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()

            return {
                'success': True,
                'data': response.json()
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Failed to retrieve transaction data: {str(e)}'
            }

    def make_payment(self, account_id, amount, payment_date=None):
        """Make a credit card payment"""
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
            url = f"{self.credit_card_api_url}/payments"
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

    def get_credit_limits(self, account_id):
        """Get credit card limits and available credit"""
        if not self._is_token_valid():
            return {'success': False, 'error': 'Authentication required'}

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        try:
            url = f"{self.credit_card_api_url}/accounts/{account_id}/limits"
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            return {
                'success': True,
                'data': response.json()
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Failed to retrieve credit limits: {str(e)}'
            }

    def _is_token_valid(self):
        """Check if current access token is valid"""
        return self.access_token and self.token_expires and datetime.now() < self.token_expires

# Initialize Chase API client
chase_api = ChaseCreditCardAPI()

def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

@router.route('/chase-credit-cards/login', methods=['POST'])
def chase_login():
    """Handle Chase login"""
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

@router.route('/chase-credit-cards/accounts', methods=['GET'])
@login_required
def get_accounts():
    """Get credit card accounts"""
    account_id = request.args.get('account_id')

    result = chase_api.get_credit_card_accounts(account_id)

    if result['success']:
        return jsonify(result)
    else:
        return jsonify(result), 400

@router.route('/chase-credit-cards/transactions/<account_id>', methods=['GET'])
@login_required
def get_transactions(account_id):
    """Get credit card transactions"""
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    result = chase_api.get_transaction_history(account_id, start_date, end_date)

    if result['success']:
        return jsonify(result)
    else:
        return jsonify(result), 400

@router.route('/chase-credit-cards/payment', methods=['POST'])
@login_required
def make_payment():
    """Make a credit card payment"""
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

@router.route('/chase-credit-cards/limits/<account_id>', methods=['GET'])
@login_required
def get_limits(account_id):
    """Get credit card limits"""
    result = chase_api.get_credit_limits(account_id)

    if result['success']:
        return jsonify(result)
    else:
        return jsonify(result), 400

@router.route('/chase-credit-cards/sync', methods=['POST'])
@login_required
def sync_credit_card_data():
    """Sync credit card data with local system"""
    try:
        # Get all accounts
        accounts_result = chase_api.get_credit_card_accounts()

        if not accounts_result['success']:
            return jsonify(accounts_result), 400

        accounts = accounts_result['data'].get('accounts', [])

        synced_data = {
            'sync_timestamp': datetime.now().isoformat(),
            'accounts': []
        }

        for account in accounts:
            account_id = account['id']

            # Get recent transactions
            transactions_result = chase_api.get_transaction_history(
                account_id,
                start_date=(datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            )

            # Get credit limits
            limits_result = chase_api.get_credit_limits(account_id)

            account_data = {
                'account_id': account_id,
                'account_info': account,
                'recent_transactions': transactions_result['data'] if transactions_result['success'] else [],
                'credit_limits': limits_result['data'] if limits_result['success'] else {}
            }

            synced_data['accounts'].append(account_data)

        # Save to local file (in production, use database)
        sync_file = os.path.join(os.path.dirname(__file__), 'credit_card_sync_data.json')
        with open(sync_file, 'w') as f:
            json.dump(synced_data, f, indent=2)

        return jsonify({
            'success': True,
            'message': 'Credit card data synced successfully',
            'data': synced_data
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Sync failed: {str(e)}'
        }), 500

@router.route('/chase-credit-cards')
def chase_credit_cards_page():
    """
    Serve enhanced Chase Credit Cards page with API integration.
    """
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Chase Credit Cards Integration</title>
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
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
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

          .credit-utilization {
            background: linear-gradient(90deg, #28a745 0%, #ffc107 50%, #dc3545 100%);
            height: 8px;
            border-radius: 4px;
            margin: 10px 0;
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

          .transactions-list {
            max-height: 300px;
            overflow-y: auto;
            margin-top: 15px;
          }

          .transaction-item {
            padding: 10px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
          }

          .transaction-item:last-child {
            border-bottom: none;
          }

          .transaction-amount {
            font-weight: 600;
          }

          .transaction-amount.positive {
            color: #28a745;
          }

          .transaction-amount.negative {
            color: #dc3545;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>💳 Chase Credit Cards Integration</h1>
            <p>Secure access to your credit card accounts and transaction management</p>
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
            <h2>📊 Credit Cards Dashboard</h2>
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
          const API_BASE = '/chase-credit-cards';
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
                <h3>${account.name || 'Credit Card Account'}</h3>
                <div class="account-info">
                  <p><strong>Account ID:</strong> ${account.id}</p>
                  <p><strong>Balance:</strong> $${account.balance || '0.00'}</p>
                  <p><strong>Credit Limit:</strong> $${account.creditLimit || 'N/A'}</p>
                  <p><strong>Available Credit:</strong> $${account.availableCredit || 'N/A'}</p>
                  <div class="credit-utilization" style="width: ${calculateUtilization(account.balance, account.creditLimit)}%"></div>
                  <p><strong>Status:</strong> <span class="status active">${account.status || 'Active'}</span></p>
                </div>
                <button class="btn" onclick="viewTransactions('${account.id}')">View Transactions</button>
                <button class="btn" onclick="makePayment('${account.id}')">Make Payment</button>
              </div>
            `).join('');
          }

          // Calculate credit utilization percentage
          function calculateUtilization(balance, limit) {
            if (!balance || !limit) return 0;
            return Math.min((balance / limit) * 100, 100);
          }

          // View transactions
          async function viewTransactions(accountId) {
            try {
              const response = await fetch(`${API_BASE}/transactions/${accountId}`, {
                headers: {
                  'Authorization': `Bearer ${authToken}`,
                },
              });

              const data = await response.json();

              if (data.success) {
                const transactions = data.data.transactions || [];
                const transactionHtml = `
                  <div class="account-card">
                    <h3>Recent Transactions</h3>
                    <div class="transactions-list">
                      ${transactions.slice(0, 10).map(transaction => `
                        <div class="transaction-item">
                          <div>
                            <strong>${transaction.description || 'Transaction'}</strong><br>
                            <small>${new Date(transaction.date).toLocaleDateString()}</small>
                          </div>
                          <div class="transaction-amount ${transaction.amount > 0 ? 'positive' : 'negative'}">
                            ${transaction.amount > 0 ? '+' : ''}$${Math.abs(transaction.amount || 0).toFixed(2)}
                          </div>
                        </div>
                      `).join('')}
                    </div>
                  </div>
                `;
                alert('Transactions loaded! (Check console for details)');
                console.log('Transactions:', transactions);
              } else {
                alert('Failed to load transactions');
              }
            } catch (error) {
              alert('Network error occurred');
            }
          }

          // Make payment
          function makePayment(accountId) {
            const amount = prompt('Enter payment amount:');
            if (amount && !isNaN(amount)) {
              // In a real implementation, this would make an API call
              alert(`Payment of $${amount} initiated for account ${accountId}`);
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
