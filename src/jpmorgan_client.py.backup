import requests
import logging
import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import jwt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class JPMorganAPIClient:
    """
    Enhanced JPMorgan API client for Equity Shield Advocates integration.
    Handles authentication, account management, and transaction processing.
    """

    def __init__(self):
        self.base_url = os.getenv('JPMORGAN_API_BASE_URL', 'https://api.jpmorgan.com')
        self.client_id = os.getenv('JPMORGAN_CLIENT_ID')
        self.client_secret = os.getenv('JPMORGAN_CLIENT_SECRET')
        self.api_key = os.getenv('JPMORGAN_API_KEY')
        self.private_key_path = os.getenv('JPMORGAN_PRIVATE_KEY_PATH')

        # Token management
        self.access_token = None
        self.token_expires_at = None

        # Session for connection reuse
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-API-Key': self.api_key
        })

    def _get_access_token(self) -> str:
        """Get or refresh access token using OAuth2/JWT"""
        if self.access_token and self.token_expires_at and datetime.now() < self.token_expires_at:
            return self.access_token

        try:
            # Load private key for JWT signing
            with open(self.private_key_path, 'r') as f:
                private_key = f.read()

            # Create JWT payload
            now = datetime.utcnow()
            payload = {
                'iss': self.client_id,
                'sub': self.client_id,
                'aud': f'{self.base_url}/oauth/token',
                'iat': now,
                'exp': now + timedelta(minutes=30)
            }

            # Sign JWT
            token = jwt.encode(payload, private_key, algorithm='RS256')

            # Request access token
            token_url = f'{self.base_url}/oauth/token'
            data = {
                'grant_type': 'client_credentials',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': token
            }

            response = self.session.post(token_url, data=data)
            response.raise_for_status()

            token_data = response.json()
            self.access_token = token_data['access_token']
            expires_in = token_data.get('expires_in', 3600)
            self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)

            logger.info("Successfully obtained JPMorgan access token")
            return self.access_token

        except Exception as e:
            logger.error(f"Failed to get access token: {str(e)}")
            raise

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated request to JPMorgan API"""
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f'Bearer {self._get_access_token()}'

        kwargs['headers'] = headers

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            raise

    def get_account_balance(self, account_id: str) -> Dict[str, Any]:
        """Get account balance information"""
        logger.info(f"Fetching balance for account: {account_id}")
        return self._make_request('GET', f'/accounts/{account_id}/balance')

    def get_account_transactions(self, account_id: str, start_date: str = None, end_date: str = None) -> List[Dict[str, Any]]:
        """Get account transaction history"""
        params = {}
        if start_date:
            params['startDate'] = start_date
        if end_date:
            params['endDate'] = end_date

        logger.info(f"Fetching transactions for account: {account_id}")
        response = self._make_request('GET', f'/accounts/{account_id}/transactions', params=params)
        return response.get('transactions', [])

    def initiate_transfer(self, from_account: str, to_account: str, amount: float, currency: str = 'USD') -> Dict[str, Any]:
        """Initiate a transfer between accounts"""
        transfer_data = {
            'fromAccount': from_account,
            'toAccount': to_account,
            'amount': amount,
            'currency': currency,
            'transferDate': datetime.now().isoformat(),
            'description': 'Equity Shield Advocates Transfer'
        }

        logger.info(f"Initiating transfer: {amount} {currency} from {from_account} to {to_account}")
        return self._make_request('POST', '/transfers', json=transfer_data)

    def get_transfer_status(self, transfer_id: str) -> Dict[str, Any]:
        """Get transfer status"""
        logger.info(f"Checking transfer status: {transfer_id}")
        return self._make_request('GET', f'/transfers/{transfer_id}')

    def get_corporate_accounts(self, client_id: str) -> List[Dict[str, Any]]:
        """Get corporate account information"""
        logger.info(f"Fetching corporate accounts for client: {client_id}")
        response = self._make_request('GET', f'/clients/{client_id}/accounts')
        return response.get('accounts', [])

    def create_corporate_account(self, client_id: str, account_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new corporate account"""
        logger.info(f"Creating corporate account for client: {client_id}")
        return self._make_request('POST', f'/clients/{client_id}/accounts', json=account_data)

    def get_investment_portfolio(self, account_id: str) -> Dict[str, Any]:
        """Get investment portfolio details"""
        logger.info(f"Fetching investment portfolio for account: {account_id}")
        return self._make_request('GET', f'/accounts/{account_id}/portfolio')

    def place_investment_order(self, account_id: str, order_data: Dict[str, Any]) -> Dict[str, Any]:
        """Place an investment order"""
        logger.info(f"Placing investment order for account: {account_id}")
        return self._make_request('POST', f'/accounts/{account_id}/orders', json=order_data)

    def get_market_data(self, symbols: List[str]) -> Dict[str, Any]:
        """Get market data for specified symbols"""
        symbols_param = ','.join(symbols)
        logger.info(f"Fetching market data for symbols: {symbols_param}")
        return self._make_request('GET', f'/market-data?symbols={symbols_param}')

    def get_compliance_status(self, account_id: str) -> Dict[str, Any]:
        """Get compliance status for account"""
        logger.info(f"Fetching compliance status for account: {account_id}")
        return self._make_request('GET', f'/accounts/{account_id}/compliance')

    def submit_compliance_report(self, account_id: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit compliance report"""
        logger.info(f"Submitting compliance report for account: {account_id}")
        return self._make_request('POST', f'/accounts/{account_id}/compliance/reports', json=report_data)

# Global client instance
jpmorgan_client = JPMorganAPIClient()
