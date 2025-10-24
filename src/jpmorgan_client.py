import requests
import logging
import json
import os
import threading
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import jwt
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

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
        self.timeout = int(os.getenv('JPMORGAN_REQUEST_TIMEOUT', '30'))

        # Token management with thread safety
        self._token_lock = threading.Lock()
        self.access_token = None
        self.token_expires_at = None

        # Session for connection reuse with timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-API-Key': self.api_key
        })

        # Validate configuration on initialization
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate required configuration parameters"""
        required_vars = ['client_id', 'client_secret', 'api_key', 'private_key_path']
        missing_vars = [var for var in required_vars if not getattr(self, var)]

        if missing_vars:
            raise ValueError(f"Missing required JPMorgan configuration: {', '.join(missing_vars)}")

        if not os.path.exists(self.private_key_path):
            raise FileNotFoundError(f"JPMorgan private key file not found: {self.private_key_path}")

    def _get_access_token(self) -> str:
        """Get or refresh access token using OAuth2/JWT with thread safety"""
        with self._token_lock:
            if self.access_token and self.token_expires_at and datetime.now() < self.token_expires_at:
                return self.access_token

            try:
                # Validate private key file exists and is readable
                if not os.path.isfile(self.private_key_path):
                    raise FileNotFoundError(f"Private key file not found: {self.private_key_path}")

                # Load private key for JWT signing
                with open(self.private_key_path, 'r') as f:
                    private_key = f.read().strip()

                if not private_key:
                    raise ValueError("Private key file is empty")

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

                response = self.session.post(token_url, data=data, timeout=self.timeout)
                response.raise_for_status()

                token_data = response.json()
                self.access_token = token_data['access_token']
                expires_in = token_data.get('expires_in', 3600)
                self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)

                logger.info("Successfully obtained JPMorgan access token")
                return self.access_token

            except FileNotFoundError as e:
                logger.error(f"Private key file error: {str(e)}")
                raise
            except jwt.InvalidKeyError as e:
                logger.error(f"Invalid private key: {str(e)}")
                raise ValueError("Invalid JPMorgan private key format") from e
            except requests.exceptions.RequestException as e:
                logger.error(f"Token request failed: {str(e)}")
                raise
            except Exception as e:
                logger.error(f"Unexpected error getting access token: {str(e)}")
                raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((requests.exceptions.RequestException, requests.exceptions.Timeout))
    )
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated request to JPMorgan API with retry logic"""
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f'Bearer {self._get_access_token()}'

        kwargs['headers'] = headers
        kwargs.setdefault('timeout', self.timeout)

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:
                logger.warning(f"Rate limited by JPMorgan API: {response.status_code}")
                raise  # Will be retried by tenacity
            elif response.status_code >= 500:
                logger.warning(f"JPMorgan API server error: {response.status_code}")
                raise  # Will be retried by tenacity
            else:
                logger.error(f"JPMorgan API error: {response.status_code} - {response.text}")
                raise
        except requests.exceptions.Timeout as e:
            logger.warning(f"Request timeout for {endpoint}: {str(e)}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {endpoint}: {str(e)}")
            raise

    def get_account_balance(self, account_id: str) -> Dict[str, Any]:
        """Get account balance information"""
        if not account_id or not isinstance(account_id, str):
            raise ValueError("Invalid account_id provided")

        logger.info(f"Fetching balance for account: {account_id}")
        return self._make_request('GET', f'/accounts/{account_id}/balance')

    def get_account_transactions(self, account_id: str, start_date: str = None, end_date: str = None) -> List[Dict[str, Any]]:
        """Get account transaction history"""
        if not account_id or not isinstance(account_id, str):
            raise ValueError("Invalid account_id provided")

        params = {}
        if start_date:
            # Validate date format
            try:
                datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                params['startDate'] = start_date
            except ValueError:
                raise ValueError("Invalid start_date format. Use ISO format.")
        if end_date:
            try:
                datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                params['endDate'] = end_date
            except ValueError:
                raise ValueError("Invalid end_date format. Use ISO format.")

        logger.info(f"Fetching transactions for account: {account_id}")
        response = self._make_request('GET', f'/accounts/{account_id}/transactions', params=params)
        return response.get('transactions', [])

    def initiate_transfer(self, from_account: str, to_account: str, amount: float, currency: str = 'USD') -> Dict[str, Any]:
        """Initiate a transfer between accounts"""
        if not all([from_account, to_account, amount]):
            raise ValueError("Missing required transfer parameters")

        if amount <= 0:
            raise ValueError("Transfer amount must be positive")

        if currency not in ['USD', 'EUR', 'GBP']:
            raise ValueError("Unsupported currency")

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
        if not transfer_id or not isinstance(transfer_id, str):
            raise ValueError("Invalid transfer_id provided")

        logger.info(f"Checking transfer status: {transfer_id}")
        return self._make_request('GET', f'/transfers/{transfer_id}')

    def get_corporate_accounts(self, client_id: str) -> List[Dict[str, Any]]:
        """Get corporate account information"""
        if not client_id or not isinstance(client_id, str):
            raise ValueError("Invalid client_id provided")

        logger.info(f"Fetching corporate accounts for client: {client_id}")
        response = self._make_request('GET', f'/clients/{client_id}/accounts')
        return response.get('accounts', [])

    def create_corporate_account(self, client_id: str, account_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new corporate account"""
        if not client_id or not isinstance(client_id, str):
            raise ValueError("Invalid client_id provided")

        if not account_data or not isinstance(account_data, dict):
            raise ValueError("Invalid account_data provided")

        logger.info(f"Creating corporate account for client: {client_id}")
        return self._make_request('POST', f'/clients/{client_id}/accounts', json=account_data)

    def get_investment_portfolio(self, account_id: str) -> Dict[str, Any]:
        """Get investment portfolio details"""
        if not account_id or not isinstance(account_id, str):
            raise ValueError("Invalid account_id provided")

        logger.info(f"Fetching investment portfolio for account: {account_id}")
        return self._make_request('GET', f'/accounts/{account_id}/portfolio')

    def place_investment_order(self, account_id: str, order_data: Dict[str, Any]) -> Dict[str, Any]:
        """Place an investment order"""
        if not account_id or not isinstance(account_id, str):
            raise ValueError("Invalid account_id provided")

        if not order_data or not isinstance(order_data, dict):
            raise ValueError("Invalid order_data provided")

        logger.info(f"Placing investment order for account: {account_id}")
        return self._make_request('POST', f'/accounts/{account_id}/orders', json=order_data)

    def get_market_data(self, symbols: List[str]) -> Dict[str, Any]:
        """Get market data for specified symbols"""
        if not symbols or not isinstance(symbols, list):
            raise ValueError("Invalid symbols list provided")

        # Sanitize symbols
        sanitized_symbols = [str(s).strip().upper() for s in symbols if s and str(s).strip()]
        if not sanitized_symbols:
            raise ValueError("No valid symbols provided")

        symbols_param = ','.join(sanitized_symbols)
        logger.info(f"Fetching market data for symbols: {symbols_param}")
        return self._make_request('GET', f'/market-data?symbols={symbols_param}')

    def get_compliance_status(self, account_id: str) -> Dict[str, Any]:
        """Get compliance status for account"""
        if not account_id or not isinstance(account_id, str):
            raise ValueError("Invalid account_id provided")

        logger.info(f"Fetching compliance status for account: {account_id}")
        return self._make_request('GET', f'/accounts/{account_id}/compliance')

    def submit_compliance_report(self, account_id: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit compliance report"""
        if not account_id or not isinstance(account_id, str):
            raise ValueError("Invalid account_id provided")

        if not report_data or not isinstance(report_data, dict):
            raise ValueError("Invalid report_data provided")

        logger.info(f"Submitting compliance report for account: {account_id}")
        return self._make_request('POST', f'/accounts/{account_id}/compliance/reports', json=report_data)

# Global client instance
jpmorgan_client = JPMorganAPIClient()
