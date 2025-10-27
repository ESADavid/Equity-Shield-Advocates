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
from src.credential_manager import credential_manager
from src.audit_logger import audit_logger

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
        # Use credential manager for secure storage
        jpmorgan_creds = credential_manager.retrieve_credential('jpmorgan')
        if jpmorgan_creds:
            self.client_id = jpmorgan_creds.get('client_id')
            self.client_secret = jpmorgan_creds.get('client_secret')
            self.api_key = jpmorgan_creds.get('api_key')
            self.private_key_path = jpmorgan_creds.get('private_key_path')
        else:
            # Fallback to environment variables
            self.client_id = os.getenv('JPMORGAN_CLIENT_ID')
            self.client_secret = os.getenv('JPMORGAN_CLIENT_SECRET')
            self.api_key = os.getenv('JPMORGAN_API_KEY')
            self.private_key_path = os.getenv('JPMORGAN_PRIVATE_KEY_PATH')

        self.base_url = os.getenv('JPMORGAN_API_BASE_URL', 'https://api.jpmorgan.com')
        self.timeout = int(os.getenv('JPMORGAN_REQUEST_TIMEOUT', '30'))

        # Enhanced token management with encryption
        self._token_lock = threading.Lock()
        self.token_cache_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'jpmorgan_tokens.enc')
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None
        self.refresh_token_expires_at = None

        # Session for connection reuse with timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-API-Key': self.api_key
        })

        # Load cached tokens
        self._load_token_cache()

        # Validate configuration on initialization
        self._validate_config()

    def _load_token_cache(self) -> None:
        """Load encrypted token cache"""
        try:
            if os.path.exists(self.token_cache_file):
                with open(self.token_cache_file, 'r') as f:
                    encrypted_data = f.read().strip()
                    if encrypted_data:
                        cache_data = credential_manager._decrypt_data(encrypted_data)
                        self.access_token = cache_data.get('access_token')
                        self.refresh_token = cache_data.get('refresh_token')
                        if cache_data.get('token_expires_at'):
                            self.token_expires_at = datetime.fromisoformat(cache_data['token_expires_at'])
                        if cache_data.get('refresh_token_expires_at'):
                            self.refresh_token_expires_at = datetime.fromisoformat(cache_data['refresh_token_expires_at'])
        except Exception as e:
            logger.warning(f"Failed to load token cache: {str(e)}")

    def _save_token_cache(self) -> None:
        """Save encrypted token cache"""
        try:
            cache_data = {
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'token_expires_at': self.token_expires_at.isoformat() if self.token_expires_at else None,
                'refresh_token_expires_at': self.refresh_token_expires_at.isoformat() if self.refresh_token_expires_at else None
            }
            encrypted_data = credential_manager._encrypt_data(cache_data)
            os.makedirs(os.path.dirname(self.token_cache_file), exist_ok=True)
            with open(self.token_cache_file, 'w') as f:
                f.write(encrypted_data)
        except Exception as e:
            logger.error(f"Failed to save token cache: {str(e)}")

    def _validate_config(self) -> None:
        """Validate required configuration parameters"""
        required_vars = ['client_id', 'client_secret', 'api_key', 'private_key_path']
        missing_vars = [var for var in required_vars if not getattr(self, var)]

        if missing_vars:
            error_msg = f"Missing required JPMorgan configuration: {', '.join(missing_vars)}"
            audit_logger.log_security_incident(
                'configuration_error',
                'high',
                details={'missing_vars': missing_vars, 'service': 'jpmorgan_client'}
            )
            raise ValueError(error_msg)

        if not os.path.exists(self.private_key_path):
            error_msg = f"JPMorgan private key file not found: {self.private_key_path}"
            audit_logger.log_security_incident(
                'file_not_found',
                'high',
                details={'file_path': self.private_key_path, 'service': 'jpmorgan_client'}
            )
            raise FileNotFoundError(error_msg)

    def _get_access_token(self) -> str:
        """Get or refresh access token using OAuth2/JWT with enhanced caching"""
        with self._token_lock:
            # Check if current token is still valid
            if (self.access_token and self.token_expires_at and
                datetime.now() < self.token_expires_at - timedelta(minutes=5)):  # Refresh 5 minutes early
                return self.access_token

            # Try to refresh token if we have a refresh token
            if (self.refresh_token and self.refresh_token_expires_at and
                datetime.now() < self.refresh_token_expires_at):
                if self._refresh_access_token():
                    audit_logger.log_auth_event('token_refresh', 'jpmorgan_client', True)
                    return self.access_token

            # Get new tokens
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
                self.refresh_token = token_data.get('refresh_token')  # May not be provided by all OAuth servers

                expires_in = token_data.get('expires_in', 3600)
                self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)

                # Set refresh token expiry (typically longer than access token)
                refresh_expires_in = token_data.get('refresh_expires_in', expires_in * 24)  # Default 24 hours
                self.refresh_token_expires_at = datetime.now() + timedelta(seconds=refresh_expires_in)

                # Save to cache
                self._save_token_cache()

                audit_logger.log_auth_event('token_generation', 'jpmorgan_client', True)
                logger.info("Successfully obtained JPMorgan access token")
                return self.access_token

            except FileNotFoundError as e:
                audit_logger.log_security_incident('file_access_error', 'high',
                    details={'error': str(e), 'service': 'jpmorgan_client'})
                logger.error(f"Private key file error: {str(e)}")
                raise
            except jwt.InvalidKeyError as e:
                audit_logger.log_security_incident('invalid_key', 'critical',
                    details={'error': str(e), 'service': 'jpmorgan_client'})
                logger.error(f"Invalid private key: {str(e)}")
                raise ValueError("Invalid JPMorgan private key format") from e
            except requests.exceptions.RequestException as e:
                audit_logger.log_auth_event('token_generation', 'jpmorgan_client', False,
                    details={'error': str(e)})
                logger.error(f"Token request failed: {str(e)}")
                raise
            except Exception as e:
                audit_logger.log_security_incident('token_error', 'high',
                    details={'error': str(e), 'service': 'jpmorgan_client'})
                logger.error(f"Unexpected error getting access token: {str(e)}")
                raise

    def _refresh_access_token(self) -> bool:
        """Refresh access token using refresh token"""
        try:
            if not self.refresh_token:
                return False

            token_url = f'{self.base_url}/oauth/token'
            data = {
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token,
                'client_id': self.client_id
            }

            response = self.session.post(token_url, data=data, timeout=self.timeout)
            response.raise_for_status()

            token_data = response.json()
            self.access_token = token_data['access_token']

            expires_in = token_data.get('expires_in', 3600)
            self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)

            # Update refresh token if provided
            if 'refresh_token' in token_data:
                self.refresh_token = token_data['refresh_token']
                refresh_expires_in = token_data.get('refresh_expires_in', expires_in * 24)
                self.refresh_token_expires_at = datetime.now() + timedelta(seconds=refresh_expires_in)

            self._save_token_cache()

            logger.info("Successfully refreshed JPMorgan access token")
            return True

        except Exception as e:
            logger.warning(f"Failed to refresh access token: {str(e)}")
            # Clear invalid tokens
            self.access_token = None
            self.refresh_token = None
            self._save_token_cache()
            return False

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((requests.exceptions.RequestException, requests.exceptions.Timeout))
    )
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated request to JPMorgan API with enhanced error handling"""
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f'Bearer {self._get_access_token()}'

        kwargs['headers'] = headers
        kwargs.setdefault('timeout', self.timeout)

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            # Log successful API call
            audit_logger.log_api_access(
                'jpmorgan_client',
                endpoint,
                method,
                response.status_code,
                getattr(response, 'elapsed', None).total_seconds() * 1000 if hasattr(response, 'elapsed') else None
            )

            return response.json()

        except requests.exceptions.HTTPError as e:
            status_code = response.status_code

            # Log API error
            audit_logger.log_api_access(
                'jpmorgan_client',
                endpoint,
                method,
                status_code
            )

            if status_code == 401:
                audit_logger.log_security_incident('unauthorized_access', 'medium',
                    details={'endpoint': endpoint, 'service': 'jpmorgan_client'})
                # Token might be invalid, clear cache
                self.access_token = None
                self._save_token_cache()
            elif status_code == 403:
                audit_logger.log_security_incident('forbidden_access', 'high',
                    details={'endpoint': endpoint, 'service': 'jpmorgan_client'})
            elif status_code == 429:
                audit_logger.log_security_incident('rate_limit_exceeded', 'medium',
                    details={'endpoint': endpoint, 'service': 'jpmorgan_client'})
                logger.warning(f"Rate limited by JPMorgan API: {status_code}")
                raise  # Will be retried by tenacity
            elif status_code >= 500:
                audit_logger.log_security_incident('api_server_error', 'medium',
                    details={'endpoint': endpoint, 'status_code': status_code, 'service': 'jpmorgan_client'})
                logger.warning(f"JPMorgan API server error: {status_code}")
                raise  # Will be retried by tenacity
            else:
                audit_logger.log_security_incident('api_error', 'low',
                    details={'endpoint': endpoint, 'status_code': status_code, 'service': 'jpmorgan_client'})
                logger.error(f"JPMorgan API error: {status_code} - {response.text}")
                raise

        except requests.exceptions.Timeout as e:
            audit_logger.log_security_incident('api_timeout', 'medium',
                details={'endpoint': endpoint, 'service': 'jpmorgan_client'})
            logger.warning(f"Request timeout for {endpoint}: {str(e)}")
            raise
        except requests.exceptions.RequestException as e:
            audit_logger.log_security_incident('api_connection_error', 'high',
                details={'endpoint': endpoint, 'error': str(e), 'service': 'jpmorgan_client'})
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

# Global client instance - only create if configuration is available
try:
    jpmorgan_client = JPMorganAPIClient()
    logger.info("JPMorgan client initialized successfully")
except (ValueError, FileNotFoundError) as e:
    logger.warning(f"JPMorgan client initialization failed: {str(e)}. JPMorgan features will be disabled.")
    jpmorgan_client = None
except Exception as e:
    logger.error(f"Unexpected error initializing JPMorgan client: {str(e)}")
    jpmorgan_client = None
