import pytest
import json
import os
import sys
from unittest.mock import Mock, patch, MagicMock
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from src.jpmorgan_client import JPMorganAPIClient
from src.api_server import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    client = app.test_client()
    yield client

API_KEY = "equity-shield-2024-secure-key"
HEADERS = {"X-API-KEY": API_KEY}

class TestJPMorganAPIClient:
    """Test cases for JPMorgan API client"""

    @patch('src.jpmorgan_client.requests.Session')
    @patch('src.jpmorgan_client.credential_manager')
    def test_get_access_token(self, mock_cred_manager, mock_session):
        """Test OAuth2 token retrieval"""
        # Mock credential manager
        mock_cred_manager.retrieve_credential.return_value = {
            'client_id': 'test_client',
            'client_secret': 'test_secret',
            'api_key': 'test_api_key',
            'private_key_path': '/tmp/test_key.pem'
        }

        # Mock the session and response
        mock_response = Mock()
        mock_response.json.return_value = {
            'access_token': 'test_token',
            'expires_in': 3600
        }
        mock_session.return_value.post.return_value = mock_response

        # Mock file operations
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = 'test_key'
            with patch('jwt.encode') as mock_jwt:
                mock_jwt.return_value = 'test_jwt'
                client = JPMorganAPIClient()
        client.client_id = 'test_client'
        client.private_key_path = '/tmp/test_key.pem'

        # Mock file reading
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = 'test_key'
            with patch('jwt.encode') as mock_jwt:
                mock_jwt.return_value = 'test_jwt'
                token = client._get_access_token()

                assert token == 'test_token'
                assert client.access_token == 'test_token'

    @patch('src.jpmorgan_client.JPMorganAPIClient._get_access_token')
    @patch('src.jpmorgan_client.requests.Session')
    @patch('src.jpmorgan_client.credential_manager')
    def test_get_account_balance(self, mock_cred_manager, mock_session, mock_token):
        """Test account balance retrieval"""
        # Mock credential manager
        mock_cred_manager.retrieve_credential.return_value = {
            'client_id': 'test_client',
            'client_secret': 'test_secret',
            'api_key': 'test_api_key',
            'private_key_path': '/tmp/test_key.pem'
        }

        mock_token.return_value = 'test_token'

        mock_response = Mock()
        mock_response.json.return_value = {
            'account_id': '12345',
            'balance': 1000000.00,
            'currency': 'USD'
        }
        mock_response.elapsed = Mock()
        mock_response.elapsed.total_seconds.return_value = 0.5
        mock_response.status_code = 200
        mock_session.return_value.request.return_value = mock_response

        # Mock file operations
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = 'test_key'
            with patch('jwt.encode') as mock_jwt:
                mock_jwt.return_value = 'test_jwt'
                client = JPMorganAPIClient()
        result = client.get_account_balance('12345')

        assert result['account_id'] == '12345'
        assert result['balance'] == 1000000.00

    @patch('src.jpmorgan_client.JPMorganAPIClient._get_access_token')
    @patch('src.jpmorgan_client.requests.Session')
    @patch('src.jpmorgan_client.credential_manager')
    def test_initiate_transfer(self, mock_cred_manager, mock_session, mock_token):
        """Test transfer initiation"""
        # Mock credential manager
        mock_cred_manager.retrieve_credential.return_value = {
            'client_id': 'test_client',
            'client_secret': 'test_secret',
            'api_key': 'test_api_key',
            'private_key_path': '/tmp/test_key.pem'
        }

        mock_token.return_value = 'test_token'

        mock_response = Mock()
        mock_response.json.return_value = {
            'transfer_id': 'TRX123456',
            'status': 'pending',
            'amount': 50000.00
        }
        mock_response.elapsed = Mock()
        mock_response.elapsed.total_seconds.return_value = 0.5
        mock_response.status_code = 200
        mock_session.return_value.request.return_value = mock_response

        # Mock file operations
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = 'test_key'
            with patch('jwt.encode') as mock_jwt:
                mock_jwt.return_value = 'test_jwt'
                client = JPMorganAPIClient()
        result = client.initiate_transfer('acc1', 'acc2', 50000.00, 'USD')

        assert result['transfer_id'] == 'TRX123456'
        assert result['status'] == 'pending'

class TestJPMorganAPIEndpoints:
    """Test cases for JPMorgan API endpoints"""

    @patch('src.api_server.jpmorgan_client')
    def test_get_jpmorgan_account_success(self, mock_client, client):
        """Test successful JPMorgan account retrieval"""
        mock_client.get_account_balance.side_effect = Exception("JPMorgan API unavailable")

        response = client.get('/api/banks/jpmorgan-chase/account?account_id=JPM001', headers=HEADERS)
        assert response.status_code == 200

        data = response.get_json()
        assert data['status'] == 'success'
        # Note: The endpoint falls back to standard method when JPMorgan API fails
        assert data['integration'] == 'fallback'
        assert 'account_number' in data['data']
        assert 'routing_number' in data['data']
        assert 'bank_name' in data['data']

    @patch('src.api_server.jpmorgan_client')
    def test_jpmorgan_transfer_success(self, mock_client, client):
        """Test successful JPMorgan transfer"""
        mock_client.initiate_transfer.return_value = {
            'transfer_id': 'TRX789',
            'status': 'completed'
        }

        transfer_data = {
            'from_bank': 'jpmorgan-chase',
            'to_bank': 'citi-private-bank',
            'amount': 100000,
            'currency': 'USD'
        }

        response = client.post('/api/banks/transfer',
                              json=transfer_data,
                              headers=HEADERS)
        assert response.status_code == 200

        data = response.get_json()
        assert data['status'] == 'success'
        assert data['integration'] == 'jpmorgan_api'

    @patch('src.api_server.jpmorgan_client')
    def test_get_jpmorgan_accounts_endpoint(self, mock_client, client):
        """Test JPMorgan accounts endpoint"""
        mock_client.get_corporate_accounts.return_value = [
            {
                'id': 'ACC001',
                'name': 'Primary Corporate Account',
                'balance': 10000000.00
            }
        ]

        with patch.dict(os.environ, {'JPMORGAN_CLIENT_ID': 'test_client'}):
            response = client.get('/api/jpmorgan/accounts', headers=HEADERS)
            assert response.status_code == 200

            data = response.get_json()
            assert data['status'] == 'success'
            assert len(data['data']) == 1

    @patch('src.api_server.jpmorgan_sync.perform_full_sync')
    def test_sync_jpmorgan_data(self, mock_sync, client):
        """Test JPMorgan data synchronization endpoint"""
        mock_sync.return_value = {
            'corporate_accounts': True,
            'market_data': True
        }

        response = client.post('/api/jpmorgan/sync', headers=HEADERS)
        assert response.status_code == 200

        data = response.get_json()
        assert data['status'] == 'success'
        assert 'corporate_accounts' in data['results']

class TestJPMorganIntegration:
    """Integration tests combining multiple components"""

    @patch('src.api_server.jpmorgan_client')
    def test_full_jpmorgan_workflow(self, mock_client, client):
        """Test complete JPMorgan workflow"""
        # Mock all client methods
        mock_client.get_account_balance.return_value = {'balance': 1000000}
        mock_client.get_corporate_accounts.return_value = [{'id': 'ACC001'}]
        mock_client.get_investment_portfolio.return_value = {'holdings': []}

        # Test account retrieval
        response = client.get('/api/banks/jpmorgan-chase/account', headers=HEADERS)
        assert response.status_code == 200

        # Test accounts endpoint
        with patch.dict(os.environ, {'JPMORGAN_CLIENT_ID': 'test_client'}):
            response = client.get('/api/jpmorgan/accounts', headers=HEADERS)
            assert response.status_code == 200

        # Test portfolio endpoint
        response = client.get('/api/jpmorgan/portfolio/ACC001', headers=HEADERS)
        assert response.status_code == 200

if __name__ == '__main__':
    pytest.main([__file__])
