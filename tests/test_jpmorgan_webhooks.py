import pytest
import json
import hmac
import hashlib
from unittest.mock import Mock, patch
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from src.jpmorgan_webhooks import JPMorganWebhookHandler, JPMORGAN_AVAILABLE
from src.api_server import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    client = app.test_client()
    yield client

API_KEY = "equity-shield-2024-secure-key"
HEADERS = {"X-API-KEY": API_KEY}

class TestJPMorganWebhookHandler:
    """Test cases for JPMorgan webhook handler"""

    def test_verify_webhook_signature_valid(self):
        """Test valid webhook signature verification"""
        handler = JPMorganWebhookHandler()
        handler.webhook_secret = 'test_secret'

        payload = '{"test": "data"}'
        signature = f"sha256={hmac.new(handler.webhook_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()}"

        assert handler.verify_webhook_signature(payload, signature) == True

    def test_verify_webhook_signature_invalid(self):
        """Test invalid webhook signature verification"""
        handler = JPMorganWebhookHandler()
        handler.webhook_secret = 'test_secret'

        payload = '{"test": "data"}'
        signature = "sha256=invalid_signature"

        assert handler.verify_webhook_signature(payload, signature) == False

    def test_verify_webhook_signature_no_secret(self):
        """Test signature verification without configured secret"""
        handler = JPMorganWebhookHandler()
        handler.webhook_secret = None

        payload = '{"test": "data"}'
        signature = "sha256=some_signature"

        assert handler.verify_webhook_signature(payload, signature) == False

    @patch('src.jpmorgan_webhooks.jpmorgan_sync.sync_investment_portfolio')
    @patch('src.jpmorgan_webhooks.JPMORGAN_AVAILABLE', True)
    def test_handle_account_update(self, mock_sync):
        """Test account update event handling"""
        mock_sync.return_value = True

        handler = JPMorganWebhookHandler()
        payload = {
            'account_id': 'ACC001',
            'event_type': 'account.updated'
        }

        result = handler._handle_account_update(payload)

        assert result['account_id'] == 'ACC001'
        assert result['sync_result'] == True
        assert result['action'] == 'portfolio_sync_triggered'
        mock_sync.assert_called_once_with('ACC001')

    @patch('src.jpmorgan_webhooks.JPMORGAN_AVAILABLE', False)
    def test_handle_account_update_unavailable(self):
        """Test account update when client unavailable"""
        handler = JPMorganWebhookHandler()
        payload = {
            'account_id': 'ACC001',
            'event_type': 'account.updated'
        }

        result = handler._handle_account_update(payload)

        assert result['account_id'] == 'ACC001'
        assert result['sync_result'] == False
        assert result['action'] == 'portfolio_sync_triggered'

    @patch('src.jpmorgan_webhooks.jpmorgan_sync.sync_corporate_accounts')
    @patch('src.jpmorgan_webhooks.JPMORGAN_AVAILABLE', True)
    def test_handle_transaction_complete(self, mock_sync):
        """Test transaction completion event handling"""
        mock_sync.return_value = True

        handler = JPMorganWebhookHandler()
        payload = {
            'transaction_id': 'TRX001',
            'account_id': 'ACC001',
            'amount': 50000.00
        }

        result = handler._handle_transaction_complete(payload)

        assert result['transaction_id'] == 'TRX001'
        assert result['account_id'] == 'ACC001'
        assert result['amount'] == 50000.00
        assert result['sync_result'] == True
        mock_sync.assert_called_once()

    @patch('src.jpmorgan_webhooks.JPMORGAN_AVAILABLE', False)
    def test_handle_transaction_complete_unavailable(self):
        """Test transaction complete when client unavailable"""
        handler = JPMorganWebhookHandler()
        payload = {
            'transaction_id': 'TRX001',
            'account_id': 'ACC001',
            'amount': 50000.00
        }

        result = handler._handle_transaction_complete(payload)

        assert result['transaction_id'] == 'TRX001'
        assert result['account_id'] == 'ACC001'
        assert result['amount'] == 50000.00
        assert result['sync_result'] == False

    def test_handle_compliance_alert(self):
        """Test compliance alert event handling"""
        handler = JPMorganWebhookHandler()
        payload = {
            'alert_type': 'suspicious_activity',
            'account_id': 'ACC001',
            'severity': 'high',
            'timestamp': '2024-01-01T12:00:00Z',
            'details': 'Unusual transaction pattern detected'
        }

        with patch('src.jpmorgan_webhooks.os.path.exists', return_value=False):
            with patch('builtins.open', create=True):
                result = handler._handle_compliance_alert(payload)

        assert result['alert_type'] == 'suspicious_activity'
        assert result['account_id'] == 'ACC001'
        assert result['severity'] == 'high'
        assert result['action'] == 'alert_logged'

    @patch('src.jpmorgan_webhooks.jpmorgan_sync.sync_market_data')
    @patch('src.jpmorgan_webhooks.JPMORGAN_AVAILABLE', True)
    def test_handle_market_data_update(self, mock_sync):
        """Test market data update event handling"""
        mock_sync.return_value = True

        handler = JPMorganWebhookHandler()
        payload = {
            'symbols': ['JPM', 'BAC', 'MSFT']
        }

        result = handler._handle_market_data_update(payload)

        assert result['symbols'] == ['JPM', 'BAC', 'MSFT']
        assert result['sync_result'] == True
        assert result['action'] == 'market_data_synced'
        mock_sync.assert_called_once()

    @patch('src.jpmorgan_webhooks.JPMORGAN_AVAILABLE', False)
    def test_handle_market_data_update_unavailable(self):
        """Test market data update when client unavailable"""
        handler = JPMorganWebhookHandler()
        payload = {
            'symbols': ['JPM', 'BAC', 'MSFT']
        }

        result = handler._handle_market_data_update(payload)

        assert result['symbols'] == ['JPM', 'BAC', 'MSFT']
        assert result['sync_result'] == False
        assert result['action'] == 'market_data_synced'

    @patch('src.jpmorgan_webhooks.jpmorgan_sync.sync_investment_portfolio')
    @patch('src.jpmorgan_webhooks.JPMORGAN_AVAILABLE', True)
    def test_handle_portfolio_change(self, mock_sync):
        """Test portfolio change event handling"""
        mock_sync.return_value = True

        handler = JPMorganWebhookHandler()
        payload = {
            'account_id': 'ACC001',
            'change_type': 'rebalance'
        }

        result = handler._handle_portfolio_change(payload)

        assert result['account_id'] == 'ACC001'
        assert result['change_type'] == 'rebalance'
        assert result['sync_result'] == True
        assert result['action'] == 'portfolio_synced'
        mock_sync.assert_called_once_with('ACC001')

    @patch('src.jpmorgan_webhooks.JPMORGAN_AVAILABLE', False)
    def test_handle_portfolio_change_unavailable(self):
        """Test portfolio change when client unavailable"""
        handler = JPMorganWebhookHandler()
        payload = {
            'account_id': 'ACC001',
            'change_type': 'rebalance'
        }

        result = handler._handle_portfolio_change(payload)

        assert result['account_id'] == 'ACC001'
        assert result['change_type'] == 'rebalance'
        assert result['sync_result'] == False
        assert result['action'] == 'portfolio_synced'

    def test_process_webhook_unknown_event(self):
        """Test processing unknown webhook event"""
        handler = JPMorganWebhookHandler()

        result = handler.process_webhook('unknown.event', {})

        assert result['status'] == 'error'
        assert 'Unknown event type' in result['message']

    @patch('src.jpmorgan_webhooks.JPMorganWebhookHandler._handle_account_update')
    def test_process_webhook_success(self, mock_handler):
        """Test successful webhook processing"""
        mock_handler.return_value = {'processed': True}

        handler = JPMorganWebhookHandler()

        result = handler.process_webhook('account.updated', {'account_id': 'ACC001'})

        assert result['status'] == 'success'
        assert 'processed successfully' in result['message']
        mock_handler.assert_called_once_with({'account_id': 'ACC001'})

    @patch('src.jpmorgan_webhooks.JPMorganWebhookHandler._handle_account_update')
    def test_process_webhook_error(self, mock_handler):
        """Test webhook processing with error"""
        mock_handler.side_effect = Exception('Test error')

        handler = JPMorganWebhookHandler()

        result = handler.process_webhook('account.updated', {'account_id': 'ACC001'})

        assert result['status'] == 'error'
        assert 'Error processing event' in result['message']

class TestJPMorganWebhookEndpoints:
    """Test cases for webhook API endpoints"""

    def test_webhook_endpoint_valid_payload(self, client):
        """Test webhook endpoint with valid payload"""
        payload = {
            'event_type': 'account.updated',
            'account_id': 'ACC001'
        }

        with patch('src.api_server.webhook_handler.process_webhook') as mock_process:
            mock_process.return_value = {
                'status': 'success',
                'message': 'Event processed'
            }

            response = client.post('/api/webhooks/jpmorgan',
                                 json=payload,
                                 headers={'Content-Type': 'application/json'})

            assert response.status_code == 200
            data = response.get_json()
            assert data['status'] == 'success'

    def test_webhook_endpoint_invalid_json(self, client):
        """Test webhook endpoint with invalid JSON"""
        response = client.post('/api/webhooks/jpmorgan',
                             data='invalid json',
                             headers={'Content-Type': 'application/json'})

        assert response.status_code == 400
        data = response.get_json()
        assert 'Invalid JSON payload' in data['message']

    def test_webhook_endpoint_missing_event_type(self, client):
        """Test webhook endpoint with missing event type"""
        payload = {'account_id': 'ACC001'}

        response = client.post('/api/webhooks/jpmorgan',
                             json=payload,
                             headers={'Content-Type': 'application/json'})

        assert response.status_code == 400
        data = response.get_json()
        assert 'Missing event_type' in data['message']

    def test_webhook_endpoint_invalid_signature(self, client):
        """Test webhook endpoint with invalid signature"""
        payload = {
            'event_type': 'account.updated',
            'account_id': 'ACC001'
        }

        with patch('src.api_server.webhook_handler.verify_webhook_signature', return_value=False):
            response = client.post('/api/webhooks/jpmorgan',
                                 json=payload,
                                 headers={
                                     'Content-Type': 'application/json',
                                     'X-JPMorgan-Signature': 'invalid'
                                 })

            assert response.status_code == 401
            data = response.get_json()
            assert 'Invalid signature' in data['message']

    def test_webhook_endpoint_processing_error(self, client):
        """Test webhook endpoint with processing error"""
        payload = {
            'event_type': 'account.updated',
            'account_id': 'ACC001'
        }

        with patch('src.api_server.webhook_handler.process_webhook') as mock_process:
            mock_process.side_effect = Exception('Processing failed')

            response = client.post('/api/webhooks/jpmorgan',
                                 json=payload,
                                 headers={'Content-Type': 'application/json'})

            assert response.status_code == 500
            data = response.get_json()
            assert data['status'] == 'error'

if __name__ == '__main__':
    pytest.main([__file__])
