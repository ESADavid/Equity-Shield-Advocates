import pytest
import json
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from src.jpmorgan_sync import JPMorganDataSync

class TestJPMorganDataSync:
    """Test cases for JPMorgan data synchronization"""

    def setup_method(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.data_file = os.path.join(self.temp_dir, 'corporate_structure.json')

        # Create test data file
        test_data = {
            'Financial': [
                {
                    'ticker': 'JPM',
                    'name': 'JPMorgan Chase & Co.',
                    'description': 'Test company'
                }
            ]
        }

        with open(self.data_file, 'w') as f:
            json.dump(test_data, f)

    def teardown_method(self):
        """Clean up test fixtures"""
        if os.path.exists(self.data_file):
            os.remove(self.data_file)
        os.rmdir(self.temp_dir)

    @patch('src.jpmorgan_sync.jpmorgan_client')
    def test_sync_corporate_accounts_success(self, mock_client):
        """Test successful corporate accounts synchronization"""
        # Mock JPMorgan client
        mock_client.get_corporate_accounts.return_value = [
            {
                'id': 'ACC001',
                'name': 'Primary Account',
                'balance': 1000000.00
            }
        ]

        sync = JPMorganDataSync()
        sync.data_file = self.data_file

        with patch.dict(os.environ, {'JPMORGAN_CLIENT_ID': 'test_client'}):
            result = sync.sync_corporate_accounts()

        assert result == True

        # Verify data was updated
        with open(self.data_file, 'r') as f:
            data = json.load(f)

        jpm_entry = data['Financial'][0]
        assert 'jpmorgan_accounts' in jpm_entry
        assert len(jpm_entry['jpmorgan_accounts']) == 1
        assert jpm_entry['jpmorgan_accounts'][0]['id'] == 'ACC001'
        assert jpm_entry['total_aum'] == 1000000.00

    @patch('src.jpmorgan_sync.jpmorgan_client')
    def test_sync_corporate_accounts_no_client_id(self, mock_client):
        """Test sync failure when client ID is not configured"""
        sync = JPMorganDataSync()

        result = sync.sync_corporate_accounts()

        assert result == False
        mock_client.get_corporate_accounts.assert_not_called()

    @patch('src.jpmorgan_sync.jpmorgan_client')
    def test_sync_investment_portfolio(self, mock_client):
        """Test investment portfolio synchronization"""
        mock_client.get_investment_portfolio.return_value = {
            'holdings': [
                {'symbol': 'AAPL', 'shares': 1000},
                {'symbol': 'MSFT', 'shares': 500}
            ],
            'total_value': 500000.00
        }

        sync = JPMorganDataSync()
        sync.data_file = self.data_file

        result = sync.sync_investment_portfolio('ACC001')

        assert result == True

        # Verify portfolio data was added
        with open(self.data_file, 'r') as f:
            data = json.load(f)

        jpm_entry = data['Financial'][0]
        assert 'portfolios' in jpm_entry
        assert 'ACC001' in jpm_entry['portfolios']
        assert jpm_entry['portfolios']['ACC001']['total_value'] == 500000.00

    @patch('src.jpmorgan_sync.jpmorgan_client')
    def test_sync_market_data(self, mock_client):
        """Test market data synchronization"""
        mock_client.get_market_data.return_value = {
            'JPM': {'price': 150.00, 'change': 2.5},
            'BAC': {'price': 35.00, 'change': -1.2}
        }

        sync = JPMorganDataSync()
        sync.data_file = self.data_file

        result = sync.sync_market_data()

        assert result == True

        # Verify market data was added
        with open(self.data_file, 'r') as f:
            data = json.load(f)

        jpm_entry = data['Financial'][0]
        assert 'market_data' in jpm_entry
        assert jpm_entry['market_data']['price'] == 150.00

    def test_should_sync_initial(self):
        """Test sync timing - should sync when never synced"""
        sync = JPMorganDataSync()

        assert sync.should_sync() == True

    def test_should_sync_within_interval(self):
        """Test sync timing - should not sync within interval"""
        sync = JPMorganDataSync()
        sync.last_sync_time = datetime.now() - timedelta(minutes=30)  # Less than 1 hour

        assert sync.should_sync() == False

    def test_should_sync_after_interval(self):
        """Test sync timing - should sync after interval"""
        sync = JPMorganDataSync()
        sync.last_sync_time = datetime.now() - timedelta(hours=2)  # More than 1 hour

        assert sync.should_sync() == True

    @patch('src.jpmorgan_sync.JPMorganDataSync.sync_corporate_accounts')
    @patch('src.jpmorgan_sync.JPMorganDataSync.sync_market_data')
    @patch('src.jpmorgan_sync.JPMorganDataSync.sync_investment_portfolio')
    def test_perform_full_sync(self, mock_portfolio, mock_market, mock_accounts):
        """Test full synchronization"""
        mock_accounts.return_value = True
        mock_market.return_value = True
        mock_portfolio.return_value = True

        # Set up test data with accounts
        test_data = {
            'Financial': [
                {
                    'ticker': 'JPM',
                    'jpmorgan_accounts': [{'id': 'ACC001'}]
                }
            ]
        }

        with open(self.data_file, 'w') as f:
            json.dump(test_data, f)

        sync = JPMorganDataSync()
        sync.data_file = self.data_file

        with patch.dict(os.environ, {'JPMORGAN_CLIENT_ID': 'test_client'}):
            results = sync.perform_full_sync()

        assert 'corporate_accounts' in results
        assert 'market_data' in results
        assert 'portfolio_ACC001' in results
        assert results['corporate_accounts'] == True
        assert results['market_data'] == True
        assert results['portfolio_ACC001'] == True

        # Verify last sync time was set
        assert sync.last_sync_time is not None

    def test_load_local_data_missing_file(self):
        """Test loading data when file doesn't exist"""
        sync = JPMorganDataSync()
        sync.data_file = '/nonexistent/file.json'

        data = sync.load_local_data()

        assert data == {}

    def test_save_local_data(self):
        """Test saving local data"""
        sync = JPMorganDataSync()
        sync.data_file = self.data_file

        test_data = {'test': 'data'}

        sync.save_local_data(test_data)

        # Verify data was saved
        with open(self.data_file, 'r') as f:
            saved_data = json.load(f)

        assert saved_data == test_data

if __name__ == '__main__':
    pytest.main([__file__])
