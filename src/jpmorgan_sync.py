import logging
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from src.jpmorgan_client import jpmorgan_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class JPMorganDataSync:
    """
    Handles synchronization of corporate data between Equity Shield and JPMorgan systems.
    """

    def __init__(self):
        self.last_sync_time = None
        self.sync_interval = timedelta(hours=1)  # Sync every hour
        self.data_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'corporate_structure.json')

    def load_local_data(self) -> Dict[str, Any]:
        """Load corporate structure data from local file"""
        try:
            with open(self.data_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("Local corporate structure file not found")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing local data file: {str(e)}")
            return {}

    def save_local_data(self, data: Dict[str, Any]) -> None:
        """Save corporate structure data to local file"""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("Local corporate structure data updated")
        except Exception as e:
            logger.error(f"Error saving local data: {str(e)}")

    def sync_corporate_accounts(self) -> bool:
        """
        Synchronize corporate account data with JPMorgan.
        Returns True if sync was successful, False otherwise.
        """
        try:
            logger.info("Starting corporate account synchronization with JPMorgan")

            # Get client ID from environment
            client_id = os.getenv('JPMORGAN_CLIENT_ID')
            if not client_id:
                logger.error("JPMORGAN_CLIENT_ID not configured")
                return False

            # Fetch corporate accounts from JPMorgan
            jpmorgan_accounts = jpmorgan_client.get_corporate_accounts(client_id)

            # Load existing local data
            local_data = self.load_local_data()

            # Update Financial sector with JPMorgan data
            if 'Financial' not in local_data:
                local_data['Financial'] = []

            # Find or create JPMorgan entry
            jpmorgan_entry = None
            for company in local_data['Financial']:
                if company.get('ticker') == 'JPM':
                    jpmorgan_entry = company
                    break

            if not jpmorgan_entry:
                jpmorgan_entry = {
                    'ticker': 'JPM',
                    'name': 'JPMorgan Chase & Co.',
                    'description': 'Global financial services firm with integrated corporate account data',
                    'market_position': 'Leading investment bank and financial services provider'
                }
                local_data['Financial'].append(jpmorgan_entry)

            # Update with live account data
            jpmorgan_entry['jpmorgan_accounts'] = jpmorgan_accounts
            jpmorgan_entry['last_sync'] = datetime.now().isoformat()
            jpmorgan_entry['account_count'] = len(jpmorgan_accounts)

            # Calculate total assets under management
            total_aum = sum(account.get('balance', 0) for account in jpmorgan_accounts)
            jpmorgan_entry['total_aum'] = total_aum

            # Save updated data
            self.save_local_data(local_data)

            logger.info(f"Successfully synchronized {len(jpmorgan_accounts)} JPMorgan accounts")
            self.last_sync_time = datetime.now()
            return True

        except Exception as e:
            logger.error(f"Corporate account sync failed: {str(e)}")
            return False

    def sync_investment_portfolio(self, account_id: str) -> bool:
        """
        Synchronize investment portfolio data for a specific account.
        """
        try:
            logger.info(f"Syncing investment portfolio for account: {account_id}")

            # Fetch portfolio data from JPMorgan
            portfolio_data = jpmorgan_client.get_investment_portfolio(account_id)

            # Load local data
            local_data = self.load_local_data()

            # Find JPMorgan entry and update portfolio
            for sector in local_data.values():
                for company in sector:
                    if company.get('ticker') == 'JPM':
                        if 'portfolios' not in company:
                            company['portfolios'] = {}
                        company['portfolios'][account_id] = portfolio_data
                        company['portfolios'][account_id]['last_sync'] = datetime.now().isoformat()
                        break

            # Save updated data
            self.save_local_data(local_data)

            logger.info(f"Successfully synchronized portfolio for account {account_id}")
            return True

        except Exception as e:
            logger.error(f"Portfolio sync failed for account {account_id}: {str(e)}")
            return False

    def sync_market_data(self) -> bool:
        """
        Synchronize market data for tracked companies.
        """
        try:
            logger.info("Syncing market data")

            # Load local data to get company tickers
            local_data = self.load_local_data()
            tickers = []

            for sector_companies in local_data.values():
                for company in sector_companies:
                    ticker = company.get('ticker')
                    if ticker:
                        tickers.append(ticker)

            if not tickers:
                logger.warning("No tickers found for market data sync")
                return False

            # Fetch market data from JPMorgan
            market_data = jpmorgan_client.get_market_data(tickers)

            # Update local data with market information
            for sector_companies in local_data.values():
                for company in sector_companies:
                    ticker = company.get('ticker')
                    if ticker and ticker in market_data:
                        company['market_data'] = market_data[ticker]
                        company['market_data']['last_update'] = datetime.now().isoformat()

            # Save updated data
            self.save_local_data(local_data)

            logger.info(f"Successfully synchronized market data for {len(tickers)} companies")
            return True

        except Exception as e:
            logger.error(f"Market data sync failed: {str(e)}")
            return False

    def should_sync(self) -> bool:
        """
        Check if synchronization should be performed based on time interval.
        """
        if not self.last_sync_time:
            return True

        time_since_last_sync = datetime.now() - self.last_sync_time
        return time_since_last_sync >= self.sync_interval

    def perform_full_sync(self) -> Dict[str, bool]:
        """
        Perform a complete synchronization with JPMorgan systems.
        Returns status of each sync operation.
        """
        results = {}

        logger.info("Starting full synchronization with JPMorgan")

        # Sync corporate accounts
        results['corporate_accounts'] = self.sync_corporate_accounts()

        # Sync market data
        results['market_data'] = self.sync_market_data()

        # Sync portfolios for known accounts
        local_data = self.load_local_data()
        for sector_companies in local_data.values():
            for company in sector_companies:
                if company.get('ticker') == 'JPM' and 'jpmorgan_accounts' in company:
                    for account in company['jpmorgan_accounts']:
                        account_id = account.get('id')
                        if account_id:
                            results[f'portfolio_{account_id}'] = self.sync_investment_portfolio(account_id)

        logger.info(f"Full synchronization completed: {results}")
        return results

# Global sync instance
jpmorgan_sync = JPMorganDataSync()
