import logging
import json
import hmac
import hashlib
import os
from typing import Dict, Any, Optional
from flask import request, jsonify
from src.jpmorgan_sync import jpmorgan_sync

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class JPMorganWebhookHandler:
    """
    Handles incoming webhooks from JPMorgan systems and triggers appropriate actions.
    """

    def __init__(self):
        self.webhook_secret = os.getenv('JPMORGAN_WEBHOOK_SECRET')
        self.allowed_events = {
            'account.updated': self._handle_account_update,
            'transaction.completed': self._handle_transaction_complete,
            'compliance.alert': self._handle_compliance_alert,
            'market.data.updated': self._handle_market_data_update,
            'portfolio.changed': self._handle_portfolio_change
        }

    def verify_webhook_signature(self, payload: str, signature: str) -> bool:
        """
        Verify webhook signature using HMAC-SHA256.
        """
        if not self.webhook_secret:
            logger.warning("JPMorgan webhook secret not configured")
            return False

        expected_signature = hmac.new(
            self.webhook_secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(f"sha256={expected_signature}", signature)

    def process_webhook(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process incoming webhook based on event type.
        """
        logger.info(f"Processing JPMorgan webhook: {event_type}")

        # Validate event type
        if event_type not in self.allowed_events:
            logger.warning(f"Unknown webhook event type: {event_type}")
            return {
                'status': 'error',
                'message': f'Unknown event type: {event_type}'
            }

        try:
            # Process the event
            result = self.allowed_events[event_type](payload)
            logger.info(f"Successfully processed webhook event: {event_type}")
            return {
                'status': 'success',
                'message': f'Event {event_type} processed successfully',
                'result': result
            }
        except Exception as e:
            logger.error(f"Error processing webhook event {event_type}: {str(e)}")
            return {
                'status': 'error',
                'message': f'Error processing event {event_type}',
                'error': str(e)
            }

    def _handle_account_update(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle account update events"""
        account_id = payload.get('account_id')
        if not account_id:
            raise ValueError("Account ID missing from payload")

        logger.info(f"Processing account update for: {account_id}")

        # Trigger sync for the specific account
        sync_result = jpmorgan_sync.sync_investment_portfolio(account_id)

        return {
            'account_id': account_id,
            'sync_result': sync_result,
            'action': 'portfolio_sync_triggered'
        }

    def _handle_transaction_complete(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle transaction completion events"""
        transaction_id = payload.get('transaction_id')
        account_id = payload.get('account_id')
        amount = payload.get('amount')

        logger.info(f"Processing transaction completion: {transaction_id}")

        # Update account balance in sync
        sync_result = jpmorgan_sync.sync_corporate_accounts()

        return {
            'transaction_id': transaction_id,
            'account_id': account_id,
            'amount': amount,
            'sync_result': sync_result,
            'action': 'account_balance_updated'
        }

    def _handle_compliance_alert(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle compliance alert events"""
        alert_type = payload.get('alert_type')
        account_id = payload.get('account_id')
        severity = payload.get('severity', 'medium')

        logger.warning(f"Compliance alert received: {alert_type} for account {account_id}")

        # Log compliance alert (in production, this might trigger notifications)
        alert_data = {
            'alert_type': alert_type,
            'account_id': account_id,
            'severity': severity,
            'timestamp': payload.get('timestamp'),
            'details': payload.get('details')
        }

        # Store alert in local data for review
        self._store_compliance_alert(alert_data)

        return {
            'alert_type': alert_type,
            'account_id': account_id,
            'severity': severity,
            'action': 'alert_logged'
        }

    def _handle_market_data_update(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle market data update events"""
        symbols = payload.get('symbols', [])

        logger.info(f"Processing market data update for symbols: {symbols}")

        # Trigger market data sync
        sync_result = jpmorgan_sync.sync_market_data()

        return {
            'symbols': symbols,
            'sync_result': sync_result,
            'action': 'market_data_synced'
        }

    def _handle_portfolio_change(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle portfolio change events"""
        account_id = payload.get('account_id')
        change_type = payload.get('change_type')

        logger.info(f"Processing portfolio change for account {account_id}: {change_type}")

        # Sync portfolio data
        sync_result = jpmorgan_sync.sync_investment_portfolio(account_id)

        return {
            'account_id': account_id,
            'change_type': change_type,
            'sync_result': sync_result,
            'action': 'portfolio_synced'
        }

    def _store_compliance_alert(self, alert_data: Dict[str, Any]) -> None:
        """Store compliance alert for review"""
        try:
            alerts_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'compliance_alerts.json')

            # Load existing alerts
            if os.path.exists(alerts_file):
                with open(alerts_file, 'r') as f:
                    alerts = json.load(f)
            else:
                alerts = []

            # Add new alert
            alerts.append(alert_data)

            # Save updated alerts
            with open(alerts_file, 'w') as f:
                json.dump(alerts, f, indent=2)

            logger.info("Compliance alert stored successfully")
        except Exception as e:
            logger.error(f"Failed to store compliance alert: {str(e)}")

# Global webhook handler instance
webhook_handler = JPMorganWebhookHandler()
