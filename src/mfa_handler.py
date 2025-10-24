import pyotp
import logging
import os
import json
import qrcode
import base64
from io import BytesIO
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from src.credential_manager import credential_manager

logger = logging.getLogger(__name__)

class MFAHandler:
    """
    TOTP-based Multi-Factor Authentication handler with challenge/response flow.
    """

    def __init__(self):
        self.issuer_name = "Equity Shield Advocates"
        self.mfa_secrets_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'mfa_secrets.enc')
        self.challenge_timeout = int(os.getenv('MFA_CHALLENGE_TIMEOUT_MINUTES', '5'))

        # Service accounts that bypass MFA
        self.service_accounts = set(os.getenv('MFA_BYPASS_ACCOUNTS', 'system,service,jpmorgan-sync').split(','))

    def generate_mfa_secret(self, user_id: str) -> Tuple[str, str]:
        """
        Generate TOTP secret for user
        Returns: (secret, provisioning_uri)
        """
        try:
            # Generate random secret
            secret = pyotp.random_base32()

            # Create provisioning URI for QR code
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(
                name=user_id,
                issuer_name=self.issuer_name
            )

            # Store secret securely
            self._store_mfa_secret(user_id, secret)

            logger.info(f"Generated MFA secret for user: {user_id}")
            return secret, provisioning_uri

        except Exception as e:
            logger.error(f"Failed to generate MFA secret for {user_id}: {str(e)}")
            raise

    def generate_qr_code(self, provisioning_uri: str) -> str:
        """
        Generate QR code as base64 string
        """
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            qr_base64 = base64.b64encode(buffered.getvalue()).decode()

            return f"data:image/png;base64,{qr_base64}"

        except Exception as e:
            logger.error(f"Failed to generate QR code: {str(e)}")
            return ""

    def verify_mfa_code(self, user_id: str, code: str) -> bool:
        """
        Verify TOTP code for user
        """
        try:
            secret = self._retrieve_mfa_secret(user_id)
            if not secret:
                logger.warning(f"No MFA secret found for user: {user_id}")
                return False

            totp = pyotp.TOTP(secret)
            is_valid = totp.verify(code, valid_window=1)  # Allow 30-second window

            if is_valid:
                logger.info(f"Successful MFA verification for user: {user_id}")
            else:
                logger.warning(f"Failed MFA verification for user: {user_id}")

            return is_valid

        except Exception as e:
            logger.error(f"Error verifying MFA code for {user_id}: {str(e)}")
            return False

    def _store_mfa_secret(self, user_id: str, secret: str) -> None:
        """Store MFA secret securely"""
        try:
            mfa_data = {
                'user_id': user_id,
                'secret': secret,
                'created_at': datetime.now().isoformat(),
                'enabled': True
            }

            credential_manager.store_credential(f"mfa_{user_id}", mfa_data)

        except Exception as e:
            logger.error(f"Failed to store MFA secret for {user_id}: {str(e)}")
            raise

    def _retrieve_mfa_secret(self, user_id: str) -> Optional[str]:
        """Retrieve MFA secret"""
        try:
            cred_data = credential_manager.retrieve_credential(f"mfa_{user_id}")
            if cred_data and cred_data.get('enabled', False):
                return cred_data.get('secret')
            return None

        except Exception as e:
            logger.error(f"Failed to retrieve MFA secret for {user_id}: {str(e)}")
            return None

    def enable_mfa(self, user_id: str, code: str) -> bool:
        """
        Enable MFA for user after verifying initial code
        """
        try:
            if self.verify_mfa_code(user_id, code):
                # Update credential to mark as enabled
                cred_data = credential_manager.retrieve_credential(f"mfa_{user_id}")
                if cred_data:
                    cred_data['enabled'] = True
                    cred_data['enabled_at'] = datetime.now().isoformat()
                    credential_manager.store_credential(f"mfa_{user_id}", cred_data)

                logger.info(f"MFA enabled for user: {user_id}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to enable MFA for {user_id}: {str(e)}")
            return False

    def disable_mfa(self, user_id: str) -> bool:
        """
        Disable MFA for user
        """
        try:
            credential_manager.delete_credential(f"mfa_{user_id}")
            logger.info(f"MFA disabled for user: {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to disable MFA for {user_id}: {str(e)}")
            return False

    def is_mfa_enabled(self, user_id: str) -> bool:
        """
        Check if MFA is enabled for user
        """
        try:
            secret = self._retrieve_mfa_secret(user_id)
            return secret is not None

        except Exception as e:
            logger.error(f"Error checking MFA status for {user_id}: {str(e)}")
            return False

    def should_bypass_mfa(self, user_id: str) -> bool:
        """
        Check if user should bypass MFA (service accounts)
        """
        return user_id.lower() in [acc.lower() for acc in self.service_accounts]

    def create_mfa_challenge(self, user_id: str) -> Optional[str]:
        """
        Create MFA challenge for user
        Returns challenge ID
        """
        try:
            if self.should_bypass_mfa(user_id):
                logger.info(f"MFA bypassed for service account: {user_id}")
                return "bypass"

            if not self.is_mfa_enabled(user_id):
                logger.warning(f"MFA not enabled for user: {user_id}")
                return None

            # Generate challenge ID
            challenge_id = f"mfa_challenge_{user_id}_{int(datetime.now().timestamp())}"

            # Store challenge data
            challenge_data = {
                'user_id': user_id,
                'challenge_id': challenge_id,
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(minutes=self.challenge_timeout)).isoformat(),
                'status': 'pending'
            }

            credential_manager.store_credential(f"challenge_{challenge_id}", challenge_data)

            logger.info(f"Created MFA challenge for user: {user_id}")
            return challenge_id

        except Exception as e:
            logger.error(f"Failed to create MFA challenge for {user_id}: {str(e)}")
            return None

    def verify_mfa_challenge(self, challenge_id: str, code: str) -> bool:
        """
        Verify MFA challenge with code
        """
        try:
            if challenge_id == "bypass":
                return True

            # Retrieve challenge data
            challenge_data = credential_manager.retrieve_credential(f"challenge_{challenge_id}")

            if not challenge_data:
                logger.warning(f"Challenge not found: {challenge_id}")
                return False

            # Check if challenge expired
            expires_at = datetime.fromisoformat(challenge_data['expires_at'])
            if datetime.now() > expires_at:
                logger.warning(f"Challenge expired: {challenge_id}")
                # Clean up expired challenge
                credential_manager.delete_credential(f"challenge_{challenge_id}")
                return False

            # Check if already used
            if challenge_data.get('status') != 'pending':
                logger.warning(f"Challenge already used: {challenge_id}")
                return False

            user_id = challenge_data['user_id']

            # Verify the code
            if self.verify_mfa_code(user_id, code):
                # Mark challenge as completed
                challenge_data['status'] = 'completed'
                challenge_data['completed_at'] = datetime.now().isoformat()
                credential_manager.store_credential(f"challenge_{challenge_id}", challenge_data)

                logger.info(f"MFA challenge verified for user: {user_id}")
                return True

            # Mark as failed
            challenge_data['status'] = 'failed'
            challenge_data['failed_at'] = datetime.now().isoformat()
            credential_manager.store_credential(f"challenge_{challenge_id}", challenge_data)

            logger.warning(f"MFA challenge failed for user: {user_id}")
            return False

        except Exception as e:
            logger.error(f"Error verifying MFA challenge {challenge_id}: {str(e)}")
            return False

    def get_mfa_setup_info(self, user_id: str) -> Dict[str, Any]:
        """
        Get MFA setup information for user
        """
        try:
            if self.is_mfa_enabled(user_id):
                return {
                    'enabled': True,
                    'message': 'MFA is already enabled for this account'
                }

            secret, provisioning_uri = self.generate_mfa_secret(user_id)
            qr_code = self.generate_qr_code(provisioning_uri)

            return {
                'enabled': False,
                'secret': secret,
                'provisioning_uri': provisioning_uri,
                'qr_code': qr_code,
                'instructions': [
                    '1. Install an authenticator app (Google Authenticator, Authy, etc.)',
                    '2. Scan the QR code or manually enter the secret key',
                    '3. Enter the 6-digit code to enable MFA'
                ]
            }

        except Exception as e:
            logger.error(f"Failed to get MFA setup info for {user_id}: {str(e)}")
            return {
                'enabled': False,
                'error': 'Failed to generate MFA setup information'
            }

    def cleanup_expired_challenges(self) -> int:
        """
        Clean up expired MFA challenges
        Returns number of challenges cleaned up
        """
        try:
            credentials = credential_manager.list_credentials()
            cleaned_count = 0

            for cred_name in credentials:
                if cred_name.startswith('challenge_'):
                    challenge_data = credential_manager.retrieve_credential(cred_name)

                    if challenge_data:
                        expires_at = datetime.fromisoformat(challenge_data['expires_at'])
                        if datetime.now() > expires_at:
                            credential_manager.delete_credential(cred_name)
                            cleaned_count += 1

            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired MFA challenges")

            return cleaned_count

        except Exception as e:
            logger.error(f"Error cleaning up MFA challenges: {str(e)}")
            return 0

    def get_mfa_status(self, user_id: str) -> Dict[str, Any]:
        """
        Get MFA status for user
        """
        try:
            enabled = self.is_mfa_enabled(user_id)
            bypass = self.should_bypass_mfa(user_id)

            status = {
                'user_id': user_id,
                'mfa_enabled': enabled,
                'mfa_bypass': bypass,
                'effective_protection': not bypass
            }

            if enabled:
                cred_data = credential_manager.retrieve_credential(f"mfa_{user_id}")
                if cred_data:
                    status['enabled_at'] = cred_data.get('enabled_at')
                    status['last_used'] = cred_data.get('last_used')

            return status

        except Exception as e:
            logger.error(f"Error getting MFA status for {user_id}: {str(e)}")
            return {
                'user_id': user_id,
                'error': 'Failed to retrieve MFA status'
            }

# Global MFA handler instance
mfa_handler = MFAHandler()
